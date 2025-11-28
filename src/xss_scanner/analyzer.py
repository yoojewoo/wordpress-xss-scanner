"""
XSS 후보 라인 추출, taint 분석, 컨텍스트/가드 판정 등
"파일 단위 정적 분석"을 담당하는 모듈.
"""

import os
import re
from datetime import datetime

from .patterns import (
    SINK_TOKENS,
    SINK_FUNCS,
    SOURCE_PATTERNS,
    GUARD_FUNCS,
    ATTR_CONTEXT_HINT,
    JS_SINK_HINT,
    CONTEXT_LINES,
)


def strip_strings_and_comments(src: str) -> str:
    """
    문자열과 주석을 공백으로 치환하여 토큰 검출 시 노이즈를 줄인다.
    """
    def _replacer(m):
        return ' ' * (len(m.group(0)))

    # /* ... */ 스타일 주석
    src = re.sub(r'/\*.*?\*/', _replacer, src, flags=re.DOTALL)
    # //, # 한 줄 주석
    src = re.sub(r'//.*?$', _replacer, src, flags=re.MULTILINE)
    src = re.sub(r'#.*?$', _replacer, src, flags=re.MULTILINE)
    # '...' / "..." 문자열
    src = re.sub(r"'(?:\\.|[^'])*'", _replacer, src)
    src = re.sub(r'\"(?:\\.|[^\"])*\"', _replacer, src)
    return src


def find_candidates(lines, window: int = 3):
    """
    후보 축소:
    - 소스(SOURCE_PATTERNS)와 싱크(SINK_TOKENS/SINK_FUNCS)가
      ±window 라인 이내에 같이 등장하는 라인을 후보로 반환.
    """
    stripped = [strip_strings_and_comments(l) for l in lines]
    source_lines = set()
    sink_lines = set()

    for i, line in enumerate(stripped):
        for sp in SOURCE_PATTERNS:
            if re.search(sp, line, re.IGNORECASE):
                source_lines.add(i + 1)
                break
        for sk in SINK_TOKENS:
            if re.search(sk, line, re.IGNORECASE):
                sink_lines.add(i + 1)
                break
        for func in SINK_FUNCS:
            if func in line:
                sink_lines.add(i + 1)

    candidates = set()
    # 소스 기준으로 주변 싱크 라인 후보 추가
    for s in source_lines:
        for i in range(s - window, s + window + 1):
            if i in sink_lines:
                candidates.add(i)

    # 동일 라인에서 소스/싱크 같이 있는 경우
    for sk in sink_lines:
        if any(re.search(sp, stripped[sk - 1], re.IGNORECASE) for sp in SOURCE_PATTERNS):
            candidates.add(sk)

    # 후보가 하나도 없으면 싱크 상위 10개라도 본다.
    if not candidates:
        candidates = set(list(sink_lines)[:10])

    return sorted(candidates)


def build_taint_map(lines, max_hops: int = 3):
    """
    얕은 데이터 플로(1~3 hop) 추적: 변수 -> taint source mapping.
    '$var = $_GET[...]', '$b = $a', ... 형태를 간단히 추적한다.
    """
    taint = {}
    assign_re = re.compile(r'\$[A-Za-z_][A-Za-z0-9_]*')

    for line_num, raw in enumerate(lines, 1):
        line = strip_strings_and_comments(raw)
        m = re.search(r'(\$[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+);', line)
        if not m:
            continue
        left = m.group(1)
        right = m.group(2)

        # 오른쪽에 직접 superglobal이 있으면 taint 시작
        for sp in SOURCE_PATTERNS:
            if re.search(sp, right, re.IGNORECASE):
                taint[left] = {'source': sp.lower(), 'line': line_num, 'hops': 0}
                break
        else:
            # 이미 tainted 변수에서 전파
            vars_in_right = re.findall(r'(\$[A-Za-z_][A-Za-z0-9_]*)', right)
            for v in vars_in_right:
                if v in taint and taint[v]['hops'] < max_hops:
                    taint[left] = {
                        'source': taint[v]['source'],
                        'line': taint[v]['line'],
                        'hops': taint[v]['hops'] + 1,
                    }
                    break
    return taint


def detect_context_for_line(line: str) -> str:
    """
    싱크가 속한 컨텍스트( html / attr / js / url ) 추정.
    """
    lower = line.lower()
    if any(h in lower for h in JS_SINK_HINT):
        return 'js'
    if any(h in lower for h in ATTR_CONTEXT_HINT):
        return 'attr'
    if 'location.href' in lower or 'window.location' in lower or 'href=' in lower:
        return 'url'
    return 'html'


def check_guard_in_expression(expr: str, context: str):
    """
    가드 함수(esc_html, esc_attr, esc_url, esc_js 등) 존재 및
    컨텍스트와의 매칭 여부 검사.
    """
    guards = GUARD_FUNCS.get(context, [])
    # 우선 해당 컨텍스트에 맞는 가드 함수 탐색
    for g in guards:
        if re.search(rf'\b{g}\s*\(', expr):
            return True, g, None

    # JS 컨텍스트에서 wp_json_encode도 허용
    if context == 'js' and re.search(r'wp_json_encode\s*\(', expr):
        return True, 'wp_json_encode', None

    # 다른 컨텍스트용 가드가 쓰인 경우 guard mismatch
    for ctx, funcs in GUARD_FUNCS.items():
        for f in funcs:
            if re.search(rf'\b{f}\s*\(', expr):
                if ctx != context:
                    return False, f, f'guard_mismatch: used {f} for {context} but maps to {ctx}'

    return False, None, None


def calculate_confidence_score(vuln: dict) -> int:
    """
    취약점 신뢰도 점수(0~100)를 계산.
    - superglobal 직접 사용, hop 수, guard 유무, 위험도 등 반영.
    """
    score = 0

    if vuln.get('direct_superglobal'):
        score += 50

    hops = vuln.get('taint_hops')
    if hops is None:
        score += 10
    else:
        score += max(0, 30 - hops * 8)

    guard_present = vuln.get('guard_present')
    if guard_present:
        score += 10
    else:
        score += 20

    rl = vuln.get('risk_level', 'LOW')
    if rl == 'CRITICAL':
        score += 20
    elif rl == 'HIGH':
        score += 10

    if vuln.get('guard_mismatch'):
        score -= 10

    return min(100, max(0, int(score)))


def get_code_context(lines, line_num: int, context_size: int = CONTEXT_LINES) -> str:
    """
    라인 주변 코드 문맥을 예쁘게 문자열로 만든다.
    """
    start = max(0, line_num - context_size - 1)
    end = min(len(lines), line_num + context_size)
    context_lines = []
    for i in range(start, end):
        marker = '>>>' if i == line_num - 1 else '   '
        context_lines.append(f"{marker}{i + 1}: {lines[i].rstrip()}")
    return '\n'.join(context_lines)


def classify_vulnerability(vuln: dict, raw_line: str, full_file_content: str) -> str:
    """
    취약점을 Reflected / DOM-based / Stored / Possible 로 분류.
    """
    line_lower = raw_line.lower()
    content_lower = full_file_content.lower()

    # DB 관련 소스(서버 저장 값) -> Stored XSS 가능성
    for db_pattern in [
        'get_option',
        'get_post_meta',
        'get_user_meta',
        'update_option',
        'add_post_meta',
        'update_post_meta',
        'add_option',
    ]:
        if db_pattern in line_lower or db_pattern in content_lower:
            return 'Stored XSS'

    # DOM 관련 토큰이 보이면 DOM-based
    dom_tokens = [
        'document.write',
        'innerhtml',
        'eval(',
        'setattribute(',
        'location.hash',
        'location.href',
        'window.location',
        '.outerhtml',
    ]
    if any(tok in line_lower for tok in dom_tokens):
        return 'DOM-based XSS'

    # js context + inline script / DOM 토큰
    if vuln.get('context') == 'js' and any(
        tok in line_lower for tok in ['<script', 'document.write', 'innerhtml', 'eval(']
    ):
        return 'DOM-based XSS'

    # 직접 superglobal이 sink에 들어가면 Reflected XSS 가능성
    if vuln.get('direct_superglobal'):
        return 'Reflected XSS'

    # tainted 변수가 superglobal에서 왔다면 Reflected 가능성
    if vuln.get('tainted_var') and vuln.get('taint_hops') is not None:
        src = vuln.get('taint_source', '')
        if src and any(sg in src for sg in ['$_get', '$_post', '$_request', '$_cookie', '$_files']):
            return 'Reflected XSS'

    # 그 외는 애매 → Possible
    return 'Possible XSS (unknown)'


def scan_file_for_xss(file_path: str):
    """
    단일 파일(PHP/JS)에 대해 XSS 후보를 스캔하고,
    'vulnerability' 딕셔너리 리스트를 반환.
    """
    vulnerabilities = []

    try:
        if not (file_path.lower().endswith('.php') or file_path.lower().endswith('.js')):
            return vulnerabilities

        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            lines = content.split('\n')

        candidate_sink_lines = find_candidates(lines, window=3)
        taint_map = build_taint_map(lines, max_hops=3)

        for ln in candidate_sink_lines:
            raw_line = lines[ln - 1]
            stripped = strip_strings_and_comments(raw_line)
            context = detect_context_for_line(raw_line)

            direct_super = any(re.search(sp, stripped, re.IGNORECASE) for sp in SOURCE_PATTERNS)

            vars_used = re.findall(r'(\$[A-Za-z_][A-Za-z0-9_]*)', stripped)
            tainted = None
            taint_hops = None
            taint_origin_line = None
            taint_source = None
            for v in vars_used:
                if v in taint_map:
                    tainted = v
                    taint_hops = taint_map[v]['hops']
                    taint_origin_line = taint_map[v].get('line')
                    taint_source = taint_map[v].get('source')
                    break

            risk = 'LOW'
            guard_present = False
            guard_name = None
            guard_mismatch = None

            gp, gname, gm = check_guard_in_expression(stripped, context)
            guard_present = gp
            guard_name = gname
            guard_mismatch = gm

            if direct_super and not guard_present:
                risk = 'CRITICAL'
            elif (tainted is not None) and not guard_present:
                risk = 'HIGH'
            elif guard_mismatch:
                risk = 'HIGH'
            else:
                risk = 'LOW'

            # attr 컨텍스트에서 html용 guard 사용 시 mismatch 처리
            if context == 'attr' and guard_present and guard_name and guard_name in GUARD_FUNCS.get('html', []):
                guard_mismatch = f'used {guard_name} for attr but it maps to html'
                risk = 'HIGH'

            vuln = {
                'file': file_path,
                'line_num': ln,
                'line_content': raw_line.strip()[:300],
                'context': context,
                'tainted_var': tainted,
                'taint_hops': taint_hops,
                'taint_origin_line': taint_origin_line,
                'taint_source': taint_source,
                'direct_superglobal': direct_super,
                'guard_present': guard_present,
                'guard_name': guard_name,
                'guard_mismatch': guard_mismatch,
                'vulnerability_type': 'XSS - '
                + ('Direct Input Output' if direct_super else ('Tainted Output' if tainted else 'Suspicious Output')),
                'risk_level': risk,
                'description': '',
                'context_snippet': get_code_context(lines, ln, context_size=CONTEXT_LINES),
            }

            if direct_super:
                vuln['description'] = 'Sink directly outputs superglobal input.'
            elif tainted:
                vuln['description'] = f'Variable {tainted} is tainted (source at line {taint_origin_line}).'
            else:
                vuln['description'] = 'Sink found near source token but taint not resolved — 추가 분석 권장.'

            # 신뢰도 계산
            vuln['confidence'] = calculate_confidence_score(vuln)

            # 분류
            vuln['vulnerability_category'] = classify_vulnerability(vuln, raw_line, content)

            # 너무 낮은 신뢰도 & LOW 위험도는 버림
            if vuln['risk_level'] != 'LOW' or vuln['confidence'] >= 50:
                vulnerabilities.append(vuln)

    except Exception as e:
        print(f"Error scanning {file_path}: {e}")

    return vulnerabilities
