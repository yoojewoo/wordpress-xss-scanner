"""
분석 결과(취약점 리스트)를 사람이 읽기 쉬운
Markdown 보안 리포트로 변환해주는 모듈.
"""

from collections import Counter
from datetime import datetime
import os


def _risk_rank(level: str) -> int:
    """위험도 정렬용 점수."""
    level = (level or "").upper()
    if level == "CRITICAL":
        return 3
    if level == "HIGH":
        return 2
    if level == "LOW":
        return 1
    return 0


def _classify_type(cat: str) -> str:
    """분류 문자열을 네 가지 카테고리로 정규화."""
    if not cat:
        return "Possible XSS (unknown)"
    cat_lower = cat.lower()
    if "reflected" in cat_lower:
        return "Reflected XSS"
    if "stored" in cat_lower:
        return "Stored XSS"
    if "dom-based" in cat_lower or "dom based" in cat_lower:
        return "DOM-based XSS"
    return "Possible XSS (unknown)"


def _format_source_info(v: dict) -> str:
    """입력 소스 / taint 관련 요약 텍스트."""
    parts = []

    if v.get("direct_superglobal"):
        parts.append("직접 superglobal 사용 (`$_GET` / `$_POST` 등)")

    tv = v.get("tainted_var")
    if tv:
        hops = v.get("taint_hops")
        src = v.get("taint_source")
        origin = v.get("taint_origin_line")
        hop_txt = f"{hops} hop" if hops is not None else "hop 수 미상"
        src_txt = src if src else "알 수 없는 source"
        parts.append(
            f"tainted 변수: `{tv}` (source: `{src_txt}`, origin line: {origin}, {hop_txt})"
        )

    if not parts:
        parts.append("명시적인 superglobal/taint 추적은 발견되지 않음 (정적 분석 한계 가능성)")

    return "; ".join(parts)


def _format_guard_info(v: dict) -> str:
    """guard 함수 / mismatch 요약."""
    if v.get("guard_present"):
        name = v.get("guard_name") or "알 수 없는 guard"
        if v.get("guard_mismatch"):
            return f"guard 함수 사용: `{name}` (⚠ 문맥 불일치: {v.get('guard_mismatch')})"
        return f"guard 함수 사용: `{name}` (문맥 상 적절한 것으로 판단)"
    else:
        return "guard 함수(이스케이프/필터링) 미사용"


def _format_verification_label(v: dict) -> str:
    """
    verification 값이 'Verified' 또는 'Possibly Escaped' 인 경우 강조 표시.
    (없으면 빈 문자열 반환)
    """
    ver = (v.get("verification") or "").strip()
    if ver.lower() == "verified":
        return "**[검증 결과: Verified]** "
    if ver.lower() == "possibly escaped":
        return "**[검증 결과: Possibly Escaped]** "
    return ""


def generate_local_report(scan_result: dict, top_n: int = 5) -> str:
    """
    플러그인 하나에 대한 스캔 결과를 Markdown 보안 리포트 형식으로 생성.
    """
    plugin_name = scan_result.get("plugin_name", "unknown-plugin")
    total_files = scan_result.get("total_files_scanned", "?")
    vulns = scan_result.get("vulnerabilities", [])
    scan_time = scan_result.get("scan_time", datetime.now().isoformat())

    # 취약점이 하나도 없을 때
    if not vulns:
        return (
            f"# WordPress 플러그인 XSS 분석 리포트\n\n"
            f"- 플러그인 이름: **{plugin_name}**\n"
            f"- 스캔 시각: {scan_time}\n"
            f"- 스캔한 파일 수: {total_files}\n"
            f"- 발견된 XSS 취약점 후보: **0건**\n\n"
            f"## 1. 개요\n"
            f"해당 플러그인에 대해 정적 분석을 수행한 결과, XSS 취약점 후보는 발견되지 않았습니다.\n"
            f"다만, 정적 분석 도구의 한계로 인해 모든 취약 가능성을 완전히 배제할 수는 없으므로, "
            f"업데이트 시마다 주기적인 보안 점검을 권장합니다.\n"
        )

    # --- 통계 계산 ---

    # 유형별 통계 (Reflected / Stored / DOM-based / Possible)
    type_counter = Counter()
    for v in vulns:
        cat = _classify_type(v.get("vulnerability_category"))
        type_counter[cat] += 1

    # 위험도 통계
    risk_counter = Counter((v.get("risk_level") or "UNKNOWN").upper() for v in vulns)

    # 핵심 취약점 Top N 선정 (위험도 > 신뢰도 순)
    def _key(v):
        return (_risk_rank(v.get("risk_level")), v.get("confidence", 0))

    sorted_vulns = sorted(vulns, key=_key, reverse=True)
    top_vulns = sorted_vulns[:top_n]

    # --- 리포트 본문 작성 (Markdown) ---

    report_lines = []

    # 제목 & 기본 정보
    report_lines.append(f"# WordPress 플러그인 XSS 분석 리포트")
    report_lines.append("")
    report_lines.append(f"- 플러그인 이름: **{plugin_name}**")
    report_lines.append(f"- 스캔 시각: {scan_time}")
    report_lines.append(f"- 스캔한 파일 수: **{total_files}**")
    report_lines.append(f"- 발견된 XSS 취약점 후보: **{len(vulns)}건**")
    report_lines.append("")

    # 1. 개요
    report_lines.append("## 1. 개요")
    report_lines.append(
        f"{plugin_name} 플러그인에 대해 WordPress 코어 및 템플릿 구조를 고려한 "
        "정적 분석 기반 XSS 점검을 수행했습니다. 아래 통계와 Top 취약점들을 우선적으로 검토하는 것을 권장합니다."
    )
    report_lines.append("")

    # 2. 취약점 유형별 요약 통계
    report_lines.append("## 2. 취약점 유형별 요약 통계")
    report_lines.append("")
    report_lines.append("| 취약점 유형 | 발견 건수 |")
    report_lines.append("|------------|-----------|")
    for t in ["Reflected XSS", "Stored XSS", "DOM-based XSS", "Possible XSS (unknown)"]:
        report_lines.append(f"| {t} | {type_counter.get(t, 0)} |")
    report_lines.append("")
    report_lines.append("### 2-1. 위험도(Risk Level) 분포")
    report_lines.append("")
    report_lines.append("| Risk Level | 건수 |")
    report_lines.append("|-----------|------|")
    for level in ["CRITICAL", "HIGH", "LOW", "UNKNOWN"]:
        report_lines.append(f"| {level} | {risk_counter.get(level, 0)} |")
    report_lines.append("")

    # 3. 핵심 취약점 Top N
    report_lines.append(f"## 3. 핵심 취약점 Top {len(top_vulns)}")
    report_lines.append(
        "위험도(Risk Level)와 신뢰도(Confidence %)를 기준으로 우선적으로 검토해야 할 취약점 후보를 정리했습니다."
    )
    report_lines.append("")

    for idx, v in enumerate(top_vulns, 1):
        file_path = v.get("file", "?")
        line_num = v.get("line_num", "?")
        risk = v.get("risk_level", "UNKNOWN")
        conf = v.get("confidence", 0)
        category = _classify_type(v.get("vulnerability_category"))
        vtype = v.get("vulnerability_type", "XSS")
        context = v.get("context", "unknown")
        desc = v.get("description", "").strip()
        context_snippet = v.get("context_snippet", "").rstrip()

        verification_label = _format_verification_label(v)

        report_lines.append(f"### 3-{idx}. {os.path.basename(file_path)}:{line_num}")
        report_lines.append("")
        # 검증 결과 라벨 (있으면)
        if verification_label:
            report_lines.append(verification_label + "\n")

        report_lines.append(f"- **파일 경로**: `{file_path}`")
        report_lines.append(f"- **라인 번호**: `{line_num}`")
        report_lines.append(f"- **취약점 분류(Category)**: `{category}` / 탐지 타입: `{vtype}`")
        report_lines.append(f"- **Risk Level**: `{risk}`")
        report_lines.append(f"- **Confidence**: `{conf}%`")
        report_lines.append(f"- **출력 컨텍스트**: `{context}` (HTML/JS/URL/Attr 등 추정)")
        report_lines.append("")
        report_lines.append(f"**요약 설명:** {desc if desc else '설명 없음'}")
        report_lines.append("")
        report_lines.append("**입력 소스 및 taint 정보**")
        report_lines.append(f"- {_format_source_info(v)}")
        report_lines.append("")
        report_lines.append("**Guard 함수 사용 여부**")
        report_lines.append(f"- {_format_guard_info(v)}")
        report_lines.append("")

        # 코드 스니펫 (문맥)
        if context_snippet:
            report_lines.append("**코드 스니펫 (주변 문맥)**")
            report_lines.append("")
            report_lines.append("```php")
            report_lines.append(context_snippet)
            report_lines.append("```")
            report_lines.append("")

        report_lines.append("---")
        report_lines.append("")

    # 4. verification 강조 섹션
    verified_items = [v for v in vulns if (v.get("verification") or "").strip().lower() in ("verified", "possibly escaped")]
    if verified_items:
        report_lines.append("## 4. 검증(Verification) 결과 요약")
        report_lines.append("")
        report_lines.append(
            "아래 항목은 도구/추가 로직에 의해 **Verified** 또는 **Possibly Escaped** 로 표시된 취약점입니다. "
            "실제 PoC 또는 동적 검증 결과에 따라 우선순위를 조정해야 합니다."
        )
        report_lines.append("")
        for v in verified_items:
            label = _format_verification_label(v)
            file_path = v.get("file", "?")
            line_num = v.get("line_num", "?")
            category = _classify_type(v.get("vulnerability_category"))
            risk = v.get("risk_level", "UNKNOWN")
            conf = v.get("confidence", 0)
            report_lines.append(
                f"- {label}`{os.path.basename(file_path)}:{line_num}` "
                f"({category}, Risk={risk}, Confidence={conf}%)"
            )
        report_lines.append("")

    # 5. 전반적인 보안 권고사항
    report_lines.append("## 5. 전반적인 보안 권고사항")
    report_lines.append("")
    report_lines.append("- **입력 검증(Validation)**")
    report_lines.append(
        "  - 외부 입력(superglobal, DB에 저장된 값 포함)에 대해 타입/길이/패턴 기반 검증을 수행하고, "
        "허용 리스트(allow-list) 중심의 검증 정책을 적용합니다."
    )
    report_lines.append("")
    report_lines.append("- **컨텍스트 기반 escaping**")
    report_lines.append(
        "  - 출력 위치에 따라 `esc_html`, `esc_attr`, `esc_url`, `esc_js` 등 **문맥별 이스케이프 함수**를 사용해야 합니다."
    )
    report_lines.append("  - HTML 본문, 속성, URL, JS 문자열 각각에 적합한 이스케이프를 적용하지 않으면 우회 공격이 발생할 수 있습니다.")
    report_lines.append("")
    report_lines.append("- **DOM 조작 시 주의사항**")
    report_lines.append(
        "  - 클라이언트 사이드에서 `innerHTML`, `document.write`, `eval` 등의 위험한 API로 사용자 입력을 삽입하지 않습니다."
    )
    report_lines.append(
        "  - 가능하면 `textContent`, `setAttribute`(검증된 값에 한함) 등 상대적으로 안전한 API를 사용합니다."
    )
    report_lines.append("")
    report_lines.append("- **저장 기반(Stored) XSS 대비**")
    report_lines.append(
        "  - DB에 저장되는 모든 사용자 입력에 대해 저장 전 필터링/검증을 수행하고, "
        "출력 시에도 반드시 컨텍스트 기반 이스케이프를 적용합니다."
    )
    report_lines.append("")
    report_lines.append("- **운영 측면 권고**")
    report_lines.append(
        "  - 플러그인 업데이트/배포 전 정적 분석 도구를 CI 파이프라인에 통합하고, "
        "중요 기능에 대해서는 Headless 브라우저 기반 PoC 검증을 병행하는 것을 권장합니다."
    )
    report_lines.append("")

    return "\n".join(report_lines)
