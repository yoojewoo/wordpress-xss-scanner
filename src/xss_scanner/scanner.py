"""
플러그인 디렉토리 전체를 돌면서 파일들을 스캔하고,
리포트를 생성/저장하는 상위 레벨 스캐너 모듈.
"""

import os
from datetime import datetime

from .analyzer import scan_file_for_xss
from .reporter import generate_local_report

DEFAULT_PLUGIN_DIR = "./plugins"
DEFAULT_REPORT_DIR = "./reports"


def scan_plugin_directory(plugin_dir: str):
    """
    플러그인 디렉토리(php/js 파일들)를 모두 스캔하고
    취약점 리스트를 반환한다.
    """
    plugin_name = os.path.basename(os.path.abspath(plugin_dir))
    all_vulnerabilities = []
    file_count = 0

    print(f"[*] Scanning (improved): {plugin_name}")

    for root, dirs, files in os.walk(plugin_dir):
        for file in files:
            if file.lower().endswith(('.php', '.js')):
                file_path = os.path.join(root, file)
                file_count += 1
                vulns = scan_file_for_xss(file_path)
                all_vulnerabilities.extend(vulns)

    # dedupe
    seen = set()
    unique = []
    for v in all_vulnerabilities:
        key = (v['file'], v['line_num'], v.get('tainted_var'))
        if key not in seen:
            seen.add(key)
            unique.append(v)

    unique.sort(key=lambda x: x.get('confidence', 0), reverse=True)
    print(f"[+] {plugin_name}: {file_count} files, {len(unique)} unique vulns (improved)")

    return {
        'plugin_name': plugin_name,
        'plugin_dir': plugin_dir,
        'total_files_scanned': file_count,
        'vulnerabilities': unique,
        'scan_time': datetime.now().isoformat(),
    }


def scan_downloaded_plugins(
    plugin_root_dir: str = DEFAULT_PLUGIN_DIR,
    report_dir: str = DEFAULT_REPORT_DIR,
):
    """
    plugins/ 아래에 있는 플러그인 디렉토리를 모두 순회하며
    스캔을 수행하고, reports/에 리포트를 저장한다.
    """
    print('\n' + '=' * 50)
    print('XSS 취약점 스캔 시작')
    print('=' * 50)

    if not os.path.exists(plugin_root_dir):
        print(f"플러그인 디렉터리 없음: {plugin_root_dir}")
        return

    plugin_dirs = [
        os.path.join(plugin_root_dir, d)
        for d in os.listdir(plugin_root_dir)
        if os.path.isdir(os.path.join(plugin_root_dir, d))
    ]
    if not plugin_dirs:
        print('스캔할 플러그인 없음')
        return

    os.makedirs(report_dir, exist_ok=True)

    all_scan_results = []
    for pd in plugin_dirs:
        res = scan_plugin_directory(pd)
        all_scan_results.append(res)

        report_text = generate_local_report(res)
        ts = datetime.now().strftime('%Y%m%d_%H%M%S')
        fname = os.path.join(report_dir, f"{res['plugin_name']}_improved_{ts}.txt")
        with open(fname, 'w', encoding='utf-8') as f:
            f.write(report_text)
        print(f"[저장] {fname}")

    print('\n' + '=' * 50)
    print('모든 플러그인 스캔 완료')
    print('=' * 50)

    return all_scan_results
