"""
패키지 엔트리: 'python -m xss_scanner' 형태로 실행할 때 사용할 수 있는
간단한 CLI.

- 플러그인 다운로드
- 플러그인 스캔
"""

import argparse

from .downloader import download_plugins_for_keywords
from .scanner import scan_downloaded_plugins


def main():
    parser = argparse.ArgumentParser(description="WordPress XSS Scanner")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # download 서브커맨드
    p_download = subparsers.add_parser("download", help="Search & download WordPress plugins")
    p_download.add_argument(
        "keywords",
        nargs="+",
        help="검색 키워드(여러 개 입력 가능)",
    )
    p_download.add_argument(
        "--max",
        type=int,
        default=None,
        help="다운로드 최대 플러그인 개수",
    )

    # scan 서브커맨드
    p_scan = subparsers.add_parser("scan", help="Scan downloaded plugins for XSS")
    p_scan.add_argument(
        "--plugins-dir",
        default="./plugins",
        help="플러그인 디렉토리 루트 (기본: ./plugins)",
    )
    p_scan.add_argument(
        "--reports-dir",
        default="./reports",
        help="리포트 저장 디렉토리 (기본: ./reports)",
    )

    args = parser.parse_args()

    if args.command == "download":
        download_plugins_for_keywords(args.keywords, max_plugins=args.max)
    elif args.command == "scan":
        scan_downloaded_plugins(plugin_root_dir=args.plugins_dir, report_dir=args.reports_dir)


if __name__ == "__main__":
    main()
