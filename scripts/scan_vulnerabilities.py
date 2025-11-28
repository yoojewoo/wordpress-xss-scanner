#!/usr/bin/env python3
"""
다운로드된 워드프레스 플러그인(./plugins)을 대상으로
XSS 취약점 정적 분석을 수행하고, ./reports 에 리포트를 남기는 스크립트.

예)
    python scripts/scan_vulnerabilities.py
"""

import os
import sys

# src/ 를 import 경로에 추가
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC_DIR = os.path.join(ROOT_DIR, "src")
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

from xss_scanner.scanner import scan_downloaded_plugins  # noqa: E402


if __name__ == "__main__":
    scan_downloaded_plugins()
