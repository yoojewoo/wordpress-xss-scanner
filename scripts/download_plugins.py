#!/usr/bin/env python3
"""
워드프레스 플러그인 다운로드 스크립트.

예)
    python scripts/download_plugins.py
"""

import os
import sys

# src/ 를 import 경로에 추가
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC_DIR = os.path.join(ROOT_DIR, "src")
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

from xss_scanner.downloader import interactive_cli  # noqa: E402


if __name__ == "__main__":
    interactive_cli()
