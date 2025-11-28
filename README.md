# wordpress-xss-scanner

**wordpress-xss-scanner**는 WordPress.org 플러그인을 자동으로 다운로드한 뒤, 정적 분석 기반 XSS 스캔을 수행하고 필요 시 동적 검증(PoC)을 포함하여 취약점을 확인한 후 리포트를 생성하는 자동화 도구입니다.

이 스캐너는 Reflected / Stored / DOM-based / Unknown 형태의 XSS 취약점을 탐지하도록 설계되었습니다.

---

## 주요 기능

### 플러그인 자동 다운로드
- WordPress.org 플러그인을 키워드 기반으로 검색하여 ZIP 파일을 다운로드합니다.
- 다운로드된 플러그인을 안전하게 압축 해제하며, 경로 탈출(Path Traversal)을 차단합니다.
- 이미 다운로드된 플러그인은 중복 처리하지 않습니다.

### 정적 XSS 분석
- PHP 및 JavaScript 파일에서 Source·Sink 패턴 기반으로 취약점 후보 라인을 탐지합니다.
- 단순 taint 흐름 분석을 통해 간접 변수 전달도 추적합니다.
- HTML/속성/URL/JavaScript 환경을 구분하여 컨텍스트 기반 평가를 수행합니다.
- escaping 함수 사용 여부를 검증합니다.
- Risk Level과 Confidence Score를 계산하여 취약점의 신뢰도를 제공합니다.
- Reflected / Stored / DOM-based / Unknown 유형으로 분류합니다.

### 동적 검증(선택적)
- PHP CLI를 사용한 PoC 실행을 통해 실제 공격 구문이 출력에 반영되는지 확인합니다.
- Verified / Possibly Escaped / Failed 상태를 판단합니다.

### 리포트 자동 생성
- 플러그인 단위의 상세 리포트를 텍스트 파일로 생성합니다.
- 취약점 리스트, 상세 분석 내용, 코드 스니펫, 추천 보안 가이드 등을 포함합니다.
- `./reports/` 디렉터리에 자동 저장됩니다.

---

## 설치 및 실행 방법

### 1. 환경 준비

- Python 3.8 이상
- pip 패키지: `requests`, `beautifulsoup4`, `urllib3`

설치:

```
pip install -r requirements.txt
```

---

### 2. 플러그인 다운로드

```
$ python scripts/download_plugins.py
============================================================
WordPress 플러그인 다운로더
============================================================

검색 키워드 입력 (공백으로 구분): security contact form
다운로드 최대 갯수 (없으면 엔터): 5
```

---

### 3. XSS 스캔 실행

#### 명령어로 실행

```
$ python scripts/scan_vulnerabilities.py
============================================================
XSS 취약점 분석 도구
============================================================

플러그인 폴더: ./plugins
특정 플러그인만 분석하시겠습니까? (엔터 시 전체 분석):
총 5개의 플러그인을 분석합니다.
```


---

## 출력 결과

### 리포트 파일
- 경로: `./reports/<plugin>_report_<timestamp>.txt`
- 주요 내용:
  - 플러그인 요약 정보
  - 취약점 목록
  - Risk Level 및 Confidence Score
  - 검증 결과
  - 코드 스니펫과 취약 지점 설명

---

## 프로젝트 구조

```
wordpress-xss-scanner/
│
├── docs/
├── plugins/   
├── reports/
│
├── scripts/
│   ├── download_plugins.py
│   └── scan_vulnerabilities.py
│
├── src/
│   └── xss_scanner/
│       ├── __init__.py
│       ├── __version__.py
│       ├── downloader.py
│       ├── scanner.py
│       ├── analyzer.py
│       ├── reporter.py
│       ├── verifier.py
│       ├── patterns.py
│       ├── main.py 
│
├── LICENSE
├── README.md
└── requirements.txt
```

---
