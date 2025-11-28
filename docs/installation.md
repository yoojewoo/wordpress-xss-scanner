# 설치 가이드

## 시스템 요구사항

- Python 3.8 이상
- pip (Python 패키지 관리자)
- 인터넷 연결 (플러그인 다운로드 및 API 호출용)

## 1. 프로젝트 클론

```bash
git clone https://github.com/kuality/llm...hmm...git
cd wordpress-xss-scanner
```

## 2. 가상환경 생성 (권장)

### Windows
```bash
python -m venv venv
venv\Scripts\activate
```

### macOS/Linux
```bash
python3 -m venv venv
source venv/bin/activate
```

## 3. 의존성 패키지 설치

```bash
pip install -r requirements.txt
```

### 설치되는 주요 패키지
- `beautifulsoup4`: HTML 파싱
- `requests`: HTTP 요청
- `crewai`: AI 에이전트 프레임워크
- `langchain-groq`: Groq LLM 연동
- `python-dotenv`: 환경변수 관리

## 4. 환경변수 설정

### 4.1 환경변수 파일 생성
```bash
cp .env.example .env
```

### 4.2 API 키 설정
`.env` 파일을 열어서 다음 내용을 수정:

```env
# Groq API 키 입력 (필수)
GROQ_API_KEY=your_actual_groq_api_key_here

# 디렉토리 설정 (선택사항)
PLUGINS_DIR=./plugins
REPORTS_DIR=./reports
```

### 4.3 Groq API 키 발급 방법

1. [Groq Console](https://console.groq.com/) 접속
2. 회원가입 또는 로그인
3. API Keys 메뉴에서 새 API 키 생성
4. 생성된 키를 복사하여 `.env` 파일에 붙여넣기

## 5. 설치 확인

```bash
# Python 버전 확인
python --version

# 패키지 설치 확인
pip list | grep crewai
pip list | grep beautifulsoup4

# 프로젝트 구조 확인
tree -L 2  # Windows: dir /s
```

예상 출력:
```
wordpress-xss-scanner/
├── src/
│   └── xss_scanner/
├── scripts/
├── config/
├── tests/
├── docs/
├── examples/
├── requirements.txt
└── README.md
```

## 6. 개발 모드 설치 (선택사항)

프로젝트를 수정하면서 사용할 경우:

```bash
pip install -e .
```

이렇게 하면 코드를 수정해도 재설치 없이 바로 반영됩니다.

## 7. 테스트 실행

설치가 제대로 되었는지 확인:

```bash
# 단위 테스트 실행
python -m pytest tests/

# 또는
python -m unittest discover tests/
```

## 문제 해결

### 문제 1: `ModuleNotFoundError: No module named 'crewai'`
**해결**: 
```bash
pip install --upgrade pip
pip install -r requirements.txt
```

### 문제 2: `ImportError: cannot import name 'ChatGroq'`
**해결**:
```bash
pip install langchain-groq --upgrade
```

### 문제 3: SSL 인증서 오류
**해결**:
```bash
pip install --trusted-host pypi.org --trusted-host files.pythonhosted.org -r requirements.txt
```

### 문제 4: Permission denied (권한 오류)
**해결**:
```bash
# Linux/macOS
sudo pip install -r requirements.txt

# 또는 사용자 로컬에 설치
pip install --user -r requirements.txt
```

### 문제 5: `GROQ_API_KEY not found`
**해결**:
1. `.env` 파일이 프로젝트 루트에 있는지 확인
2. `.env` 파일에 `GROQ_API_KEY=` 뒤에 실제 키가 입력되어 있는지 확인
3. 환경변수를 직접 설정:
   ```bash
   # Linux/macOS
   export GROQ_API_KEY=your_key_here
   
   # Windows (CMD)
   set GROQ_API_KEY=your_key_here
   
   # Windows (PowerShell)
   $env:GROQ_API_KEY="your_key_here"
   ```

## 다음 단계

설치가 완료되었으면:
- [사용 가이드](usage.md) 확인
- [기본 예제](../examples/basic_usage.py) 실행
- 첫 번째 스캔 시작!

```bash
# 간단한 테스트
python examples/basic_usage.py
```