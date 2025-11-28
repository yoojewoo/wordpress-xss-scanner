"""
(선택) 동적 검증/PoC 실행용 모듈의 자리.
현재는 구현되어 있지 않고, 추후 headless 브라우저 등을
연동할 때 이 모듈을 확장하면 된다.
"""


def verify_vulnerability(vuln: dict) -> dict:
    """
    취약점에 대한 동적 검증을 수행하는 자리를 위한 더미 함수.
    현재는 항상 '검증되지 않음'으로 표시만 한다.
    """
    return {
        "verified": False,
        "details": "Dynamic verification not implemented yet.",
    }
