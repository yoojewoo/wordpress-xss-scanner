"""
XSS 스캐너에서 사용하는 패턴/상수 정의 모듈.
"""

# 싱크/소스/가드/컨텍스트 정의 (간결화된 규칙)
SINK_TOKENS = [r'echo\b', r'print\b', r'printf\b', r'sprintf\b', r'<\?=']
SINK_FUNCS = ['wp_send_json', 'wp_add_inline_script', 'the_content', 'the_title']

SOURCE_PATTERNS = [
    r'\$_GET\b',
    r'\$_POST\b',
    r'\$_REQUEST\b',
    r'\$_COOKIE\b',
    r'\$_FILES\b',
    r'get_option\b',
    r'get_post_meta\b',
    r'get_user_meta\b',
]

GUARD_FUNCS = {
    'html': ['esc_html', 'wp_kses', 'wp_kses_post'],
    'attr': ['esc_attr'],
    'url': ['esc_url'],
    'js': ['esc_js', 'wp_json_encode', 'json_encode'],
}

# context 매핑 규칙(간단한 heuristics)
ATTR_CONTEXT_HINT = ["href=", "src=", "data-", "value="]
JS_SINK_HINT = [
    'wp_add_inline_script',
    '<script',
    'document.write',
    'innerHTML',
    'setAttribute(',
    'eval(',
    'location.href',
    'window.location',
]

# 코드 문맥에 포함할 라인 수
CONTEXT_LINES = 3
