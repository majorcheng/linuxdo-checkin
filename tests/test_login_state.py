from main import classify_login_snapshot


def test_logged_in_by_avatar_signal():
    status, reason = classify_login_snapshot(
        {
            'url': 'https://linux.do/',
            'avatar_count': 1,
            'current_user_count': 0,
            'login_button_count': 0,
            'login_link_count': 0,
            'register_link_count': 0,
            'body_text': '首页',
            'title': 'LINUX DO',
        }
    )
    assert status == 'ok'
    assert reason is None


def test_logged_in_by_t_cookie_without_anonymous_controls():
    status, reason = classify_login_snapshot(
        {
            'url': 'https://linux.do/',
            'avatar_count': 0,
            'current_user_count': 0,
            'login_button_count': 0,
            'login_link_count': 0,
            'register_link_count': 0,
            'body_text': '首页',
            'title': 'LINUX DO',
        },
        has_login_session_cookie=True,
    )
    assert status == 'ok'
    assert '主站会话 Cookie' in (reason or '')


def test_anonymous_home_with_login_button_is_invalid_cookie():
    status, reason = classify_login_snapshot(
        {
            'url': 'https://linux.do/',
            'avatar_count': 0,
            'current_user_count': 0,
            'login_button_count': 1,
            'login_link_count': 0,
            'register_link_count': 1,
            'body_text': '登录 注册',
            'title': 'LINUX DO',
        }
    )
    assert status == 'cookie_invalid'
    assert 'Cookie 可能失效' in (reason or '')


def test_login_page_is_not_considered_logged_in_even_with_t_cookie():
    status, reason = classify_login_snapshot(
        {
            'url': 'https://linux.do/login',
            'avatar_count': 0,
            'current_user_count': 0,
            'login_button_count': 0,
            'login_link_count': 0,
            'register_link_count': 0,
            'body_text': '欢迎回来 登录',
            'title': 'LINUX DO',
        },
        has_login_session_cookie=True,
    )
    assert status == 'login_page'
    assert '登录页' in (reason or '')
