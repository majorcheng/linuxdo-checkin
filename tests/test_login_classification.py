from main import classify_browser_login_entry, classify_login_snapshot


def test_classify_login_snapshot_accepts_user_menu_signal():
    status, reason = classify_login_snapshot(
        {
            "url": "https://linux.do/",
            "body_text": "首页",
            "current_user_count": 0,
            "avatar_count": 0,
            "user_menu_count": 1,
            "login_button_count": 0,
            "login_link_count": 0,
            "register_link_count": 0,
        }
    )

    assert status == "ok"
    assert reason is None


def test_classify_login_snapshot_accepts_logged_in_ui_even_with_footer_login_link():
    status, reason = classify_login_snapshot(
        {
            "url": "https://linux.do/",
            "body_text": "首页 登录 注册",
            "current_user_count": 1,
            "avatar_count": 1,
            "user_menu_count": 1,
            "login_button_count": 0,
            "login_link_count": 1,
            "register_link_count": 1,
        }
    )

    assert status == "ok"
    assert reason is None


def test_classify_login_snapshot_accepts_session_cookie_without_anonymous_controls():
    status, reason = classify_login_snapshot(
        {
            "url": "https://linux.do/",
            "body_text": "首页",
            "current_user_count": 0,
            "avatar_count": 0,
            "user_menu_count": 0,
            "login_button_count": 0,
            "login_link_count": 0,
            "register_link_count": 0,
        },
        has_login_session_cookie=True,
    )

    assert status == "ok"
    assert "Cookie" in reason


def test_classify_login_snapshot_marks_anonymous_controls_as_invalid():
    status, reason = classify_login_snapshot(
        {
            "url": "https://linux.do/",
            "body_text": "跳到主要内容 登录 ZH",
            "current_user_count": 0,
            "avatar_count": 0,
            "user_menu_count": 0,
            "login_button_count": 1,
            "login_link_count": 0,
            "register_link_count": 0,
        }
    )

    assert status == "cookie_invalid"
    assert "匿名态控件" in reason


def test_classify_browser_login_entry_prefers_hcaptcha_status():
    status, reason = classify_browser_login_entry(
        {
            "url": "https://linux.do/login",
            "body_text": "欢迎回来 人机验证 验证",
            "current_user_count": 0,
            "avatar_count": 0,
            "user_menu_count": 0,
            "login_button_count": 1,
            "login_link_count": 0,
            "register_link_count": 0,
            "hcaptcha_modal_count": 1,
            "hcaptcha_verify_button_count": 1,
            "hcaptcha_checkbox_frame_count": 1,
            "hcaptcha_challenge_frame_count": 0,
        },
        has_login_form=True,
    )

    assert status == "verification_required"
    assert "hCaptcha" in reason


def test_classify_browser_login_entry_accepts_logged_in_user_menu():
    status, reason = classify_browser_login_entry(
        {
            "url": "https://linux.do/",
            "body_text": "首页",
            "current_user_count": 0,
            "avatar_count": 0,
            "user_menu_count": 1,
            "login_button_count": 0,
            "login_link_count": 0,
            "register_link_count": 0,
        },
        has_login_form=False,
    )

    assert status == "already_logged_in"
    assert reason is None


def test_classify_browser_login_entry_accepts_logged_in_ui_even_with_login_link():
    status, reason = classify_browser_login_entry(
        {
            "url": "https://linux.do/",
            "body_text": "首页 登录",
            "current_user_count": 1,
            "avatar_count": 1,
            "user_menu_count": 1,
            "login_button_count": 0,
            "login_link_count": 1,
            "register_link_count": 0,
        },
        has_login_form=False,
    )

    assert status == "already_logged_in"
    assert reason is None
