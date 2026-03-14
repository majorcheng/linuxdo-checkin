import main
from main import LinuxDoBrowser, validate_runtime_config


class DummyNotifier:
    def __init__(self) -> None:
        self.success_calls = []
        self.telegram_calls = []

    def send_all(self, title: str, message: str):
        self.success_calls.append((title, message))
        return True

    def send_telegram(self, title: str, message: str):
        self.telegram_calls.append((title, message))
        return True


def make_browser() -> LinuxDoBrowser:
    browser = LinuxDoBrowser.__new__(LinuxDoBrowser)
    browser.notifier = DummyNotifier()
    browser.page = None
    browser.managed_browser = None
    browser.last_failure_reason = ""
    return browser


def test_validate_runtime_config_requires_cookie(monkeypatch):
    monkeypatch.setattr(main, "COOKIES", "")

    is_valid, message = validate_runtime_config()

    assert is_valid is False
    assert "LINUXDO_COOKIES" in message


def test_run_sends_telegram_when_cookie_login_fails(monkeypatch):
    browser = make_browser()
    monkeypatch.setattr(main, "COOKIES", "_t=token")
    monkeypatch.setattr(main, "BROWSE_ENABLED", False)
    monkeypatch.setattr(main, "CONNECT_INFO_ENABLED", False)
    browser.login_with_cookies = lambda cookie_str: False

    browser.run()

    assert browser.notifier.success_calls == []
    assert len(browser.notifier.telegram_calls) == 1
    assert "Cookie 登录验证失败" in browser.notifier.telegram_calls[0][1]


def test_run_sends_telegram_when_browse_fails(monkeypatch):
    browser = make_browser()
    monkeypatch.setattr(main, "COOKIES", "_t=token")
    monkeypatch.setattr(main, "BROWSE_ENABLED", True)
    monkeypatch.setattr(main, "CONNECT_INFO_ENABLED", False)
    browser.login_with_cookies = lambda cookie_str: True
    browser.click_topic = lambda deadline_ts: False

    browser.run()

    assert browser.notifier.success_calls == []
    assert len(browser.notifier.telegram_calls) == 1
    assert "浏览任务失败" in browser.notifier.telegram_calls[0][1]


def test_run_sends_success_notification_when_cookie_login_succeeds(monkeypatch):
    browser = make_browser()
    monkeypatch.setattr(main, "COOKIES", "_t=token")
    monkeypatch.setattr(main, "BROWSE_ENABLED", False)
    monkeypatch.setattr(main, "CONNECT_INFO_ENABLED", False)
    browser.login_with_cookies = lambda cookie_str: True

    browser.run()

    assert len(browser.notifier.success_calls) == 1
    assert browser.notifier.telegram_calls == []
    assert "每日登录成功" in browser.notifier.success_calls[0][1]


def test_run_sends_telegram_when_unhandled_exception_occurs(monkeypatch):
    browser = make_browser()
    monkeypatch.setattr(main, "COOKIES", "_t=token")
    monkeypatch.setattr(main, "BROWSE_ENABLED", False)
    monkeypatch.setattr(main, "CONNECT_INFO_ENABLED", False)

    def raise_error(_cookie_str: str) -> bool:
        raise RuntimeError("boom")

    browser.login_with_cookies = raise_error

    browser.run()

    assert browser.notifier.success_calls == []
    assert len(browser.notifier.telegram_calls) == 1
    assert "运行异常: boom" in browser.notifier.telegram_calls[0][1]
