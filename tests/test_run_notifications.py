import main
from main import LinuxDoBrowser


class FakeNotifier:
    def __init__(self):
        self.sent_all = []
        self.sent_telegram = []

    def send_all(self, title, message):
        self.sent_all.append((title, message))
        return True

    def send_telegram(self, title, message):
        self.sent_telegram.append((title, message))
        return True


def test_run_sends_telegram_when_cookie_is_missing(monkeypatch):
    browser = LinuxDoBrowser.__new__(LinuxDoBrowser)
    browser.page = None
    browser.managed_browser = None
    browser.notifier = FakeNotifier()
    browser.last_failure_reason = "旧失败原因"

    monkeypatch.setattr(main, "COOKIES", "")
    monkeypatch.setattr(main, "BROWSE_ENABLED", False)
    monkeypatch.setattr(main, "CONNECT_INFO_ENABLED", False)

    browser.run()

    assert browser.notifier.sent_all == []
    assert browser.notifier.sent_telegram == [
        ("LINUX DO", "❌执行失败: 未配置 LINUXDO_COOKIES，无法执行 Cookie 登录")
    ]
