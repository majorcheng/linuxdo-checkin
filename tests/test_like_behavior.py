import main
import pytest
from main import LinuxDoBrowser, is_like_toggle_url


class FakeButton:
    def __init__(self, visible: bool = True) -> None:
        self.visible = visible
        self.click_count = 0
        self.last_timeout = None

    def is_visible(self) -> bool:
        return self.visible

    def click(self, timeout=None) -> None:
        self.click_count += 1
        self.last_timeout = timeout


class FakeLocator:
    def __init__(self, items) -> None:
        self.items = list(items)

    def count(self) -> int:
        return len(self.items)

    def nth(self, index: int):
        return self.items[index]


class FakeResponse:
    def __init__(self, url: str, status: int) -> None:
        self.url = url
        self.status = status


class FakeResponseInfo:
    def __init__(self, response: FakeResponse) -> None:
        self.value = response

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


class FakeLikePage:
    def __init__(self, selector_map, response: FakeResponse) -> None:
        self.selector_map = selector_map
        self.response = response
        self.locator_calls = []
        self.expect_response_calls = []

    def locator(self, selector: str) -> FakeLocator:
        self.locator_calls.append(selector)
        return FakeLocator(self.selector_map.get(selector, []))

    def expect_response(self, predicate, timeout=None) -> FakeResponseInfo:
        self.expect_response_calls.append(timeout)
        assert predicate(self.response) is True
        return FakeResponseInfo(self.response)


class FakeTopicPage:
    def __init__(self) -> None:
        self.goto_calls = []
        self.closed = False

    def set_default_navigation_timeout(self, _timeout) -> None:
        return None

    def set_default_timeout(self, _timeout) -> None:
        return None

    def goto(self, url: str, wait_until=None) -> None:
        self.goto_calls.append((url, wait_until))

    def close(self) -> None:
        self.closed = True


class FakeContext:
    def __init__(self, page) -> None:
        self.page = page

    def new_page(self):
        return self.page


class FakeBrowser:
    def __init__(self, page) -> None:
        self.context = FakeContext(page)


def test_is_like_toggle_url_matches_current_endpoint():
    assert is_like_toggle_url(
        "https://linux.do/discourse-reactions/posts/16477673/custom-reactions/heart/toggle.json"
    )
    assert not is_like_toggle_url("https://linux.do/posts/16477673")


def test_click_like_uses_real_button_and_waits_for_toggle_response(monkeypatch):
    button = FakeButton()
    response = FakeResponse(
        "https://linux.do/discourse-reactions/posts/16477673/custom-reactions/heart/toggle.json",
        200,
    )
    page = FakeLikePage(
        {main.LIKE_BUTTON_SELECTORS[0]: [button]},
        response,
    )
    browser = LinuxDoBrowser.__new__(LinuxDoBrowser)

    monkeypatch.setattr(main.random, "uniform", lambda _a, _b: 0.0)
    monkeypatch.setattr(main.time, "sleep", lambda _seconds: None)

    browser.click_like(page)

    assert button.click_count == 1
    assert button.last_timeout == 3_000
    assert page.expect_response_calls == [8_000]
    assert page.locator_calls[0] == main.LIKE_BUTTON_SELECTORS[0]


@pytest.mark.parametrize(
    ("random_value", "should_like"),
    [
        (0.49, True),
        (0.50, False),
    ],
)
def test_click_one_topic_uses_50_percent_like_probability(
    monkeypatch,
    random_value: float,
    should_like: bool,
):
    page = FakeTopicPage()
    browser = LinuxDoBrowser.__new__(LinuxDoBrowser)
    browser.browser = FakeBrowser(page)
    calls = []

    monkeypatch.setattr(main, "wait_page_seconds", lambda *_args, **_kwargs: 0.0)
    monkeypatch.setattr(main.random, "random", lambda: random_value)
    browser.click_like = lambda current_page: calls.append(("like", current_page))
    browser.browse_post = lambda current_page: calls.append(("browse", current_page))

    browser.click_one_topic("https://linux.do/t/topic/1933502")

    assert page.goto_calls == [("https://linux.do/t/topic/1933502", "domcontentloaded")]
    assert any(action == "browse" for action, _page in calls)
    assert any(action == "like" for action, _page in calls) is should_like
    assert page.closed is True
