import main
import pytest
from main import (
    LinuxDoBrowser,
    extract_like_button_post_id,
    is_like_toggle_url,
    is_pointer_intercept_error,
)


class FakeButton:
    def __init__(
        self,
        visible: bool = True,
        click_error: Exception | None = None,
        post_id: str = "1001",
    ) -> None:
        self.visible = visible
        self.click_count = 0
        self.last_timeout = None
        self.click_error = click_error
        self.evaluate_calls = []
        self.post_id = post_id

    def is_visible(self) -> bool:
        return self.visible

    def click(self, timeout=None) -> None:
        if self.click_error is not None:
            raise self.click_error
        self.click_count += 1
        self.last_timeout = timeout

    def evaluate(self, script: str):
        self.evaluate_calls.append(script)
        if "closest('article')?.getAttribute('data-post-id')" in script:
            return self.post_id
        return None


class FakeLocator:
    def __init__(self, items) -> None:
        self.items = list(items)

    def count(self) -> int:
        return len(self.items)

    def nth(self, index: int):
        return self.items[index]


class FakeResponse:
    def __init__(self, url: str, status: int, text: str = "") -> None:
        self.url = url
        self.status = status
        self._text = text

    def text(self) -> str:
        return self._text


class FakeResponseInfo:
    def __init__(self, response_factory) -> None:
        self._response_factory = response_factory
        self.value = None

    def __enter__(self):
        self.value = self._response_factory()
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


class FakeLikePage:
    def __init__(self, selector_map, responses) -> None:
        self.selector_map = selector_map
        self.responses = list(responses)
        self.locator_calls = []
        self.expect_response_calls = []
        self.wait_timeout_calls = []

    def locator(self, selector: str) -> FakeLocator:
        self.locator_calls.append(selector)
        return FakeLocator(self.selector_map.get(selector, []))

    def expect_response(self, predicate, timeout=None) -> FakeResponseInfo:
        self.expect_response_calls.append(timeout)
        def factory():
            assert self.responses, "no fake responses left"
            response = self.responses.pop(0)
            assert predicate(response) is True
            return response

        return FakeResponseInfo(factory)

    def wait_for_timeout(self, timeout: int) -> None:
        self.wait_timeout_calls.append(timeout)


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


def test_extract_like_button_post_id_reads_closest_article_id():
    assert extract_like_button_post_id(FakeButton(post_id="16477673")) == "16477673"


def test_click_like_uses_real_button_and_waits_for_toggle_response(monkeypatch):
    button = FakeButton(post_id="16477673")
    response = FakeResponse(
        "https://linux.do/discourse-reactions/posts/16477673/custom-reactions/heart/toggle.json",
        200,
    )
    page = FakeLikePage(
        {main.LIKE_BUTTON_SELECTORS[0]: [button]},
        [response],
    )
    browser = LinuxDoBrowser.__new__(LinuxDoBrowser)

    monkeypatch.setattr(main.random, "uniform", lambda _a, _b: 0.0)
    monkeypatch.setattr(main.time, "sleep", lambda _seconds: None)

    browser.click_like(page)

    assert button.click_count == 1
    assert button.last_timeout == 3_000
    assert page.expect_response_calls == [8_000]
    assert page.wait_timeout_calls == [150]
    assert page.locator_calls[0] == main.LIKE_BUTTON_SELECTORS[0]
    assert button.evaluate_calls == [
        "(el) => el.closest('article')?.getAttribute('data-post-id') || ''",
        "(el) => el.scrollIntoView({block: 'center', inline: 'center'})"
    ]


def test_click_like_falls_back_to_dom_click_when_pointer_is_intercepted(monkeypatch):
    button = FakeButton(
        click_error=RuntimeError(
            "Locator.click: Timeout 3000ms exceeded. <div> intercepts pointer events"
        ),
        post_id="16477673",
    )
    response = FakeResponse(
        "https://linux.do/discourse-reactions/posts/16477673/custom-reactions/heart/toggle.json",
        200,
    )
    page = FakeLikePage(
        {main.LIKE_BUTTON_SELECTORS[0]: [button]},
        [response],
    )
    browser = LinuxDoBrowser.__new__(LinuxDoBrowser)

    monkeypatch.setattr(main.random, "uniform", lambda _a, _b: 0.0)
    monkeypatch.setattr(main.time, "sleep", lambda _seconds: None)

    browser.click_like(page)

    assert button.click_count == 0
    assert button.evaluate_calls == [
        "(el) => el.closest('article')?.getAttribute('data-post-id') || ''",
        "(el) => el.scrollIntoView({block: 'center', inline: 'center'})",
        "(el) => el.click()",
    ]
    assert page.expect_response_calls == [8_000]


def test_is_pointer_intercept_error_matches_current_playwright_message():
    assert is_pointer_intercept_error(RuntimeError("foo intercepts pointer events bar"))
    assert not is_pointer_intercept_error(RuntimeError("other error"))


def test_click_like_retries_next_candidate_after_403(monkeypatch):
    first_button = FakeButton(post_id="111")
    second_button = FakeButton(post_id="222")
    responses = [
        FakeResponse(
            "https://linux.do/discourse-reactions/posts/111/custom-reactions/heart/toggle.json",
            403,
            '{"errors":["forbidden"]}',
        ),
        FakeResponse(
            "https://linux.do/discourse-reactions/posts/222/custom-reactions/heart/toggle.json",
            200,
            '{}',
        ),
    ]
    page = FakeLikePage(
        {main.LIKE_BUTTON_SELECTORS[0]: [first_button, second_button]},
        responses,
    )
    browser = LinuxDoBrowser.__new__(LinuxDoBrowser)

    monkeypatch.setattr(main.random, "uniform", lambda _a, _b: 0.0)
    monkeypatch.setattr(main.time, "sleep", lambda _seconds: None)

    browser.click_like(page)

    assert first_button.click_count == 1
    assert second_button.click_count == 1
    assert page.expect_response_calls == [8_000, 8_000]


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
