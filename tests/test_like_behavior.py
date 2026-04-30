import main
import pytest
from main import (
    LinuxDoBrowser,
    build_like_toggle_fragment,
    build_like_toggle_response_preview,
    build_topic_json_url,
    collect_likeable_post_ids,
    extract_like_action_summary,
    is_like_toggle_response_success,
    is_likeable_post_payload,
    is_pointer_intercept_error,
)


class FakeButton:
    def __init__(
        self,
        visible: bool = True,
        click_errors: list[Exception] | None = None,
    ) -> None:
        self.visible = visible
        self.click_count = 0
        self.last_timeout = None
        self.click_errors = list(click_errors or [])
        self.evaluate_calls = []

    def is_visible(self) -> bool:
        return self.visible

    def click(self, timeout=None) -> None:
        if self.click_errors:
            raise self.click_errors.pop(0)
        self.click_count += 1
        self.last_timeout = timeout

    def evaluate(self, script: str):
        self.evaluate_calls.append(script)
        return None


class FakeLocator:
    def __init__(self, items) -> None:
        self.items = list(items)

    def count(self) -> int:
        return len(self.items)

    def nth(self, index: int):
        return self.items[index]


class FakeResponse:
    def __init__(self, url: str, status: int, text: str = "", json_data=None) -> None:
        self.url = url
        self.status = status
        self.status_code = status
        self._text = text
        self._json_data = json_data

    def text(self) -> str:
        return self._text

    def json(self):
        if self._json_data is None:
            raise AssertionError("json data is not configured")
        return self._json_data


class FakeResponseInfo:
    def __init__(self, response_factory) -> None:
        self._response_factory = response_factory
        self.value = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        if exc_type is None:
            self.value = self._response_factory()
        return False


class FakeLikePage:
    def __init__(self, selector_map, responses=None, url: str = "https://linux.do/t/topic/1934859") -> None:
        self.selector_map = selector_map
        self.responses = list(responses or [])
        self.url = url
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
            while self.responses:
                response = self.responses.pop(0)
                if predicate(response) is True:
                    return response
            raise AssertionError("no matching fake response found")

        return FakeResponseInfo(factory)

    def wait_for_timeout(self, timeout: int) -> None:
        self.wait_timeout_calls.append(timeout)


class FakeSession:
    def __init__(self, get_routes=None) -> None:
        self.get_routes = {key: list(value) for key, value in (get_routes or {}).items()}
        self.get_calls = []

    def get(self, url: str, **kwargs):
        self.get_calls.append((url, kwargs))
        responses = self.get_routes.get(url, [])
        assert responses, f"unexpected GET {url}"
        return responses.pop(0)


class FakeTopicPage:
    def __init__(self, url: str = "https://linux.do/t/topic/1933502") -> None:
        self.goto_calls = []
        self.closed = False
        self.url = url

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


def scoped_like_selector(post_id: str) -> str:
    return f"article[data-post-id='{post_id}'] {main.LIKE_BUTTON_SELECTORS[0]}"


def test_build_topic_json_url_keeps_canonical_topic_path():
    assert (
        build_topic_json_url("https://linux.do/t/topic/1934859")
        == "https://linux.do/t/topic/1934859.json"
    )
    assert (
        build_topic_json_url("https://linux.do/t/topic/1934859/4?u=majorcheng")
        == "https://linux.do/t/topic/1934859.json"
    )
    assert build_topic_json_url("https://linux.do/latest") == ""


def test_build_like_toggle_fragment_uses_exact_post_id():
    assert (
        build_like_toggle_fragment("16477673")
        == "/discourse-reactions/posts/16477673/custom-reactions/heart/toggle.json"
    )
    assert build_like_toggle_fragment("") == ""


def test_extract_like_action_summary_reads_like_entry():
    payload = {"actions_summary": [{"id": 3, "can_act": True}, {"id": 2, "acted": True}]}
    assert extract_like_action_summary(payload) == {"id": 2, "acted": True}


def test_is_likeable_post_payload_skips_already_acted_and_own_post():
    assert not is_likeable_post_payload({"yours": True, "actions_summary": [{"id": 2, "can_act": True}]})
    assert not is_likeable_post_payload({"actions_summary": [{"id": 2, "acted": True}]})
    assert not is_likeable_post_payload({"actions_summary": [{"id": 2, "can_act": False}]})
    assert is_likeable_post_payload({"actions_summary": [{"id": 2, "can_act": True}]})


def test_collect_likeable_post_ids_only_keeps_unliked_posts():
    topic_payload = {
        "post_stream": {
            "posts": [
                {"id": 111, "actions_summary": [{"id": 2, "acted": True}]},
                {"id": 222, "yours": True, "actions_summary": [{"id": 2, "can_act": True}]},
                {"id": 333, "actions_summary": [{"id": 2, "can_act": True}]},
            ]
        }
    }
    assert collect_likeable_post_ids(topic_payload) == ["333"]


def test_is_like_toggle_response_success_reads_main_reaction_flags():
    assert is_like_toggle_response_success({"current_user_reaction": {"id": "heart"}})
    assert is_like_toggle_response_success({"current_user_used_main_reaction": True})
    assert not is_like_toggle_response_success({})


def test_build_like_toggle_response_preview_prefers_api_errors():
    assert (
        build_like_toggle_response_preview({"payload": {"errors": ["forbidden"]}, "preview": ""})
        == "forbidden"
    )
    assert build_like_toggle_response_preview({"payload": {}, "preview": "abc"}) == "abc"


def test_is_pointer_intercept_error_matches_current_message():
    assert is_pointer_intercept_error(RuntimeError("foo intercepts pointer events bar"))
    assert not is_pointer_intercept_error(RuntimeError("other error"))


def test_click_like_skips_already_liked_posts_and_clicks_next_candidate(monkeypatch):
    target_button = FakeButton()
    response = FakeResponse(
        f"https://linux.do{build_like_toggle_fragment('222')}",
        200,
        "{}",
        {"current_user_reaction": {"id": "heart"}},
    )
    page = FakeLikePage(
        {
            main.LIKE_BUTTON_SELECTORS[0]: [FakeButton()],
            scoped_like_selector("222"): [target_button],
        },
        [response],
    )
    browser = LinuxDoBrowser.__new__(LinuxDoBrowser)
    browser.request_kwargs = {}
    browser.session = FakeSession(
        get_routes={
            "https://linux.do/t/topic/1934859.json": [
                FakeResponse(
                    "https://linux.do/t/topic/1934859.json",
                    200,
                    json_data={
                        "post_stream": {
                            "posts": [
                                {"id": 111, "actions_summary": [{"id": 2, "acted": True}]},
                                {"id": 222, "actions_summary": [{"id": 2, "can_act": True}]},
                            ]
                        }
                    },
                )
            ],
        },
    )
    browser._sync_browser_cookies_to_session = lambda: None

    monkeypatch.setattr(main.random, "uniform", lambda _a, _b: 0.0)
    monkeypatch.setattr(main.time, "sleep", lambda _seconds: None)

    browser.click_like(page)

    assert [url for url, _kwargs in browser.session.get_calls] == [
        "https://linux.do/t/topic/1934859.json"
    ]
    assert target_button.click_count == 1
    assert target_button.last_timeout == main.LIKE_BUTTON_CLICK_TIMEOUT_MS
    assert page.expect_response_calls == [main.LIKE_BUTTON_RESPONSE_TIMEOUT_MS]


def test_click_like_retries_next_candidate_after_403(monkeypatch):
    first_button = FakeButton()
    second_button = FakeButton()
    response_111 = FakeResponse(
        f"https://linux.do{build_like_toggle_fragment('111')}",
        403,
        "<html>Just a moment...</html>",
    )
    response_222 = FakeResponse(
        f"https://linux.do{build_like_toggle_fragment('222')}",
        200,
        "{}",
        {"current_user_used_main_reaction": True},
    )
    page = FakeLikePage(
        {
            main.LIKE_BUTTON_SELECTORS[0]: [FakeButton()],
            scoped_like_selector("111"): [first_button],
            scoped_like_selector("222"): [second_button],
        },
        [response_111, response_222],
    )
    browser = LinuxDoBrowser.__new__(LinuxDoBrowser)
    browser.request_kwargs = {}
    browser.session = FakeSession(
        get_routes={
            "https://linux.do/t/topic/1934859.json": [
                FakeResponse(
                    "https://linux.do/t/topic/1934859.json",
                    200,
                    json_data={
                        "post_stream": {
                            "posts": [
                                {"id": 111, "actions_summary": [{"id": 2, "can_act": True}]},
                                {"id": 222, "actions_summary": [{"id": 2, "can_act": True}]},
                            ]
                        }
                    },
                )
            ],
        },
    )
    browser._sync_browser_cookies_to_session = lambda: None

    monkeypatch.setattr(main.random, "uniform", lambda _a, _b: 0.0)
    monkeypatch.setattr(main.time, "sleep", lambda _seconds: None)

    browser.click_like(page)

    assert first_button.click_count == 1
    assert second_button.click_count == 1
    assert page.expect_response_calls == [
        main.LIKE_BUTTON_RESPONSE_TIMEOUT_MS,
        main.LIKE_BUTTON_RESPONSE_TIMEOUT_MS,
    ]


def test_click_like_skips_candidate_missing_from_dom(monkeypatch):
    target_button = FakeButton()
    response = FakeResponse(
        f"https://linux.do{build_like_toggle_fragment('222')}",
        200,
        "{}",
        {"current_user_reaction": {"id": "heart"}},
    )
    page = FakeLikePage(
        {
            main.LIKE_BUTTON_SELECTORS[0]: [FakeButton()],
            scoped_like_selector("222"): [target_button],
        },
        [response],
    )
    browser = LinuxDoBrowser.__new__(LinuxDoBrowser)
    browser.request_kwargs = {}
    browser.session = FakeSession(
        get_routes={
            "https://linux.do/t/topic/1934859.json": [
                FakeResponse(
                    "https://linux.do/t/topic/1934859.json",
                    200,
                    json_data={
                        "post_stream": {
                            "posts": [
                                {"id": 111, "actions_summary": [{"id": 2, "can_act": True}]},
                                {"id": 222, "actions_summary": [{"id": 2, "can_act": True}]},
                            ]
                        }
                    },
                )
            ],
        },
    )
    browser._sync_browser_cookies_to_session = lambda: None

    monkeypatch.setattr(main.random, "uniform", lambda _a, _b: 0.0)
    monkeypatch.setattr(main.time, "sleep", lambda _seconds: None)

    browser.click_like(page)

    assert target_button.click_count == 1
    missing_candidate_calls = [
        call for call in page.locator_calls if call.startswith("article[data-post-id='111'] ")
    ]
    assert len(missing_candidate_calls) == len(main.LIKE_BUTTON_SELECTORS)


def test_click_like_retries_trusted_click_when_pointer_intercepted(monkeypatch):
    target_button = FakeButton(
        click_errors=[
            RuntimeError(
                "Locator.click: Timeout 3000ms exceeded. <div> intercepts pointer events"
            )
        ]
    )
    response = FakeResponse(
        f"https://linux.do{build_like_toggle_fragment('222')}",
        200,
        "{}",
        {"current_user_reaction": {"id": "heart"}},
    )
    page = FakeLikePage(
        {
            main.LIKE_BUTTON_SELECTORS[0]: [FakeButton()],
            scoped_like_selector("222"): [target_button],
        },
        [response],
    )
    browser = LinuxDoBrowser.__new__(LinuxDoBrowser)
    browser.request_kwargs = {}
    browser.session = FakeSession(
        get_routes={
            "https://linux.do/t/topic/1934859.json": [
                FakeResponse(
                    "https://linux.do/t/topic/1934859.json",
                    200,
                    json_data={
                        "post_stream": {
                            "posts": [
                                {"id": 222, "actions_summary": [{"id": 2, "can_act": True}]},
                            ]
                        }
                    },
                )
            ],
        },
    )
    browser._sync_browser_cookies_to_session = lambda: None

    monkeypatch.setattr(main.random, "uniform", lambda _a, _b: 0.0)
    monkeypatch.setattr(main.time, "sleep", lambda _seconds: None)

    browser.click_like(page)

    assert target_button.click_count == 1
    assert target_button.evaluate_calls == [
        "(el) => el.scrollIntoView({block: 'center', inline: 'center'})",
        "(el) => el.scrollIntoView({block: 'end', inline: 'center'})",
    ]
    assert page.expect_response_calls == [
        main.LIKE_BUTTON_RESPONSE_TIMEOUT_MS,
        main.LIKE_BUTTON_RESPONSE_TIMEOUT_MS,
    ]


def test_click_like_skips_candidate_when_pointer_intercept_persists(monkeypatch):
    first_button = FakeButton(
        click_errors=[
            RuntimeError(
                "Locator.click: Timeout 3000ms exceeded. <div> intercepts pointer events"
            ),
            RuntimeError(
                "Locator.click: Timeout 3000ms exceeded. <div> intercepts pointer events"
            ),
            RuntimeError(
                "Locator.click: Timeout 3000ms exceeded. <div> intercepts pointer events"
            ),
        ]
    )
    second_button = FakeButton()
    response = FakeResponse(
        f"https://linux.do{build_like_toggle_fragment('222')}",
        200,
        "{}",
        {"current_user_reaction": {"id": "heart"}},
    )
    page = FakeLikePage(
        {
            main.LIKE_BUTTON_SELECTORS[0]: [FakeButton()],
            scoped_like_selector("111"): [first_button],
            scoped_like_selector("222"): [second_button],
        },
        [response],
    )
    browser = LinuxDoBrowser.__new__(LinuxDoBrowser)
    browser.request_kwargs = {}
    browser.session = FakeSession(
        get_routes={
            "https://linux.do/t/topic/1934859.json": [
                FakeResponse(
                    "https://linux.do/t/topic/1934859.json",
                    200,
                    json_data={
                        "post_stream": {
                            "posts": [
                                {"id": 111, "actions_summary": [{"id": 2, "can_act": True}]},
                                {"id": 222, "actions_summary": [{"id": 2, "can_act": True}]},
                            ]
                        }
                    },
                )
            ],
        },
    )
    browser._sync_browser_cookies_to_session = lambda: None

    monkeypatch.setattr(main.random, "uniform", lambda _a, _b: 0.0)
    monkeypatch.setattr(main.time, "sleep", lambda _seconds: None)

    browser.click_like(page)

    assert first_button.click_count == 0
    assert second_button.click_count == 1
    assert first_button.evaluate_calls == [
        "(el) => el.scrollIntoView({block: 'center', inline: 'center'})",
        "(el) => el.scrollIntoView({block: 'end', inline: 'center'})",
        "(el) => el.scrollIntoView({block: 'start', inline: 'center'})",
    ]


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
