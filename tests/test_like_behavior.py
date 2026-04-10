import main
import pytest
from main import (
    LinuxDoBrowser,
    build_topic_json_url,
    build_like_toggle_fragment,
    collect_likeable_post_ids,
    extract_like_action_summary,
    extract_like_button_post_id,
    is_likeable_post_payload,
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
    def __init__(self, url: str, status: int, text: str = "", json_data=None) -> None:
        self.url = url
        self.status = status
        self._text = text
        self.status_code = status
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
            while self.responses:
                response = self.responses.pop(0)
                if predicate(response) is True:
                    return response
            raise AssertionError("no matching fake response found")

        return FakeResponseInfo(factory)

    def wait_for_timeout(self, timeout: int) -> None:
        self.wait_timeout_calls.append(timeout)


class FakeSession:
    def __init__(self, get_routes=None, put_routes=None) -> None:
        self.get_routes = {key: list(value) for key, value in (get_routes or {}).items()}
        self.put_routes = {key: list(value) for key, value in (put_routes or {}).items()}
        self.get_calls = []
        self.put_calls = []

    def get(self, url: str, **kwargs):
        self.get_calls.append((url, kwargs))
        responses = self.get_routes.get(url, [])
        assert responses, f"unexpected GET {url}"
        return responses.pop(0)

    def put(self, url: str, **kwargs):
        self.put_calls.append((url, kwargs))
        responses = self.put_routes.get(url, [])
        assert responses, f"unexpected PUT {url}"
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


def test_extract_like_button_post_id_reads_closest_article_id():
    assert extract_like_button_post_id(FakeButton(post_id="16477673")) == "16477673"


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


def test_is_pointer_intercept_error_matches_current_playwright_message():
    assert is_pointer_intercept_error(RuntimeError("foo intercepts pointer events bar"))
    assert not is_pointer_intercept_error(RuntimeError("other error"))


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


def test_click_like_skips_already_liked_posts_and_likes_next_candidate(monkeypatch):
    page = FakeLikePage({main.LIKE_BUTTON_SELECTORS[0]: [FakeButton()]}, [])
    page.url = "https://linux.do/t/topic/1934859"
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
            "https://linux.do/session/csrf": [
                FakeResponse(
                    "https://linux.do/session/csrf",
                    200,
                    json_data={"csrf": "csrf-token"},
                )
            ],
            "https://linux.do/posts/222": [
                FakeResponse(
                    "https://linux.do/posts/222",
                    200,
                    json_data={"actions_summary": [{"id": 2, "acted": True}]},
                )
            ],
        },
        put_routes={
            "https://linux.do/discourse-reactions/posts/222/custom-reactions/heart/toggle.json": [
                FakeResponse(
                    "https://linux.do/discourse-reactions/posts/222/custom-reactions/heart/toggle.json",
                    200,
                    "{}",
                )
            ]
        },
    )
    browser._sync_browser_cookies_to_session = lambda: None

    monkeypatch.setattr(main.random, "uniform", lambda _a, _b: 0.0)
    monkeypatch.setattr(main.time, "sleep", lambda _seconds: None)

    browser.click_like(page)

    assert [url for url, _kwargs in browser.session.get_calls] == [
        "https://linux.do/t/topic/1934859.json",
        "https://linux.do/session/csrf",
        "https://linux.do/posts/222",
    ]
    assert [url for url, _kwargs in browser.session.put_calls] == [
        "https://linux.do/discourse-reactions/posts/222/custom-reactions/heart/toggle.json"
    ]
    assert page.locator_calls[0] == main.LIKE_BUTTON_SELECTORS[0]


def test_click_like_retries_next_candidate_after_403(monkeypatch):
    page = FakeLikePage({main.LIKE_BUTTON_SELECTORS[0]: [FakeButton()]}, [])
    page.url = "https://linux.do/t/topic/1934859"
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
            "https://linux.do/session/csrf": [
                FakeResponse(
                    "https://linux.do/session/csrf",
                    200,
                    json_data={"csrf": "csrf-token"},
                )
            ],
            "https://linux.do/posts/222": [
                FakeResponse(
                    "https://linux.do/posts/222",
                    200,
                    json_data={"actions_summary": [{"id": 2, "acted": True}]},
                )
            ],
        },
        put_routes={
            "https://linux.do/discourse-reactions/posts/111/custom-reactions/heart/toggle.json": [
                FakeResponse(
                    "https://linux.do/discourse-reactions/posts/111/custom-reactions/heart/toggle.json",
                    403,
                    '{"errors":["forbidden"]}',
                )
            ],
            "https://linux.do/discourse-reactions/posts/222/custom-reactions/heart/toggle.json": [
                FakeResponse(
                    "https://linux.do/discourse-reactions/posts/222/custom-reactions/heart/toggle.json",
                    200,
                    "{}",
                )
            ],
        },
    )
    browser._sync_browser_cookies_to_session = lambda: None

    monkeypatch.setattr(main.random, "uniform", lambda _a, _b: 0.0)
    monkeypatch.setattr(main.time, "sleep", lambda _seconds: None)

    browser.click_like(page)

    assert [url for url, _kwargs in browser.session.put_calls] == [
        "https://linux.do/discourse-reactions/posts/111/custom-reactions/heart/toggle.json",
        "https://linux.do/discourse-reactions/posts/222/custom-reactions/heart/toggle.json",
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
