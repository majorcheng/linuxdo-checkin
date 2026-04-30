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
    parse_bool_env,
    response_looks_like_cloudflare,
    resolve_browser_launch_useragent,
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
    def __init__(
        self,
        selector_map,
        responses=None,
        url: str = "https://linux.do/t/topic/1934859",
        dialog_present: bool = False,
    ) -> None:
        self.selector_map = selector_map
        self.responses = list(responses or [])
        self.url = url
        self.locator_calls = []
        self.expect_response_calls = []
        self.wait_timeout_calls = []
        self.page_evaluate_calls = []
        self.dialog_present = dialog_present
        self.goto_calls = []
        self.wait_for_load_state_calls = []

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

    def goto(self, url: str, wait_until=None) -> None:
        self.goto_calls.append((url, wait_until))
        self.url = url

    def wait_for_load_state(self, state: str, timeout=None) -> None:
        self.wait_for_load_state_calls.append((state, timeout))

    def evaluate(self, script: str):
        self.page_evaluate_calls.append(script)
        if "#dialog-holder" in script:
            if not self.dialog_present:
                return {"found": False, "dismissed": False, "method": ""}
            self.dialog_present = False
            return {"found": True, "dismissed": True, "method": "close-button"}
        return None


class FakeTextLocator:
    def __init__(self, text: str) -> None:
        self.text = text

    def inner_text(self, timeout=None) -> str:
        return self.text


class FakeFetchPage:
    def __init__(self, url: str, title: str = "", body_text: str = "") -> None:
        self.url = url
        self._title = title
        self._body_text = body_text

    def title(self) -> str:
        return self._title

    def locator(self, selector: str):
        assert selector == "body"
        return FakeTextLocator(self._body_text)


class FakeScraplingBrowser:
    def __init__(self, pages=None) -> None:
        self.pages = list(pages or [])
        self.fetch_calls = []

    def fetch(self, url: str, **kwargs):
        self.fetch_calls.append((url, kwargs))
        assert self.pages, "no fake fetch page configured"
        page = self.pages.pop(0)
        assert page.url == url
        page_action = kwargs.get("page_action")
        if page_action is not None:
            page_action(page)


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


def scoped_click_target_selector(post_id: str) -> str:
    return f"article[data-post-id='{post_id}'] {main.LIKE_CLICK_TARGET_SELECTORS[0]}"


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


def test_parse_bool_env_reads_common_values(monkeypatch):
    monkeypatch.setenv("TEST_BOOL_ENV", "yes")
    assert parse_bool_env("TEST_BOOL_ENV", False) is True

    monkeypatch.setenv("TEST_BOOL_ENV", "off")
    assert parse_bool_env("TEST_BOOL_ENV", True) is False

    monkeypatch.setenv("TEST_BOOL_ENV", "unexpected")
    assert parse_bool_env("TEST_BOOL_ENV", True) is True


def test_resolve_browser_launch_useragent_prefers_native_headful_ua():
    assert resolve_browser_launch_useragent("captured-ua", headless=False) == "captured-ua"
    assert resolve_browser_launch_useragent("", headless=True) == main.DEFAULT_USER_AGENT
    assert resolve_browser_launch_useragent("", headless=False) == ""


def test_response_looks_like_cloudflare_matches_challenge_html():
    assert response_looks_like_cloudflare("<title>Just a moment...</title>")
    assert response_looks_like_cloudflare("Enable JavaScript and cookies to continue")
    assert not response_looks_like_cloudflare('{"ok":true}')


def test_request_browser_json_uses_scrapling_context():
    topic_json_url = "https://linux.do/t/topic/1934859.json"
    browser = LinuxDoBrowser.__new__(LinuxDoBrowser)
    browser.browser = FakeScraplingBrowser(
        [
            FakeFetchPage(
                topic_json_url,
                body_text='{"post_stream":{"posts":[{"id":222,"actions_summary":[{"id":2,"can_act":true}]}]}}',
            )
        ]
    )

    payload = browser._request_browser_json(
        topic_json_url,
        referer_url="https://linux.do/t/topic/1934859",
    )

    assert payload["post_stream"]["posts"][0]["id"] == 222
    fetch_url, fetch_kwargs = browser.browser.fetch_calls[0]
    assert fetch_url == topic_json_url
    assert fetch_kwargs["solve_cloudflare"] is True
    assert fetch_kwargs["extra_headers"] == {"Referer": "https://linux.do/t/topic/1934859"}


def test_request_browser_json_rejects_cloudflare_html():
    browser = LinuxDoBrowser.__new__(LinuxDoBrowser)
    browser.browser = FakeScraplingBrowser(
        [
            FakeFetchPage(
                "https://linux.do/t/topic/1934859.json",
                title="Just a moment...",
                body_text="Enable JavaScript and cookies to continue",
            )
        ]
    )

    with pytest.raises(RuntimeError, match="Cloudflare challenge"):
        browser._request_browser_json("https://linux.do/t/topic/1934859.json")


def test_create_browser_session_respects_browser_mode(monkeypatch):
    class DummyStealthSession:
        def __init__(self, **kwargs) -> None:
            self.kwargs = kwargs

    monkeypatch.setattr(main, "StealthySession", DummyStealthSession)
    monkeypatch.setattr(main, "SCRAPLING_IMPORT_ERROR", None)

    browser = LinuxDoBrowser.__new__(LinuxDoBrowser)
    browser.proxy_runtime = None
    browser.local_proxy_url = None
    browser.browser_headless = False
    browser.browser_real_chrome = True
    browser.browser_launch_useragent = ""
    browser.browser_extra_headers = {"Accept-Language": "zh-CN,zh;q=0.9"}

    managed = browser._create_browser_session()

    assert managed.session.kwargs["headless"] is False
    assert managed.session.kwargs["real_chrome"] is True
    assert managed.session.kwargs["useragent"] is None


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
            scoped_click_target_selector("222"): [target_button],
        },
        [response],
    )
    browser = LinuxDoBrowser.__new__(LinuxDoBrowser)
    browser.request_kwargs = {}
    browser._request_browser_json = lambda url, referer_url="": {
        "post_stream": {
            "posts": [
                {"id": 111, "actions_summary": [{"id": 2, "acted": True}]},
                {"id": 222, "actions_summary": [{"id": 2, "can_act": True}]},
            ]
        }
    }

    monkeypatch.setattr(main.random, "uniform", lambda _a, _b: 0.0)
    monkeypatch.setattr(main.time, "sleep", lambda _seconds: None)

    browser.click_like(page)

    assert target_button.click_count == 1
    assert target_button.last_timeout == main.LIKE_BUTTON_CLICK_TIMEOUT_MS
    assert page.expect_response_calls == [main.LIKE_BUTTON_RESPONSE_TIMEOUT_MS]
    assert page.page_evaluate_calls == [
        main.DISMISS_BLOCKING_DIALOG_SCRIPT,
        main.LIKE_DISABLE_HEADER_POINTER_EVENTS_SCRIPT,
        main.LIKE_RESTORE_HEADER_POINTER_EVENTS_SCRIPT,
    ]


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
            scoped_click_target_selector("111"): [first_button],
            scoped_click_target_selector("222"): [second_button],
        },
        [response_111, response_222],
    )
    browser = LinuxDoBrowser.__new__(LinuxDoBrowser)
    browser.request_kwargs = {}
    browser._request_browser_json = lambda url, referer_url="": {
        "post_stream": {
            "posts": [
                {"id": 111, "actions_summary": [{"id": 2, "can_act": True}]},
                {"id": 222, "actions_summary": [{"id": 2, "can_act": True}]},
            ]
        }
    }

    monkeypatch.setattr(main.random, "uniform", lambda _a, _b: 0.0)
    monkeypatch.setattr(main.time, "sleep", lambda _seconds: None)

    browser.click_like(page)

    assert first_button.click_count == 1
    assert second_button.click_count == 1
    assert page.expect_response_calls == [
        main.LIKE_BUTTON_RESPONSE_TIMEOUT_MS,
        main.LIKE_BUTTON_RESPONSE_TIMEOUT_MS,
    ]


def test_click_like_retries_same_candidate_after_cloudflare_recovery(monkeypatch):
    target_button = FakeButton()
    response_403 = FakeResponse(
        f"https://linux.do{build_like_toggle_fragment('222')}",
        403,
        "<html><title>Just a moment...</title></html>",
    )
    response_200 = FakeResponse(
        f"https://linux.do{build_like_toggle_fragment('222')}",
        200,
        "{}",
        {"current_user_used_main_reaction": True},
    )
    page = FakeLikePage(
        {
            main.LIKE_BUTTON_SELECTORS[0]: [FakeButton()],
            scoped_click_target_selector("222"): [target_button],
        },
        [response_403, response_200],
        url="https://linux.do/t/topic/1934859",
    )
    browser = LinuxDoBrowser.__new__(LinuxDoBrowser)
    browser.request_kwargs = {}
    browser._request_browser_json = lambda url, referer_url="": {
        "post_stream": {
            "posts": [
                {"id": 222, "actions_summary": [{"id": 2, "can_act": True}]},
            ]
        }
    }
    fetch_calls = []
    browser._fetch_page_snapshot = (
        lambda url, include_auth_signals=False, solve_cloudflare=None: fetch_calls.append(
            (url, include_auth_signals, solve_cloudflare)
        )
        or {"url": url, "title": "", "body_text": ""}
    )

    monkeypatch.setattr(main.random, "uniform", lambda _a, _b: 0.0)
    monkeypatch.setattr(main.time, "sleep", lambda _seconds: None)

    browser.click_like(page)

    assert target_button.click_count == 2
    assert fetch_calls == [("https://linux.do/t/topic/1934859", False, True)]
    assert page.goto_calls == [("https://linux.do/t/topic/1934859", "domcontentloaded")]
    assert page.wait_for_load_state_calls == [("networkidle", 5000)]


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
            scoped_click_target_selector("222"): [target_button],
        },
        [response],
    )
    browser = LinuxDoBrowser.__new__(LinuxDoBrowser)
    browser.request_kwargs = {}
    browser._request_browser_json = lambda url, referer_url="": {
        "post_stream": {
            "posts": [
                {"id": 111, "actions_summary": [{"id": 2, "can_act": True}]},
                {"id": 222, "actions_summary": [{"id": 2, "can_act": True}]},
            ]
        }
    }

    monkeypatch.setattr(main.random, "uniform", lambda _a, _b: 0.0)
    monkeypatch.setattr(main.time, "sleep", lambda _seconds: None)

    browser.click_like(page)

    assert target_button.click_count == 1
    missing_candidate_calls = [
        call for call in page.locator_calls if call.startswith("article[data-post-id='111'] ")
    ]
    assert len(missing_candidate_calls) == len(
        main.LIKE_CLICK_TARGET_SELECTORS + main.LIKE_BUTTON_SELECTORS
    )


def test_click_like_dismisses_blocking_dialog_before_click(monkeypatch):
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
            scoped_click_target_selector("222"): [target_button],
        },
        [response],
        dialog_present=True,
    )
    browser = LinuxDoBrowser.__new__(LinuxDoBrowser)
    browser.request_kwargs = {}
    browser._request_browser_json = lambda url, referer_url="": {
        "post_stream": {
            "posts": [
                {"id": 222, "actions_summary": [{"id": 2, "can_act": True}]},
            ]
        }
    }

    monkeypatch.setattr(main.random, "uniform", lambda _a, _b: 0.0)
    monkeypatch.setattr(main.time, "sleep", lambda _seconds: None)

    browser.click_like(page)

    assert target_button.click_count == 1
    assert main.DISMISS_BLOCKING_DIALOG_SCRIPT in page.page_evaluate_calls


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
            scoped_click_target_selector("222"): [target_button],
        },
        [response],
    )
    browser = LinuxDoBrowser.__new__(LinuxDoBrowser)
    browser.request_kwargs = {}
    browser._request_browser_json = lambda url, referer_url="": {
        "post_stream": {
            "posts": [
                {"id": 222, "actions_summary": [{"id": 2, "can_act": True}]},
            ]
        }
    }

    monkeypatch.setattr(main.random, "uniform", lambda _a, _b: 0.0)
    monkeypatch.setattr(main.time, "sleep", lambda _seconds: None)

    browser.click_like(page)

    assert target_button.click_count == 1
    assert target_button.evaluate_calls == [
        main.LIKE_BUTTON_REPOSITION_STEPS[0],
        main.LIKE_BUTTON_REPOSITION_STEPS[1],
    ]
    assert page.expect_response_calls == [
        main.LIKE_BUTTON_RESPONSE_TIMEOUT_MS,
        main.LIKE_BUTTON_RESPONSE_TIMEOUT_MS,
    ]
    assert page.page_evaluate_calls == [
        main.DISMISS_BLOCKING_DIALOG_SCRIPT,
        main.LIKE_DISABLE_HEADER_POINTER_EVENTS_SCRIPT,
        main.LIKE_RESTORE_HEADER_POINTER_EVENTS_SCRIPT,
        main.LIKE_DISABLE_HEADER_POINTER_EVENTS_SCRIPT,
        main.LIKE_RESTORE_HEADER_POINTER_EVENTS_SCRIPT,
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
            scoped_click_target_selector("111"): [first_button],
            scoped_click_target_selector("222"): [second_button],
        },
        [response],
    )
    browser = LinuxDoBrowser.__new__(LinuxDoBrowser)
    browser.request_kwargs = {}
    browser._request_browser_json = lambda url, referer_url="": {
        "post_stream": {
            "posts": [
                {"id": 111, "actions_summary": [{"id": 2, "can_act": True}]},
                {"id": 222, "actions_summary": [{"id": 2, "can_act": True}]},
            ]
        }
    }

    monkeypatch.setattr(main.random, "uniform", lambda _a, _b: 0.0)
    monkeypatch.setattr(main.time, "sleep", lambda _seconds: None)

    browser.click_like(page)

    assert first_button.click_count == 0
    assert second_button.click_count == 1
    assert first_button.evaluate_calls == [
        main.LIKE_BUTTON_REPOSITION_STEPS[0],
        main.LIKE_BUTTON_REPOSITION_STEPS[1],
        main.LIKE_BUTTON_REPOSITION_STEPS[2],
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
