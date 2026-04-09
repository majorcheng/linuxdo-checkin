"""
cron: 0 */6 * * *
new Env("Linux.Do 签到")
"""

import functools
import os
import random
import re
import shlex
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from curl_cffi import requests
from loguru import logger
from tabulate import tabulate

from notify import NotificationManager
from proxy_bridge import BrowserProxyRuntime, mask_proxy_url

try:
    from scrapling.fetchers import StealthySession
except Exception as exc:  # pragma: no cover - 依赖缺失时给出清晰报错
    StealthySession = None
    SCRAPLING_IMPORT_ERROR = exc
else:
    SCRAPLING_IMPORT_ERROR = None


DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/146.0.0.0 Safari/537.36"
)


@dataclass(frozen=True)
class CapturedRequestProfile:
    url: str = ""
    cookie_str: str = ""
    headers: Dict[str, str] = field(default_factory=dict)

    @property
    def useragent(self) -> str:
        return self.headers.get("user-agent", "").strip()

    @property
    def accept_language(self) -> str:
        return self.headers.get("accept-language", "").strip()


def looks_like_curl_command(raw_text: str) -> bool:
    return raw_text.lstrip().startswith("curl ")


def normalize_curl_command(raw_text: str) -> str:
    return re.sub(r"\\\s*\n\s*", " ", raw_text).strip()


def parse_header_line(raw_header: str) -> Tuple[str, str]:
    if ":" not in raw_header:
        return raw_header.strip().lower(), ""
    name, value = raw_header.split(":", 1)
    return name.strip().lower(), value.strip()


def parse_curl_command(raw_command: str) -> CapturedRequestProfile:
    command = normalize_curl_command(raw_command)
    if not command:
        return CapturedRequestProfile()

    try:
        tokens = shlex.split(command)
    except ValueError:
        return CapturedRequestProfile()

    if not tokens or tokens[0] != "curl":
        return CapturedRequestProfile()

    url = ""
    headers: Dict[str, str] = {}
    cookie_str = ""
    index = 1

    while index < len(tokens):
        token = tokens[index]

        if token in {"-H", "--header"} and index + 1 < len(tokens):
            header_name, header_value = parse_header_line(tokens[index + 1])
            if header_name == "cookie":
                cookie_str = header_value or cookie_str
            elif header_name:
                headers[header_name] = header_value
            index += 2
            continue

        if token in {"-b", "--cookie"} and index + 1 < len(tokens):
            cookie_str = tokens[index + 1].strip() or cookie_str
            index += 2
            continue

        if token in {"-A", "--user-agent"} and index + 1 < len(tokens):
            headers["user-agent"] = tokens[index + 1].strip()
            index += 2
            continue

        if token in {"-e", "--referer"} and index + 1 < len(tokens):
            headers["referer"] = tokens[index + 1].strip()
            index += 2
            continue

        if token == "--url" and index + 1 < len(tokens):
            url = tokens[index + 1].strip()
            index += 2
            continue

        if token.startswith(("https://", "http://")) and not url:
            url = token

        index += 1

    return CapturedRequestProfile(url=url, cookie_str=cookie_str, headers=headers)


def resolve_cookie_source_profile(
    raw_cookie_text: str,
    raw_login_curl: str,
) -> Tuple[CapturedRequestProfile, str]:
    if raw_login_curl:
        profile = parse_curl_command(raw_login_curl)
        return profile, profile.cookie_str or raw_cookie_text

    if looks_like_curl_command(raw_cookie_text):
        profile = parse_curl_command(raw_cookie_text)
        return profile, profile.cookie_str

    return CapturedRequestProfile(), raw_cookie_text


RAW_COOKIE_INPUT = os.environ.get("LINUXDO_COOKIES", "").strip()
RAW_LOGIN_CURL = os.environ.get("LINUXDO_LOGIN_CURL", "").strip()
CAPTURED_REQUEST_PROFILE, COOKIES = resolve_cookie_source_profile(
    RAW_COOKIE_INPUT,
    RAW_LOGIN_CURL,
)
CONNECT_COOKIES = os.environ.get("LINUXDO_CONNECT_COOKIES", "").strip()
BROWSE_ENABLED = os.environ.get("BROWSE_ENABLED", "true").strip().lower() not in [
    "false",
    "0",
    "off",
]
PROXY_URL = os.environ.get("LINUXDO_PROXY_URL", "").strip()
PROXY_INSECURE_RAW = os.environ.get("LINUXDO_PROXY_INSECURE", "").strip().lower()
if PROXY_INSECURE_RAW:
    PROXY_INSECURE = PROXY_INSECURE_RAW in [
        "true",
        "1",
        "on",
        "yes",
    ]
else:
    PROXY_INSECURE = PROXY_URL.lower().startswith("https://")
CONNECT_INFO_ENABLED = os.environ.get("LINUXDO_CONNECT_INFO_ENABLED", "false").strip().lower() in [
    "true",
    "1",
    "on",
    "yes",
]

HOME_URL = "https://linux.do/"
CONNECT_URL = "https://connect.linux.do/"
MIN_ONLINE_SECONDS = 10 * 60
SCRAPLING_TIMEOUT_MS = 60_000
LOGIN_FAILURE_SCREENSHOT = "login_check_failed.png"

SHARED_DOMAIN_COOKIE_NAMES = {
    "cf_clearance",
    "_t",
    "_forum_session",
    "_bypass_cache",
}
CONNECT_HOST_COOKIE_NAMES = {
    "linux_do_credit_session_id",
    "auth.session-token",
    "__stripe_sid",
    "__stripe_mid",
}
CLOUDFLARE_TITLES = (
    "Just a moment...",
    "Attention Required! | Cloudflare",
    "请稍候…",
    "请稍候...",
)
CLOUDFLARE_KEYWORDS = (
    "Performing security verification",
    "Verifying you are human",
    "Just a moment...",
    "/cdn-cgi/challenge-platform/",
    "Enable JavaScript and cookies to continue",
)
RATE_LIMIT_TITLES = (
    "You are being rate limited",
)
RATE_LIMIT_KEYWORDS = (
    "You are being rate limited",
    "rate limited",
)
LOGIN_ENTRY_LINK_SELECTORS = (
    "a[href*='/login']",
    "a:has-text('登录')",
    "a:has-text('Log In')",
    "a:has-text('Sign In')",
)
LOGIN_ENTRY_BUTTON_SELECTORS = (
    "button.login-button",
    ".header-buttons .login-button",
    "button:has-text('登录')",
    "button:has-text('Log In')",
    "button:has-text('Sign In')",
)
LOGGED_IN_USER_SELECTORS = (
    "#current-user",
    ".header-dropdown-toggle.current-user",
    ".current-user",
    "[data-identifier='user-menu']",
)
LIKE_ATTEMPT_PROBABILITY = 0.5
LIKE_BUTTON_SELECTORS = (
    ".discourse-reactions-reaction-button[title='点赞此帖子'] button.btn-toggle-reaction-like",
    ".discourse-reactions-reaction-button[title='点赞此帖子'] button.reaction-button",
    "button.btn-toggle-reaction-like[title='点赞此帖子']",
    "button.reaction-button[title='点赞此帖子']",
    ".discourse-reactions-reaction-button[title='Like this post'] button.btn-toggle-reaction-like",
    ".discourse-reactions-reaction-button[title='Like this post'] button.reaction-button",
    "button.btn-toggle-reaction-like[title='Like this post']",
    "button.reaction-button[title='Like this post']",
)
LIKE_TOGGLE_URL_KEYWORDS = (
    "/discourse-reactions/posts/",
    "/custom-reactions/heart/toggle.json",
)


def retry_decorator(retries: int = 3, min_delay: int = 5, max_delay: int = 10):
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            for attempt in range(retries):
                try:
                    return func(*args, **kwargs)
                except Exception as exc:
                    if attempt == retries - 1:
                        logger.error(f"函数 {func.__name__} 最终执行失败: {str(exc)}")
                    logger.warning(
                        f"函数 {func.__name__} 第 {attempt + 1}/{retries} 次尝试失败: {str(exc)}"
                    )
                    if attempt < retries - 1:
                        sleep_s = random.uniform(min_delay, max_delay)
                        logger.info(
                            f"将在 {sleep_s:.2f}s 后重试 ({min_delay}-{max_delay}s 随机延迟)"
                        )
                        time.sleep(sleep_s)
            return None

        return wrapper

    return decorator


def normalize_text(text: Optional[str]) -> str:
    if not text:
        return ""
    return " ".join(text.split())


def browser_timeout_ms() -> int:
    return SCRAPLING_TIMEOUT_MS


def safe_title(page: Any) -> str:
    try:
        return normalize_text(page.title() or "")
    except Exception:
        return ""


def safe_body_text(page: Any) -> str:
    try:
        return normalize_text(page.locator("body").inner_text(timeout=5_000))
    except Exception:
        return ""


def safe_count(page: Any, selector: str) -> int:
    try:
        return int(page.locator(selector).count())
    except Exception:
        return 0


def safe_visible_count(page: Any, selector: str) -> int:
    try:
        locator = page.locator(selector)
        count = locator.count()
    except Exception:
        return 0

    visible_count = 0
    for index in range(count):
        try:
            if locator.nth(index).is_visible():
                visible_count += 1
        except Exception:
            continue
    return visible_count


def build_page_snapshot(page: Any, include_auth_signals: bool = False) -> Dict[str, Any]:
    snapshot: Dict[str, Any] = {
        "url": getattr(page, "url", "") or "",
        "title": safe_title(page),
        "body_text": safe_body_text(page),
    }
    if include_auth_signals:
        snapshot.update(count_auth_controls(page))
    return snapshot


def collect_page_snapshot(
    page: Any,
    include_auth_signals: bool = False,
) -> Dict[str, Any]:
    return build_page_snapshot(page, include_auth_signals=include_auth_signals)


def is_cloudflare_snapshot(snapshot: Dict[str, Any]) -> bool:
    title = snapshot.get("title", "") or ""
    body_text = snapshot.get("body_text", "") or ""
    if any(keyword in title for keyword in CLOUDFLARE_TITLES):
        return True
    return any(keyword in body_text for keyword in CLOUDFLARE_KEYWORDS)


def is_rate_limited_snapshot(snapshot: Dict[str, Any]) -> bool:
    title = snapshot.get("title", "") or ""
    body_text = snapshot.get("body_text", "") or ""
    if any(keyword in title for keyword in RATE_LIMIT_TITLES):
        return True
    return any(keyword in body_text for keyword in RATE_LIMIT_KEYWORDS)


def wait_seconds(min_seconds: float, max_seconds: float, label: str) -> float:
    seconds = random.uniform(min_seconds, max_seconds)
    logger.info(f"{label} {seconds:.2f} 秒")
    time.sleep(seconds)
    return seconds


def wait_page_seconds(page: Any, min_seconds: float, max_seconds: float, label: str) -> float:
    seconds = random.uniform(min_seconds, max_seconds)
    logger.info(f"{label} {seconds:.2f} 秒")
    try:
        page.wait_for_timeout(int(seconds * 1000))
    except Exception:
        time.sleep(seconds)
    return seconds


def count_auth_controls(page: Any) -> Dict[str, int]:
    return {
        "current_user_count": safe_count(page, "#current-user"),
        "avatar_count": safe_count(page, "#current-user img, .header-dropdown-toggle.current-user img"),
        "user_menu_count": safe_visible_count(page, ", ".join(LOGGED_IN_USER_SELECTORS)),
        "login_button_count": safe_visible_count(
            page,
            ", ".join(LOGIN_ENTRY_BUTTON_SELECTORS),
        ),
        "login_link_count": safe_visible_count(
            page,
            ", ".join(LOGIN_ENTRY_LINK_SELECTORS),
        ),
        "register_link_count": safe_visible_count(
            page,
            "a[href*='/signup'], a[href*='/sign-up'], a:has-text('注册'), a:has-text('Sign Up')",
        ),
    }


def classify_login_snapshot(
    snapshot: Dict[str, Any],
    has_login_session_cookie: bool = False,
) -> Tuple[str, Optional[str]]:
    current_url = snapshot.get("url", "") or ""
    body_text = snapshot.get("body_text", "") or ""
    current_user_count = int(snapshot.get("current_user_count", 0) or 0)
    avatar_count = int(snapshot.get("avatar_count", 0) or 0)
    user_menu_count = int(snapshot.get("user_menu_count", 0) or 0)
    login_button_count = int(snapshot.get("login_button_count", 0) or 0)
    login_link_count = int(snapshot.get("login_link_count", 0) or 0)
    register_link_count = int(snapshot.get("register_link_count", 0) or 0)
    has_logged_in_ui = current_user_count > 0 or avatar_count > 0 or user_menu_count > 0

    if is_cloudflare_snapshot(snapshot):
        return "cf_challenge", "登录检测阶段遭遇 Cloudflare/风控页"

    if is_rate_limited_snapshot(snapshot):
        return "rate_limited", "主页触发站点限流，需冷却后重试"

    if "/login" in current_url or "/session/sso_provider" in current_url:
        return "login_page", "跳转到了登录页或 SSO 页面，Cookie 可能失效"

    if has_logged_in_ui:
        return "ok", None

    if has_login_session_cookie and login_button_count == 0 and login_link_count == 0 and register_link_count == 0:
        return "ok", "检测到主站会话 Cookie，且页面未暴露匿名入口"

    if login_button_count > 0 or login_link_count > 0 or register_link_count > 0:
        return "cookie_invalid", "页面出现匿名态控件，Cookie 可能失效"

    if "登录" in body_text and ("注册" in body_text or "欢迎回来" in body_text) and not has_logged_in_ui:
        return "cookie_invalid", "页面仍停留在匿名态，Cookie 可能失效"

    return "unknown_page", "未识别到稳定登录态，可能是风控、页面结构变化或 Cookie 不匹配"


def is_linuxdo_topic_url(url: str) -> bool:
    if not url:
        return False
    parsed = urlparse(url)
    return parsed.netloc.endswith("linux.do") and "/t/" in parsed.path


def extract_target_phrase(body_text: str) -> str:
    if not body_text:
        return ""

    match = re.search(r"@[^\s]+ · 过去 100 天内的数据", body_text)
    if match:
        return match.group(0)

    marker = "过去 100 天内的数据"
    index = body_text.find(marker)
    if index < 0:
        return ""

    start = max(0, index - 24)
    end = min(len(body_text), index + len(marker) + 24)
    return body_text[start:end]


def is_like_toggle_url(url: str) -> bool:
    if not url:
        return False
    return all(keyword in url for keyword in LIKE_TOGGLE_URL_KEYWORDS)


def is_pointer_intercept_error(exc: Exception) -> bool:
    return "intercepts pointer events" in str(exc)


def build_like_toggle_fragment(post_id: str) -> str:
    post_id = str(post_id or "").strip()
    if not post_id:
        return ""
    return f"/discourse-reactions/posts/{post_id}/custom-reactions/heart/toggle.json"


def extract_like_button_post_id(button: Any) -> str:
    try:
        return str(
            button.evaluate(
                "(el) => el.closest('article')?.getAttribute('data-post-id') || ''"
            )
            or ""
        ).strip()
    except Exception:
        return ""


def read_response_text(response: Any) -> str:
    try:
        return str(response.text() or "").strip()
    except Exception:
        return ""


class ManagedStealthSession:
    """统一管理 Scrapling 会话和可选本地代理桥生命周期。"""

    def __init__(self, session: Any, proxy_runtime: Optional[BrowserProxyRuntime] = None):
        self.session = session
        self.proxy_runtime = proxy_runtime

    def __enter__(self):
        return self.session.__enter__()

    def __exit__(self, exc_type, exc, tb):
        try:
            return bool(self.session.__exit__(exc_type, exc, tb))
        finally:
            if self.proxy_runtime is not None:
                self.proxy_runtime.stop()


class LinuxDoBrowser:
    def __init__(self) -> None:
        self.proxy_runtime = None
        self.local_proxy_url = None
        self.managed_browser = None
        self.browser = None
        self.page = None
        self.notifier = NotificationManager()
        self.last_failure_reason = ""
        self.captured_request_profile = CAPTURED_REQUEST_PROFILE
        self.browser_useragent = self.captured_request_profile.useragent or DEFAULT_USER_AGENT
        self.browser_extra_headers: Dict[str, str] = {}
        if self.captured_request_profile.accept_language:
            self.browser_extra_headers["Accept-Language"] = self.captured_request_profile.accept_language

        self.session = requests.Session()
        if hasattr(self.session, "trust_env"):
            self.session.trust_env = False

        self.request_kwargs = {}
        self.session.headers.update(
            {
                "User-Agent": self.browser_useragent,
                "Accept": "application/json, text/javascript, */*; q=0.01",
                "Accept-Language": self.captured_request_profile.accept_language or "zh-CN,zh;q=0.9",
            }
        )
        if self.captured_request_profile.headers.get("referer"):
            self.session.headers["Referer"] = self.captured_request_profile.headers["referer"]

        try:
            if PROXY_URL:
                self.proxy_runtime = BrowserProxyRuntime(PROXY_URL, PROXY_INSECURE)
                self.local_proxy_url = self.proxy_runtime.start()
                self.request_kwargs = {"proxy": self.local_proxy_url}
                logger.info(
                    "浏览器与请求流量将通过本地代理桥: "
                    f"{self.local_proxy_url} -> {mask_proxy_url(PROXY_URL)}"
                )
                if PROXY_INSECURE and PROXY_URL.lower().startswith("https://"):
                    if PROXY_INSECURE_RAW:
                        logger.warning(
                            "已启用 LINUXDO_PROXY_INSECURE=true，"
                            "仅跳过连接上游 HTTPS 代理的证书校验"
                        )
                    else:
                        logger.warning(
                            "检测到上游使用 https:// 代理，默认启用 insecure 模式；"
                            "如需关闭，请显式设置 LINUXDO_PROXY_INSECURE=false"
                        )

            self.managed_browser = self._create_browser_session()
            self.browser = self.managed_browser.__enter__()
        except Exception:
            if self.proxy_runtime is not None:
                try:
                    self.proxy_runtime.stop()
                except Exception:
                    pass
            raise

    def _create_browser_session(self) -> ManagedStealthSession:
        if SCRAPLING_IMPORT_ERROR is not None or StealthySession is None:
            raise RuntimeError(
                "未检测到 Scrapling 运行依赖，请先执行 `pip install -r requirements.txt`，"
                "然后执行 `scrapling install`。"
            ) from SCRAPLING_IMPORT_ERROR

        browser = StealthySession(
            headless=True,
            solve_cloudflare=True,
            network_idle=False,
            timeout=browser_timeout_ms(),
            google_search=False,
            useragent=self.browser_useragent,
            extra_headers=self.browser_extra_headers or None,
            locale="zh-CN",
            timezone_id="Asia/Shanghai",
            proxy=self.local_proxy_url,
            load_dom=True,
        )
        return ManagedStealthSession(browser, self.proxy_runtime)

    @staticmethod
    def build_cookie_payloads(
        cookie_str: str,
        default_target_url: str = HOME_URL,
    ) -> List[Dict[str, Any]]:
        payloads = []
        for cookie_item in cookie_str.split(";"):
            cookie_item = cookie_item.strip()
            if not cookie_item or "=" not in cookie_item:
                continue

            name, value = cookie_item.split("=", 1)
            name = name.strip()
            value = value.strip()
            if not name:
                continue

            if name in SHARED_DOMAIN_COOKIE_NAMES:
                payloads.append(
                    {
                        "name": name,
                        "value": value,
                        "domain": ".linux.do",
                        "path": "/",
                        "secure": True,
                    }
                )
                continue

            if name.startswith("__Host-"):
                payloads.append(
                    {
                        "name": name,
                        "value": value,
                        "url": default_target_url,
                        "path": "/",
                        "secure": True,
                    }
                )
                continue

            target_url = (
                default_target_url
            )
            payloads.append({"name": name, "value": value, "url": target_url})

        return payloads

    @staticmethod
    def _dedupe_cookie_payloads(payloads: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        deduped: dict[tuple[str, str, str], Dict[str, Any]] = {}
        for payload in payloads:
            target = str(payload.get("domain") or payload.get("url") or "")
            path = str(payload.get("path") or "/")
            key = (str(payload.get("name") or ""), target, path)
            deduped[key] = payload
        return list(deduped.values())

    def _session_cookies_to_browser_payloads(self) -> List[Dict[str, Any]]:
        payloads = []
        cookie_jar = getattr(self.session.cookies, "jar", None)
        if cookie_jar is None:
            return payloads

        for cookie in cookie_jar:
            payload = {
                "name": cookie.name,
                "value": cookie.value,
            }

            if cookie.name.startswith("__Host-"):
                payload.update(
                    {
                        "url": HOME_URL,
                        "path": "/",
                        "secure": True,
                    }
                )
            elif getattr(cookie, "domain", None):
                payload.update(
                    {
                        "domain": cookie.domain,
                        "path": cookie.path or "/",
                    }
                )
                if getattr(cookie, "secure", False):
                    payload["secure"] = True
            else:
                target_url = CONNECT_URL if cookie.name in CONNECT_HOST_COOKIE_NAMES else HOME_URL
                payload["url"] = target_url

            expires = getattr(cookie, "expires", None)
            if expires:
                try:
                    payload["expires"] = int(float(expires))
                except (TypeError, ValueError):
                    pass

            payloads.append(payload)
        return payloads

    def _seed_browser_cookies(
        self,
        cookie_str: str,
        connect_cookie_str: str = "",
    ) -> int:
        payloads: List[Dict[str, Any]] = []
        if cookie_str:
            payloads.extend(self.build_cookie_payloads(cookie_str, HOME_URL))
        if connect_cookie_str:
            payloads.extend(self.build_cookie_payloads(connect_cookie_str, CONNECT_URL))

        payloads = self._dedupe_cookie_payloads(payloads)
        if not payloads:
            return 0

        self.browser.context.clear_cookies()
        self.browser.context.add_cookies(payloads)
        return len(payloads)

    @staticmethod
    def _session_cookie_kwargs_from_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
        kwargs: Dict[str, Any] = {}
        domain = str(payload.get("domain") or "").strip()
        path = str(payload.get("path") or "").strip()
        secure = payload.get("secure")

        if domain:
            kwargs["domain"] = domain
        elif payload.get("url"):
            parsed = urlparse(str(payload["url"]))
            if parsed.hostname:
                kwargs["domain"] = parsed.hostname
            if not path:
                path = parsed.path or "/"
            if secure is None:
                secure = parsed.scheme == "https"

        kwargs["path"] = path or "/"
        if secure is not None:
            kwargs["secure"] = bool(secure)

        expires = payload.get("expires")
        if expires:
            kwargs["expires"] = expires
        return kwargs

    def _seed_session_cookies(
        self,
        cookie_str: str,
        connect_cookie_str: str = "",
    ) -> int:
        payloads: List[Dict[str, Any]] = []
        if cookie_str:
            payloads.extend(self.build_cookie_payloads(cookie_str, HOME_URL))
        if connect_cookie_str:
            payloads.extend(self.build_cookie_payloads(connect_cookie_str, CONNECT_URL))

        payloads = self._dedupe_cookie_payloads(payloads)
        for payload in payloads:
            self.session.cookies.set(
                str(payload.get("name") or ""),
                str(payload.get("value") or ""),
                **self._session_cookie_kwargs_from_payload(payload),
            )
        return len(payloads)

    def _warmup_session_from_captured_request(self) -> bool:
        profile = self.captured_request_profile
        if not profile.url or not profile.cookie_str:
            return False

        headers = {
            header_name: header_value
            for header_name, header_value in profile.headers.items()
            if header_name != "cookie"
        }

        try:
            response = self.session.get(
                profile.url,
                headers=headers,
                impersonate="chrome136",
                **self.request_kwargs,
            )
        except Exception as exc:
            logger.warning(f"复用抓包请求预热 Cookie 会话失败: {str(exc)}")
            return False

        if response.status_code >= 400:
            logger.warning(
                f"复用抓包请求预热 Cookie 会话失败: status={response.status_code}, url={profile.url}"
            )
            return False

        logger.info(
            f"已复用抓包请求预热 Cookie 会话: status={response.status_code}, url={profile.url}"
        )
        return True

    def _sync_browser_cookies_to_session(self) -> None:
        self.session.cookies.clear()
        for cookie in self.browser.context.cookies():
            if not cookie.get("name"):
                continue

            kwargs = {}
            if cookie.get("domain"):
                kwargs["domain"] = cookie["domain"]
            if cookie.get("path"):
                kwargs["path"] = cookie["path"]
            if cookie.get("secure"):
                kwargs["secure"] = cookie["secure"]

            self.session.cookies.set(cookie["name"], cookie.get("value", ""), **kwargs)

    def _sync_session_cookies_to_browser(self) -> int:
        payloads = self._session_cookies_to_browser_payloads()
        self.browser.context.clear_cookies()
        if payloads:
            self.browser.context.add_cookies(payloads)
        return len(payloads)

    def _browser_cookie_names(self) -> set[str]:
        names: set[str] = set()
        for cookie in self.browser.context.cookies():
            name = str(cookie.get("name") or "").strip()
            if name:
                names.add(name)
        return names

    def _has_login_session_cookie(self) -> bool:
        return "_t" in self._browser_cookie_names()

    def _fetch_page_snapshot(
        self,
        target_url: str,
        include_auth_signals: bool = False,
        screenshot_path: Optional[str] = None,
        solve_cloudflare: Optional[bool] = None,
    ) -> Dict[str, Any]:
        snapshot: Dict[str, Any] = {}

        def action(page: Any) -> None:
            snapshot.update(
                collect_page_snapshot(
                    page,
                    include_auth_signals=include_auth_signals,
                )
            )
            if screenshot_path:
                try:
                    page.screenshot(path=screenshot_path, full_page=True)
                    snapshot["screenshot_path"] = screenshot_path
                except Exception as exc:
                    logger.warning(f"保存截图失败: {str(exc)}")

        fetch_kwargs = {
            "page_action": action,
            "wait_selector": "body",
            "timeout": browser_timeout_ms(),
            "google_search": False,
            "load_dom": True,
        }
        if solve_cloudflare is not None:
            fetch_kwargs["solve_cloudflare"] = solve_cloudflare

        try:
            self.browser.fetch(target_url, **fetch_kwargs)
        except Exception as exc:
            logger.warning(f"页面快照抓取首次失败，降级重试: {str(exc)}")
            fetch_kwargs.pop("wait_selector", None)
            self.browser.fetch(target_url, **fetch_kwargs)
        return snapshot

    def _remember_failure(self, reason: str) -> None:
        normalized_reason = normalize_text(reason)
        if normalized_reason:
            self.last_failure_reason = normalized_reason

    def _log_login_diagnostics(self, source_label: str, snapshot: Dict[str, Any], reason: str) -> None:
        logger.error(f"{source_label} 登录验证失败: {reason}")
        logger.info(f"当前URL: {snapshot.get('url', '<unknown>') or '<unknown>'}")
        logger.info(f"页面标题: {snapshot.get('title', '<unknown>') or '<unknown>'}")
        metric_keys = (
            "current_user_count",
            "avatar_count",
            "user_menu_count",
            "login_button_count",
            "login_link_count",
            "register_link_count",
        )
        metric_parts = [f"{key}={snapshot[key]}" for key in metric_keys if key in snapshot]
        if metric_parts:
            logger.info(f"页面信号: {', '.join(metric_parts)}")
        logger.info(
            "页面预览: "
            f"{(snapshot.get('body_text', '') or '')[:300] or '<empty>'}"
        )
        if snapshot.get("screenshot_path"):
            logger.info(f"诊断截图: {snapshot['screenshot_path']}")

    def _validate_login_state(self, source_label: str) -> bool:
        last_snapshot: Dict[str, Any] = {}
        last_reason = "未完成登录态检测"

        for attempt in range(1, 4):
            try:
                snapshot = self._fetch_page_snapshot(HOME_URL, include_auth_signals=True)
            except Exception as exc:
                last_reason = f"打开首页失败: {str(exc)}"
                logger.warning(f"{source_label} 登录态探测[{attempt}/3]失败: {last_reason}")
                if attempt < 3:
                    time.sleep(3)
                    continue
                break

            last_snapshot = snapshot
            has_login_session_cookie = self._has_login_session_cookie()
            status_code, reason = classify_login_snapshot(
                snapshot,
                has_login_session_cookie=has_login_session_cookie,
            )
            last_reason = reason or ""
            logger.info(
                f"{source_label} 登录态探测[{attempt}/3]: status={status_code}, "
                f"url={snapshot.get('url', '<unknown>')}, "
                f"current_user={snapshot.get('current_user_count', 0)}, "
                f"avatar={snapshot.get('avatar_count', 0)}, "
                f"user_menu={snapshot.get('user_menu_count', 0)}, "
                f"login_button={snapshot.get('login_button_count', 0)}, "
                f"login_link={snapshot.get('login_link_count', 0)}, "
                f"register_link={snapshot.get('register_link_count', 0)}, "
                f"has_t={int(has_login_session_cookie)}"
            )

            if status_code == "ok":
                self._sync_browser_cookies_to_session()
                logger.success(f"{source_label} 登录验证成功")
                return True

            if status_code == "cf_challenge" and attempt < 3:
                logger.warning(f"{source_label} 遇到 Cloudflare/风控页，等待后重试...")
                time.sleep(5)
                continue

            if attempt < 3:
                logger.warning(f"{source_label} 登录态未确认，等待后重试...")
                time.sleep(3)

        try:
            diagnostic_snapshot = self._fetch_page_snapshot(
                last_snapshot.get("url") or HOME_URL,
                include_auth_signals=True,
                screenshot_path=LOGIN_FAILURE_SCREENSHOT,
            )
            if diagnostic_snapshot:
                last_snapshot = diagnostic_snapshot
        except Exception as exc:
            logger.warning(f"补抓登录诊断页面失败: {str(exc)}")

        self._remember_failure(f"{source_label} 登录验证失败: {last_reason}")
        self._log_login_diagnostics(source_label, last_snapshot, last_reason)
        return False

    def login_with_cookies(self, cookie_str: str) -> bool:
        logger.info("检测到手动 Cookie，尝试 Cookie 登录...")
        self.session.cookies.clear()
        payload_count = self._seed_session_cookies(cookie_str, CONNECT_COOKIES)
        if payload_count <= 0:
            self._remember_failure("Cookie 解析失败或为空")
            logger.error("Cookie 解析失败或为空，无法使用 Cookie 登录")
            return False

        if self._warmup_session_from_captured_request():
            payload_count = self._sync_session_cookies_to_browser()
        else:
            payload_count = self._seed_browser_cookies(cookie_str, CONNECT_COOKIES)

        if CONNECT_COOKIES:
            logger.info(f"已预注入 {payload_count} 个 Cookie 到 Scrapling 浏览器上下文（含 connect 域 Cookie）")
        else:
            logger.info(f"已预注入 {payload_count} 个 Cookie 到 Scrapling 浏览器上下文")
        if not self._has_login_session_cookie():
            logger.warning("当前注入的主站 Cookie 未包含 _t，主站登录态大概率无法恢复")
        return self._validate_login_state("Cookie")

    def _open_home_page(self) -> None:
        if self.page is not None:
            try:
                self.page.close()
            except Exception:
                pass

        self.page = self.browser.context.new_page()
        self.page.set_default_navigation_timeout(browser_timeout_ms())
        self.page.set_default_timeout(browser_timeout_ms())
        self._refresh_home_page()

    def _refresh_home_page(self) -> None:
        if self.page is None:
            raise RuntimeError("首页页面未初始化")

        self.page.goto(HOME_URL, wait_until="domcontentloaded")
        try:
            self.page.wait_for_load_state("networkidle", timeout=5_000)
        except Exception:
            pass
        wait_page_seconds(self.page, 2.0, 3.5, "主页恢复后额外等待")

    def _extract_topic_urls(self) -> List[str]:
        if self.page is None:
            return []

        selectors = (
            "#list-area a.title",
            "#list-area .title a",
            "a.title.raw-link.raw-topic-link",
            "a.title",
        )
        for selector in selectors:
            try:
                urls = self.page.eval_on_selector_all(
                    selector,
                    "nodes => nodes.map(node => node.href).filter(Boolean)",
                )
            except Exception:
                continue

            clean_urls = []
            for url in urls or []:
                if is_linuxdo_topic_url(url):
                    clean_urls.append(url)

            if clean_urls:
                deduped_urls = list(dict.fromkeys(clean_urls))
                return deduped_urls

        return []

    def _wait_for_topic_urls(self, attempts: int = 3, wait_ms: int = 1_200) -> List[str]:
        for attempt in range(1, attempts + 1):
            topic_urls = self._extract_topic_urls()
            if topic_urls:
                if attempt > 1:
                    logger.info(f"主题列表延迟加载，等待后恢复，共找到 {len(topic_urls)} 个候选帖子")
                return topic_urls

            if attempt < attempts and self.page is not None:
                try:
                    self.page.wait_for_timeout(wait_ms)
                except Exception:
                    time.sleep(wait_ms / 1000)

        return []

    def _inspect_home_page_state(self) -> Tuple[str, Optional[str], Dict[str, Any]]:
        if self.page is None:
            snapshot = {"url": "", "title": "", "body_text": ""}
            return "unknown_page", "首页页面不存在", snapshot

        snapshot: Dict[str, Any] = {
            "url": getattr(self.page, "url", "") or "",
            "title": safe_title(self.page),
            "body_text": safe_body_text(self.page),
        }
        snapshot.update(count_auth_controls(self.page))
        status_code, reason = classify_login_snapshot(
            snapshot,
            has_login_session_cookie=self._has_login_session_cookie(),
        )
        return status_code, reason, snapshot

    def click_topic(self, deadline_ts: float) -> bool:
        self._open_home_page()

        seen_urls = set()
        processed_count = 0
        max_rounds = 500
        empty_retry_count = 0
        max_empty_retries = 20

        while time.time() <= deadline_ts and processed_count < max_rounds:
            topic_urls = self._wait_for_topic_urls()
            if not topic_urls:
                empty_retry_count += 1
                status_code, reason, snapshot = self._inspect_home_page_state()
                log_func = logger.info if empty_retry_count <= 2 else logger.warning
                log_func(
                    "首页未拿到主题帖，稍后重试: "
                    f"retry={empty_retry_count}/{max_empty_retries}, "
                    f"status={status_code}, "
                    f"url={snapshot.get('url', '<unknown>') or '<unknown>'}, "
                    f"title={snapshot.get('title', '<unknown>') or '<unknown>'}"
                )
                if reason and empty_retry_count in {1, 3, 6, 10, max_empty_retries}:
                    logger.info(f"首页状态提示: {reason}")
                if status_code in {"login_page", "cookie_invalid"}:
                    self._remember_failure("浏览过程中登录态疑似失效")
                    logger.error("浏览过程中登录态疑似失效，提前结束浏览任务")
                    return processed_count > 0
                if empty_retry_count > max_empty_retries:
                    self._remember_failure("多次未找到主题帖")
                    logger.error("多次未找到主题帖，结束浏览任务")
                    return processed_count > 0

                try:
                    if status_code == "rate_limited":
                        if empty_retry_count <= 2:
                            wait_seconds(12, 18, "命中限流页，冷却后停留当前主页")
                        elif empty_retry_count <= 5:
                            wait_seconds(18, 28, "命中限流页，冷却后重新进入主页")
                            self._refresh_home_page()
                        elif empty_retry_count <= 8:
                            wait_seconds(25, 40, "命中限流页，冷却后重建首页页签")
                            self._open_home_page()
                        else:
                            wait_seconds(30, 45, "命中限流页，长冷却后重建首页页签")
                            self._open_home_page()
                        continue

                    if status_code == "cf_challenge":
                        wait_seconds(4, 6, "主页触发 Cloudflare，等待后再恢复")
                    else:
                        wait_seconds(2, 4, "首页未拿到主题帖，短暂等待后恢复")

                    if empty_retry_count <= 2:
                        logger.info("首页主题列表可能仍在异步加载，继续等待当前页恢复")
                        if self.page is not None:
                            wait_page_seconds(self.page, 1.2, 1.8, "当前主页额外等待")
                    elif empty_retry_count <= 5:
                        logger.info("首页连续空列表，重新进入主页")
                        self._refresh_home_page()
                    elif empty_retry_count <= 8:
                        logger.warning("首页多次空列表，重建首页页签后重试")
                        self._open_home_page()
                    else:
                        logger.warning("首页持续空列表，触发登录态复检")
                        if not self._validate_login_state("浏览恢复"):
                            self._remember_failure(self.last_failure_reason or "浏览恢复阶段登录态复检失败")
                            logger.error("浏览恢复阶段登录态复检失败，提前结束浏览任务")
                            return processed_count > 0
                        self._open_home_page()
                except Exception as exc:
                    logger.warning(f"首页恢复动作失败，改为重建首页页签: {str(exc)}")
                    self._open_home_page()
                continue

            empty_retry_count = 0
            unvisited_urls = [url for url in topic_urls if url not in seen_urls]
            if not unvisited_urls:
                seen_urls.clear()
                unvisited_urls = topic_urls
                logger.info("当前页面主题帖已轮询一遍，重置已访问集合")

            picked_url = random.choice(unvisited_urls)
            seen_urls.add(picked_url)
            logger.info(f"随机抽取第 {processed_count + 1} 个帖子进行浏览: {picked_url}")
            self.click_one_topic(picked_url)
            logger.info("当前帖子浏览完成，准备刷新首页主题列表")
            processed_count += 1

            if time.time() > deadline_ts:
                logger.success("登录在线时长已超过10分钟，结束浏览任务")
                break

            wait_seconds(5, 9, "帖子浏览结束，返回主页前冷却")
            try:
                self._refresh_home_page()
            except Exception:
                self._open_home_page()

        if processed_count >= max_rounds:
            logger.warning(f"达到最大浏览轮次限制({max_rounds})，提前结束浏览任务")

        logger.info(f"本次共浏览 {processed_count} 个帖子")
        return processed_count > 0

    @retry_decorator()
    def click_one_topic(self, topic_url: str) -> None:
        page = self.browser.context.new_page()
        page.set_default_navigation_timeout(browser_timeout_ms())
        page.set_default_timeout(browser_timeout_ms())
        try:
            page.goto(topic_url, wait_until="domcontentloaded")
            wait_page_seconds(page, 2.0, 4.0, "进入帖子后停留")
            if random.random() < LIKE_ATTEMPT_PROBABILITY:
                self.click_like(page)
            self.browse_post(page)
        finally:
            try:
                page.close()
            except Exception:
                pass

    def browse_post(self, page: Any) -> None:
        previous_scroll_y = -1
        stopped_early = False
        for _ in range(10):
            scroll_distance = random.randint(550, 650)
            logger.info(f"向下滚动 {scroll_distance} 像素...")
            try:
                page.mouse.wheel(0, scroll_distance)
            except Exception:
                page.evaluate(f"window.scrollBy(0, {scroll_distance})")
            wait_page_seconds(page, 2.8, 4.2, "滚动后页面沉淀")
            logger.info(f"已加载页面: {getattr(page, 'url', '')}")

            if random.random() < 0.03:
                logger.success("随机退出浏览")
                stopped_early = True
                break

            try:
                scroll_y = int(page.evaluate("window.scrollY"))
                at_bottom = bool(
                    page.evaluate(
                        "window.scrollY + window.innerHeight >= document.body.scrollHeight"
                    )
                )
            except Exception:
                scroll_y = previous_scroll_y
                at_bottom = False

            if at_bottom and scroll_y == previous_scroll_y:
                logger.success("已到达页面底部，退出浏览")
                stopped_early = True
                break

            previous_scroll_y = scroll_y
            wait_seconds(4, 7, "浏览主题随机停留")

        if not stopped_early:
            logger.info("达到单帖浏览步数上限，结束当前帖子")

    def click_like(self, page: Any) -> None:
        candidate_buttons: List[Tuple[Any, str, str]] = []
        seen_post_ids: set[str] = set()
        for selector in LIKE_BUTTON_SELECTORS:
            try:
                locator = page.locator(selector)
                if locator.count() <= 0:
                    continue

                # 页面结构已从“按钮本身带 discourse-reactions-reaction-button 类”
                # 漂移为“外层 div + 内层真实 button”，这里显式挑可见的真实按钮。
                for index in range(locator.count()):
                    candidate = locator.nth(index)
                    if not candidate.is_visible():
                        continue
                    post_id = extract_like_button_post_id(candidate)
                    dedupe_key = post_id or f"{selector}::{index}"
                    if dedupe_key in seen_post_ids:
                        continue
                    seen_post_ids.add(dedupe_key)
                    candidate_buttons.append((candidate, selector, post_id))
            except Exception as exc:
                logger.warning(f"尝试点赞失败({selector}): {str(exc)}")

        if not candidate_buttons:
            logger.info("帖子可能已经点过赞了，或当前页面没有可点击的点赞按钮")
            return

        for selected_button, selected_selector, selected_post_id in candidate_buttons:
            try:
                expected_toggle_fragment = build_like_toggle_fragment(selected_post_id)
                try:
                    # 顶部 sticky header 会遮住靠近视口顶部的点赞区，先把目标滚到视口中部，
                    # 减少被 d-header-wrap 抢到点击的问题。
                    selected_button.evaluate(
                        "(el) => el.scrollIntoView({block: 'center', inline: 'center'})"
                    )
                except Exception:
                    pass
                try:
                    page.wait_for_timeout(150)
                except Exception:
                    time.sleep(0.15)

                # 继续走页面点击，但以接口返回 200 作为业务成功口径，
                # 避免把“按钮点击没报错”误记成真正点赞成功。
                with page.expect_response(
                    lambda response: (
                        is_like_toggle_url(getattr(response, "url", ""))
                        and (
                            not expected_toggle_fragment
                            or expected_toggle_fragment in getattr(response, "url", "")
                        )
                    ),
                    timeout=8_000,
                ) as response_info:
                    try:
                        selected_button.click(timeout=3_000)
                    except Exception as exc:
                        if not is_pointer_intercept_error(exc):
                            raise
                        logger.info(
                            "原生点赞点击被页面遮挡，降级为 DOM click: "
                            f"selector={selected_selector}, post_id={selected_post_id or '<unknown>'}"
                        )
                        selected_button.evaluate("(el) => el.click()")

                response = response_info.value
                status_code = getattr(response, "status", None)
                response_text = read_response_text(response)
                if status_code == 200:
                    logger.info(f"点赞成功 post_id={selected_post_id or '<unknown>'}")
                    time.sleep(random.uniform(1, 2))
                    return

                preview = response_text[:160] if response_text else ""
                logger.warning(
                    "点赞请求已发出，但接口返回异常状态"
                    f"({status_code})，selector={selected_selector}, "
                    f"post_id={selected_post_id or '<unknown>'}, "
                    f"response_url={getattr(response, 'url', '')}, "
                    f"response_preview={preview or '<empty>'}"
                )
                if status_code == 403:
                    logger.info("当前候选帖子不可点赞，继续尝试下一个可见点赞按钮")
                    continue
            except Exception as exc:
                logger.warning(
                    f"尝试点赞失败({selected_selector}, post_id={selected_post_id or '<unknown>'}): {str(exc)}"
                )

        logger.info("当前页面所有可见点赞按钮都未成功点赞")

    def print_connect_info(self) -> None:
        logger.info("获取连接信息")
        rows: List[List[str]] = []
        snapshot: Dict[str, Any] = {}

        def action(page: Any) -> None:
            snapshot["url"] = getattr(page, "url", "") or ""
            snapshot["title"] = safe_title(page)
            snapshot["body_text"] = safe_body_text(page)
            try:
                row_locator = page.locator("table tr")
                row_count = min(int(row_locator.count()), 200)
            except Exception:
                row_count = 0

            for index in range(row_count):
                try:
                    row = row_locator.nth(index)
                    cells = row.locator("td")
                    if int(cells.count()) < 3:
                        continue
                    project = normalize_text(cells.nth(0).inner_text())
                    current = normalize_text(cells.nth(1).inner_text()) or "0"
                    requirement = normalize_text(cells.nth(2).inner_text()) or "0"
                    rows.append([project, current, requirement])
                except Exception:
                    continue

        try:
            self.browser.fetch(
                CONNECT_URL,
                page_action=action,
                wait_selector="body",
                timeout=browser_timeout_ms(),
                google_search=False,
                load_dom=True,
            )
        except Exception as exc:
            logger.error(f"打开 Connect 页面失败: {str(exc)}")
            return

        marker = extract_target_phrase(snapshot.get("body_text", "") or "")
        if marker:
            logger.success(f"Connect 页面命中目标文案: {marker}")
        else:
            logger.warning(
                "Connect 页面未直接命中特征文案，"
                f"url={snapshot.get('url', '<unknown>')}, "
                f"title={snapshot.get('title', '<unknown>')}, "
                f"preview={(snapshot.get('body_text', '') or '')[:300] or '<empty>'}"
            )

        logger.info("--------------Connect Info-----------------")
        if rows:
            logger.info(
                "\n" + tabulate(rows, headers=["项目", "当前", "要求"], tablefmt="pretty")
            )
        else:
            logger.warning("Connect 页面未解析出数据表")

    def send_success_notifications(self, browse_enabled: bool) -> None:
        status_msg = "✅每日登录成功"
        if browse_enabled:
            status_msg += " + 浏览任务完成"
        self.notifier.send_all("LINUX DO", status_msg)

    def send_failure_notification(self, reason: str) -> None:
        reason = normalize_text(reason) or "未知失败"
        self.notifier.send_telegram("LINUX DO", f"❌执行失败: {reason}")

    def run(self) -> None:
        failure_reason = ""
        self.last_failure_reason = ""
        try:
            if not COOKIES:
                failure_reason = "未配置 LINUXDO_COOKIES，无法执行 Cookie 登录"
                logger.error(failure_reason)
                return

            login_res = self.login_with_cookies(COOKIES)
            if not login_res:
                failure_reason = self.last_failure_reason or "Cookie 登录验证失败"
                logger.error("登录验证失败，程序终止")
                return

            login_start_ts = time.time()
            deadline_ts = login_start_ts + MIN_ONLINE_SECONDS
            logger.info(f"登录后目标在线时长: 至少 {MIN_ONLINE_SECONDS} 秒")

            if BROWSE_ENABLED:
                click_topic_res = self.click_topic(deadline_ts)
                if not click_topic_res:
                    failure_reason = self.last_failure_reason or "浏览任务失败"
                    logger.error("点击主题失败，程序终止")
                    return
                logger.info("完成浏览任务")

            online_seconds = time.time() - login_start_ts
            logger.info(f"本次登录在线时长: {online_seconds:.2f} 秒")
            if CONNECT_INFO_ENABLED:
                logger.info("已启用 Connect 调试输出，开始抓取 connect.linux.do 信息")
                self.print_connect_info()
            else:
                logger.info("已跳过 Connect 调试页，继续按主站主线收尾")
            self.send_success_notifications(BROWSE_ENABLED)
        except Exception as exc:
            failure_reason = f"运行异常: {str(exc)}"
            logger.exception(failure_reason)
        finally:
            if failure_reason:
                self.send_failure_notification(failure_reason)
            try:
                if self.page is not None:
                    self.page.close()
            except Exception:
                pass
            if self.managed_browser is not None:
                try:
                    self.managed_browser.__exit__(None, None, None)
                except Exception as exc:
                    logger.warning(f"关闭 Scrapling 会话失败: {str(exc)}")


def validate_runtime_config() -> Tuple[bool, str]:
    if COOKIES:
        return True, ""
    return False, "请设置 LINUXDO_COOKIES（Cookie 登录）"


def send_startup_failure_notification(reason: str) -> None:
    reason = normalize_text(reason) or "未知失败"
    NotificationManager().send_telegram("LINUX DO", f"❌执行失败: {reason}")


if __name__ == "__main__":
    config_ok, config_message = validate_runtime_config()
    if not config_ok:
        print(config_message)
        send_startup_failure_notification("未设置 LINUXDO_COOKIES，程序终止")
        raise SystemExit(1)

    try:
        browser = LinuxDoBrowser()
    except Exception as exc:
        logger.exception(f"启动失败: {str(exc)}")
        send_startup_failure_notification(f"启动失败: {str(exc)}")
        raise

    browser.run()
