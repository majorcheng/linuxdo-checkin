"""
cron: 0 */6 * * *
new Env("Linux.Do 签到")
"""

import functools
import os
import random
import re
import time
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


USERNAME = os.environ.get("LINUXDO_USERNAME") or os.environ.get("USERNAME")
PASSWORD = os.environ.get("LINUXDO_PASSWORD") or os.environ.get("PASSWORD")
COOKIES = os.environ.get("LINUXDO_COOKIES", "").strip()
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
LOGIN_URL = "https://linux.do/login"
SESSION_URL = "https://linux.do/session"
CSRF_URL = "https://linux.do/session/csrf"
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
)
CLOUDFLARE_KEYWORDS = (
    "Performing security verification",
    "Verifying you are human",
    "Just a moment...",
    "/cdn-cgi/challenge-platform/",
    "Enable JavaScript and cookies to continue",
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


def is_cloudflare_snapshot(snapshot: Dict[str, Any]) -> bool:
    title = snapshot.get("title", "") or ""
    body_text = snapshot.get("body_text", "") or ""
    if any(keyword in title for keyword in CLOUDFLARE_TITLES):
        return True
    return any(keyword in body_text for keyword in CLOUDFLARE_KEYWORDS)


def count_auth_controls(page: Any) -> Dict[str, int]:
    return {
        "current_user_count": safe_count(page, "#current-user"),
        "avatar_count": safe_count(page, "#current-user img, .header-dropdown-toggle.current-user img"),
        "login_button_count": safe_count(
            page,
            "button:has-text('登录'), button:has-text('Log In'), button:has-text('Sign In')",
        ),
        "login_link_count": safe_count(
            page,
            "a[href*='/login'], a:has-text('登录'), a:has-text('Log In'), a:has-text('Sign In')",
        ),
        "register_link_count": safe_count(
            page,
            "a[href*='/signup'], a[href*='/sign-up'], a:has-text('注册'), a:has-text('Sign Up')",
        ),
    }


def classify_login_snapshot(snapshot: Dict[str, Any]) -> Tuple[str, Optional[str]]:
    current_url = snapshot.get("url", "") or ""
    body_text = snapshot.get("body_text", "") or ""
    current_user_count = int(snapshot.get("current_user_count", 0) or 0)
    avatar_count = int(snapshot.get("avatar_count", 0) or 0)
    login_button_count = int(snapshot.get("login_button_count", 0) or 0)
    login_link_count = int(snapshot.get("login_link_count", 0) or 0)
    register_link_count = int(snapshot.get("register_link_count", 0) or 0)

    if is_cloudflare_snapshot(snapshot):
        return "cf_challenge", "登录检测阶段遭遇 Cloudflare/风控页"

    if "/login" in current_url or "/session/sso_provider" in current_url:
        return "login_page", "跳转到了登录页或 SSO 页面，Cookie 可能失效"

    if current_user_count > 0 and login_button_count == 0 and login_link_count == 0:
        return "ok", None


    if login_link_count > 0 and register_link_count > 0:
        return "cookie_invalid", "页面出现登录/注册链接，Cookie 可能失效"

    if "登录" in body_text and "注册" in body_text and current_user_count == 0:
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

        self.session = requests.Session()
        if hasattr(self.session, "trust_env"):
            self.session.trust_env = False

        self.request_kwargs = {}
        self.session.headers.update(
            {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36 Edg/142.0.0.0",
                "Accept": "application/json, text/javascript, */*; q=0.01",
                "Accept-Language": "zh-CN,zh;q=0.9",
            }
        )

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
                CONNECT_URL
                if default_target_url == CONNECT_URL or name in CONNECT_HOST_COOKIE_NAMES
                else HOME_URL
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
        for cookie in self.session.cookies:
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

    def _fetch_page_snapshot(
        self,
        target_url: str,
        include_auth_signals: bool = False,
        screenshot_path: Optional[str] = None,
        solve_cloudflare: Optional[bool] = None,
    ) -> Dict[str, Any]:
        snapshot: Dict[str, Any] = {}

        def action(page: Any) -> None:
            snapshot["url"] = getattr(page, "url", "") or ""
            snapshot["title"] = safe_title(page)
            snapshot["body_text"] = safe_body_text(page)
            if include_auth_signals:
                snapshot.update(count_auth_controls(page))
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

    def _log_login_diagnostics(self, source_label: str, snapshot: Dict[str, Any], reason: str) -> None:
        logger.error(f"{source_label} 登录验证失败: {reason}")
        logger.info(f"当前URL: {snapshot.get('url', '<unknown>') or '<unknown>'}")
        logger.info(f"页面标题: {snapshot.get('title', '<unknown>') or '<unknown>'}")
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
            status_code, reason = classify_login_snapshot(snapshot)
            last_reason = reason or ""
            logger.info(
                f"{source_label} 登录态探测[{attempt}/3]: status={status_code}, "
                f"url={snapshot.get('url', '<unknown>')}, "
                f"current_user={snapshot.get('current_user_count', 0)}, "
                f"avatar={snapshot.get('avatar_count', 0)}, "
                f"login_link={snapshot.get('login_link_count', 0)}, "
                f"register_link={snapshot.get('register_link_count', 0)}"
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

        self._log_login_diagnostics(source_label, last_snapshot, last_reason)
        return False

    def login_with_cookies(self, cookie_str: str) -> bool:
        logger.info("检测到手动 Cookie，尝试 Cookie 登录...")
        payload_count = self._seed_browser_cookies(cookie_str, CONNECT_COOKIES)
        if payload_count <= 0:
            logger.error("Cookie 解析失败或为空，无法使用 Cookie 登录")
            return False

        self.session.cookies.clear()
        if CONNECT_COOKIES:
            logger.info(f"已预注入 {payload_count} 个 Cookie 到 Scrapling 浏览器上下文（含 connect 域 Cookie）")
        else:
            logger.info(f"已预注入 {payload_count} 个 Cookie 到 Scrapling 浏览器上下文")
        return self._validate_login_state("Cookie")

    def _login_via_http(self) -> bool:
        logger.info("尝试通过 HTTP 登录接口获取会话...")
        headers = {
            "User-Agent": self.session.headers["User-Agent"],
            "Accept": "application/json, text/javascript, */*; q=0.01",
            "Accept-Language": "zh-CN,zh;q=0.9",
            "X-Requested-With": "XMLHttpRequest",
            "Referer": LOGIN_URL,
        }

        try:
            resp_csrf = self.session.get(
                CSRF_URL,
                headers=headers,
                impersonate="chrome136",
                **self.request_kwargs,
            )
        except Exception as exc:
            logger.error(f"获取 CSRF token 异常: {str(exc)}")
            return False

        if resp_csrf.status_code != 200:
            logger.error(f"获取 CSRF token 失败: {resp_csrf.status_code}")
            return False

        csrf_token = (resp_csrf.json() or {}).get("csrf")
        if not csrf_token:
            logger.error("CSRF 响应缺少 csrf 字段")
            return False

        headers.update(
            {
                "X-CSRF-Token": csrf_token,
                "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                "Origin": "https://linux.do",
            }
        )
        data = {
            "login": USERNAME,
            "password": PASSWORD,
            "second_factor_method": "1",
            "timezone": "Asia/Shanghai",
        }

        try:
            resp_login = self.session.post(
                SESSION_URL,
                data=data,
                headers=headers,
                impersonate="chrome136",
                **self.request_kwargs,
            )
        except Exception as exc:
            logger.error(f"登录请求异常: {str(exc)}")
            return False

        if resp_login.status_code != 200:
            logger.error(f"登录失败，状态码: {resp_login.status_code}")
            logger.error(resp_login.text)
            return False

        response_json = resp_login.json() or {}
        if response_json.get("error"):
            logger.error(f"登录失败: {response_json.get('error')}")
            return False

        payload_count = self._sync_session_cookies_to_browser()
        logger.info(f"HTTP 登录成功，已同步 {payload_count} 个 Cookie 到浏览器上下文")
        return self._validate_login_state("账号密码-HTTP")

    def _browser_login(self) -> bool:
        logger.info("HTTP 登录不可用，尝试 Scrapling 浏览器登录...")
        self.session.cookies.clear()
        self.browser.context.clear_cookies()

        user_selectors = (
            "#login-account-name",
            "input[name='login']",
            "input[type='email']",
            "input[type='text']",
        )
        password_selectors = (
            "#login-account-password",
            "input[name='password']",
            "input[type='password']",
        )
        button_selectors = (
            "#login-button",
            "button[type='submit']",
            "button:has-text('登录')",
            "button:has-text('Log In')",
            "button:has-text('Sign In')",
        )

        action_error = {"message": None}

        def action(page: Any) -> None:
            page.wait_for_timeout(1_000)

            username_locator = None
            for selector in user_selectors:
                locator = page.locator(selector)
                if locator.count() > 0:
                    username_locator = locator.first
                    break

            password_locator = None
            for selector in password_selectors:
                locator = page.locator(selector)
                if locator.count() > 0:
                    password_locator = locator.first
                    break

            login_button = None
            for selector in button_selectors:
                locator = page.locator(selector)
                if locator.count() > 0:
                    login_button = locator.first
                    break

            if username_locator is None or password_locator is None or login_button is None:
                action_error["message"] = "登录页结构变化，未找到账号密码输入框或登录按钮"
                return

            username_locator.fill(USERNAME or "")
            password_locator.fill(PASSWORD or "")
            login_button.click()
            page.wait_for_timeout(5_000)
            try:
                page.wait_for_load_state("domcontentloaded", timeout=10_000)
            except Exception:
                pass
            try:
                page.wait_for_load_state("networkidle", timeout=8_000)
            except Exception:
                pass

        try:
            self.browser.fetch(
                LOGIN_URL,
                page_action=action,
                wait_selector="body",
                timeout=browser_timeout_ms(),
                google_search=False,
                load_dom=True,
            )
        except Exception as exc:
            logger.error(f"浏览器登录流程异常: {str(exc)}")
            return False

        if action_error["message"]:
            logger.error(action_error["message"])
            return False

        return self._validate_login_state("账号密码-浏览器")

    def login(self) -> bool:
        if not USERNAME or not PASSWORD:
            logger.error("未配置账号密码，无法执行账号密码登录")
            return False

        if self._login_via_http():
            return True

        return self._browser_login()

    def _open_home_page(self) -> None:
        if self.page is not None:
            try:
                self.page.close()
            except Exception:
                pass

        self.page = self.browser.context.new_page()
        self.page.set_default_navigation_timeout(browser_timeout_ms())
        self.page.set_default_timeout(browser_timeout_ms())
        self.page.goto(HOME_URL, wait_until="domcontentloaded")
        try:
            self.page.wait_for_load_state("networkidle", timeout=5_000)
        except Exception:
            pass
        self.page.wait_for_timeout(1_000)

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

    def click_topic(self, deadline_ts: float) -> bool:
        self._open_home_page()

        seen_urls = set()
        processed_count = 0
        max_rounds = 500
        empty_retry_count = 0
        max_empty_retries = 20

        while time.time() <= deadline_ts and processed_count < max_rounds:
            topic_urls = self._extract_topic_urls()
            if not topic_urls:
                empty_retry_count += 1
                logger.warning("未找到主题帖，稍后重试")
                if empty_retry_count >= max_empty_retries:
                    logger.error("多次未找到主题帖，结束浏览任务")
                    return processed_count > 0
                time.sleep(random.uniform(2, 4))
                try:
                    self.page.reload(wait_until="domcontentloaded")
                except Exception:
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
            processed_count += 1

            if time.time() > deadline_ts:
                logger.success("登录在线时长已超过10分钟，结束浏览任务")
                break

            try:
                self.page.reload(wait_until="domcontentloaded")
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
            page.wait_for_timeout(1_000)
            if random.random() < 0.3:
                self.click_like(page)
            self.browse_post(page)
        finally:
            try:
                page.close()
            except Exception:
                pass

    def browse_post(self, page: Any) -> None:
        previous_scroll_y = -1
        for _ in range(10):
            scroll_distance = random.randint(550, 650)
            logger.info(f"向下滚动 {scroll_distance} 像素...")
            try:
                page.mouse.wheel(0, scroll_distance)
            except Exception:
                page.evaluate(f"window.scrollBy(0, {scroll_distance})")
            page.wait_for_timeout(random.randint(1800, 2600))
            logger.info(f"已加载页面: {getattr(page, 'url', '')}")

            if random.random() < 0.03:
                logger.success("随机退出浏览")
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
                break

            previous_scroll_y = scroll_y
            wait_time = random.uniform(2, 4)
            logger.info(f"等待 {wait_time:.2f} 秒...")
            time.sleep(wait_time)

    def click_like(self, page: Any) -> None:
        selectors = (
            ".discourse-reactions-reaction-button",
            "button.discourse-reactions-reaction-button",
        )
        for selector in selectors:
            try:
                locator = page.locator(selector)
                if locator.count() <= 0:
                    continue
                locator.first.click(timeout=3_000)
                logger.info("点赞成功")
                time.sleep(random.uniform(1, 2))
                return
            except Exception as exc:
                logger.warning(f"尝试点赞失败({selector}): {str(exc)}")
        logger.info("帖子可能已经点过赞了，或当前页面没有可点击的点赞按钮")

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

    def send_notifications(self, browse_enabled: bool) -> None:
        status_msg = f"✅每日登录成功: {USERNAME or '<cookie-only>'}"
        if browse_enabled:
            status_msg += " + 浏览任务完成"
        self.notifier.send_all("LINUX DO", status_msg)

    def run(self) -> None:
        try:
            if COOKIES:
                login_res = self.login_with_cookies(COOKIES)
                if not login_res:
                    logger.warning("Cookie 登录失败，尝试账号密码登录...")
                    login_res = self.login()
            else:
                login_res = self.login()

            if not login_res:
                logger.error("登录验证失败，程序终止")
                return

            login_start_ts = time.time()
            deadline_ts = login_start_ts + MIN_ONLINE_SECONDS
            logger.info(f"登录后目标在线时长: 至少 {MIN_ONLINE_SECONDS} 秒")

            if BROWSE_ENABLED:
                click_topic_res = self.click_topic(deadline_ts)
                if not click_topic_res:
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
            self.send_notifications(BROWSE_ENABLED)
        finally:
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


if __name__ == "__main__":
    if not COOKIES and (not USERNAME or not PASSWORD):
        print("请设置 LINUXDO_COOKIES（Cookie 登录），或同时设置 USERNAME 和 PASSWORD（账号密码登录）")
        raise SystemExit(1)

    browser = LinuxDoBrowser()
    browser.run()
