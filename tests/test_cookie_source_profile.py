from curl_cffi import requests

from main import (
    CONNECT_URL,
    HOME_URL,
    LinuxDoBrowser,
    parse_curl_command,
    resolve_cookie_source_profile,
)


def test_parse_curl_command_extracts_url_headers_and_cookie():
    profile = parse_curl_command(
        r"""
        curl 'https://linux.do/latest.json?topic_ids=1751382,1749141' \
          -H 'accept-language: zh-CN,zh;q=0.9' \
          -H 'user-agent: Mozilla/5.0 TestBrowser/146.0' \
          -H 'x-csrf-token: csrf-token' \
          -b '_t=token; __stripe_sid=stripe'
        """
    )

    assert profile.url == "https://linux.do/latest.json?topic_ids=1751382,1749141"
    assert profile.cookie_str == "_t=token; __stripe_sid=stripe"
    assert profile.headers["accept-language"] == "zh-CN,zh;q=0.9"
    assert profile.headers["user-agent"] == "Mozilla/5.0 TestBrowser/146.0"
    assert profile.headers["x-csrf-token"] == "csrf-token"


def test_resolve_cookie_source_profile_allows_pasting_curl_into_cookie_field():
    profile, cookies = resolve_cookie_source_profile(
        "curl 'https://linux.do/latest.json' -A 'Mozilla/5.0 Demo/1.0' -b '_t=token'",
        "",
    )

    assert profile.url == "https://linux.do/latest.json"
    assert profile.useragent == "Mozilla/5.0 Demo/1.0"
    assert cookies == "_t=token"


def test_build_cookie_payloads_keeps_linuxdo_cookie_source_on_home_host():
    payloads = LinuxDoBrowser.build_cookie_payloads(
        "__stripe_sid=stripe; __stripe_mid=mid; _t=token",
        HOME_URL,
    )
    payload_by_name = {payload["name"]: payload for payload in payloads}

    assert payload_by_name["__stripe_sid"]["url"] == HOME_URL
    assert payload_by_name["__stripe_mid"]["url"] == HOME_URL
    assert payload_by_name["_t"]["domain"] == ".linux.do"


def test_build_cookie_payloads_keeps_connect_cookie_source_on_connect_host():
    payloads = LinuxDoBrowser.build_cookie_payloads(
        "auth.session-token=token; linux_do_credit_session_id=credit",
        CONNECT_URL,
    )
    payload_by_name = {payload["name"]: payload for payload in payloads}

    assert payload_by_name["auth.session-token"]["url"] == CONNECT_URL
    assert payload_by_name["linux_do_credit_session_id"]["url"] == CONNECT_URL


def test_session_cookies_to_browser_payloads_reads_cookiejar_objects():
    browser = LinuxDoBrowser.__new__(LinuxDoBrowser)
    browser.session = requests.Session()
    browser.session.cookies.set("__stripe_sid", "stripe", domain="linux.do", path="/")
    browser.session.cookies.set(
        "auth.session-token",
        "token",
        domain="connect.linux.do",
        path="/",
        secure=True,
    )

    payloads = browser._session_cookies_to_browser_payloads()
    payload_by_name = {payload["name"]: payload for payload in payloads}

    assert payload_by_name["__stripe_sid"]["domain"] == "linux.do"
    assert payload_by_name["auth.session-token"]["domain"] == "connect.linux.do"
    assert payload_by_name["auth.session-token"]["secure"] is True
