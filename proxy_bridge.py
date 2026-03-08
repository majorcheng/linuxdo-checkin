import base64
import select
import socket
import ssl
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn
from typing import Optional
from urllib.parse import unquote, urlparse


def mask_proxy_url(proxy_url: str) -> str:
    if not proxy_url:
        return "<未配置>"

    try:
        parsed = urlparse(proxy_url)
        if not parsed.scheme or not parsed.hostname:
            return "<无效代理地址>"

        netloc = parsed.hostname
        if parsed.port:
            netloc = f"{netloc}:{parsed.port}"

        if parsed.username or parsed.password:
            return f"{parsed.scheme}://***:***@{netloc}"
        return f"{parsed.scheme}://{netloc}"
    except Exception:
        return "<无效代理地址>"


def _recv_until_header_end(sock: socket.socket, max_bytes: int = 65_536) -> bytes:
    buffer = b""
    while b"\r\n\r\n" not in buffer and len(buffer) < max_bytes:
        chunk = sock.recv(4_096)
        if not chunk:
            break
        buffer += chunk
    return buffer


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


class UpstreamProxyBridgeHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "LinuxDoProxyBridge/1.0"

    def log_message(self, format: str, *args) -> None:
        return

    def do_CONNECT(self) -> None:
        self.server.bridge.handle_connect(self)  # type: ignore[attr-defined]

    def do_GET(self) -> None:
        self.server.bridge.handle_forward_request(self)  # type: ignore[attr-defined]

    def do_POST(self) -> None:
        self.server.bridge.handle_forward_request(self)  # type: ignore[attr-defined]

    def do_HEAD(self) -> None:
        self.server.bridge.handle_forward_request(self)  # type: ignore[attr-defined]

    def do_OPTIONS(self) -> None:
        self.server.bridge.handle_forward_request(self)  # type: ignore[attr-defined]

    def do_PUT(self) -> None:
        self.server.bridge.handle_forward_request(self)  # type: ignore[attr-defined]

    def do_PATCH(self) -> None:
        self.server.bridge.handle_forward_request(self)  # type: ignore[attr-defined]

    def do_DELETE(self) -> None:
        self.server.bridge.handle_forward_request(self)  # type: ignore[attr-defined]


class BrowserProxyRuntime:
    def __init__(self, proxy_url: str, proxy_insecure: bool = False):
        self.proxy_url = proxy_url
        self.proxy_insecure = proxy_insecure
        self.parsed_proxy = self._parse_proxy_url(proxy_url)
        self.server: Optional[ThreadedHTTPServer] = None
        self.server_thread: Optional[threading.Thread] = None
        self.local_proxy_url: Optional[str] = None

    @staticmethod
    def _parse_proxy_url(proxy_url: str):
        parsed = urlparse(proxy_url)
        scheme = (parsed.scheme or "").lower()
        if scheme not in {"http", "https"}:
            raise ValueError("当前仅支持 http:// 或 https:// 代理")
        if not parsed.hostname:
            raise ValueError("代理地址缺少主机名")
        if bool(parsed.username) != bool(parsed.password):
            raise ValueError("代理认证需要同时提供用户名和密码")
        return parsed

    def start(self) -> str:
        if self.parsed_proxy.scheme == "https":
            self._probe_upstream_proxy()

        self.server = ThreadedHTTPServer(("127.0.0.1", 0), UpstreamProxyBridgeHandler)
        self.server.bridge = self  # type: ignore[attr-defined]
        self.server_thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.server_thread.start()
        local_port = int(self.server.server_address[1])
        self.local_proxy_url = f"http://127.0.0.1:{local_port}"
        return self.local_proxy_url

    def stop(self) -> None:
        if self.server is not None:
            try:
                self.server.shutdown()
                self.server.server_close()
            finally:
                self.server = None

        if self.server_thread is not None and self.server_thread.is_alive():
            self.server_thread.join(timeout=2)
        self.server_thread = None
        self.local_proxy_url = None

    def _proxy_authorization_value(self) -> Optional[str]:
        username = self.parsed_proxy.username
        password = self.parsed_proxy.password
        if username is None and password is None:
            return None

        credentials = f"{unquote(username or '')}:{unquote(password or '')}".encode("utf-8")
        token = base64.b64encode(credentials).decode("ascii")
        return f"Basic {token}"

    def _build_connect_request(self, target: str) -> bytes:
        header_lines = [
            f"CONNECT {target} HTTP/1.1\r\n",
            f"Host: {target}\r\n",
            "Proxy-Connection: Keep-Alive\r\n",
        ]
        auth_value = self._proxy_authorization_value()
        if auth_value:
            header_lines.append(f"Proxy-Authorization: {auth_value}\r\n")
        header_lines.append("\r\n")
        return "".join(header_lines).encode("utf-8")

    def open_upstream_socket(self) -> socket.socket:
        host = self.parsed_proxy.hostname
        port = self.parsed_proxy.port or (80 if self.parsed_proxy.scheme == "http" else 443)
        raw_sock = socket.create_connection((host, port), timeout=10)

        if self.parsed_proxy.scheme == "http":
            return raw_sock

        context = ssl.create_default_context()
        if self.proxy_insecure:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            server_hostname = None
        else:
            server_hostname = host

        return context.wrap_socket(raw_sock, server_hostname=server_hostname)

    def _probe_upstream_proxy(self) -> None:
        target = "linux.do:443"
        upstream_sock: Optional[socket.socket] = None
        try:
            upstream_sock = self.open_upstream_socket()
            upstream_sock.sendall(self._build_connect_request(target))
            response_head = _recv_until_header_end(upstream_sock)
            if not response_head:
                raise RuntimeError("上游 HTTPS 代理未返回响应")

            status_line = response_head.split(b"\r\n", 1)[0].decode("iso-8859-1", errors="replace")
            if " 200 " not in f" {status_line} ":
                raise RuntimeError(f"上游 HTTPS 代理 CONNECT 失败: {status_line}")
        finally:
            if upstream_sock is not None:
                try:
                    upstream_sock.close()
                except Exception:
                    pass

    def handle_connect(self, handler: BaseHTTPRequestHandler) -> None:
        upstream_sock: Optional[socket.socket] = None
        try:
            target = handler.path
            upstream_sock = self.open_upstream_socket()
            upstream_sock.sendall(self._build_connect_request(target))
            response_head = _recv_until_header_end(upstream_sock)
            if not response_head:
                raise RuntimeError("上游代理未返回 CONNECT 响应")

            status_line = response_head.split(b"\r\n", 1)[0].decode("iso-8859-1", errors="replace")
            if " 200 " not in f" {status_line} ":
                raise RuntimeError(status_line)

            handler.connection.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            self._relay_bidirectional(handler.connection, upstream_sock)
        except Exception as exc:
            try:
                handler.send_error(502, f"上游代理 CONNECT 失败: {exc}")
            except Exception:
                pass
        finally:
            if upstream_sock is not None:
                try:
                    upstream_sock.close()
                except Exception:
                    pass

    def handle_forward_request(self, handler: BaseHTTPRequestHandler) -> None:
        upstream_sock: Optional[socket.socket] = None
        try:
            content_length = int(handler.headers.get("Content-Length", "0") or "0")
            request_body = handler.rfile.read(content_length) if content_length > 0 else b""

            header_lines: list[str] = []
            for key, value in handler.headers.items():
                if key.lower() in {"proxy-authorization", "proxy-connection", "connection"}:
                    continue
                header_lines.append(f"{key}: {value}\r\n")

            auth_value = self._proxy_authorization_value()
            if auth_value:
                header_lines.append(f"Proxy-Authorization: {auth_value}\r\n")

            header_lines.append("Connection: close\r\n")
            header_lines.append("Proxy-Connection: close\r\n")
            request_bytes = (
                f"{handler.command} {handler.path} {handler.request_version}\r\n".encode("utf-8")
                + "".join(header_lines).encode("utf-8")
                + b"\r\n"
                + request_body
            )

            upstream_sock = self.open_upstream_socket()
            upstream_sock.sendall(request_bytes)
            while True:
                chunk = upstream_sock.recv(65_536)
                if not chunk:
                    break
                handler.wfile.write(chunk)
        except Exception as exc:
            try:
                handler.send_error(502, f"上游代理转发失败: {exc}")
            except Exception:
                pass
        finally:
            if upstream_sock is not None:
                try:
                    upstream_sock.close()
                except Exception:
                    pass

    @staticmethod
    def _relay_bidirectional(client_sock: socket.socket, upstream_sock: socket.socket) -> None:
        sockets = [client_sock, upstream_sock]
        for sock in sockets:
            try:
                sock.settimeout(None)
            except Exception:
                pass

        while True:
            readable, _, errored = select.select(sockets, [], sockets, 60)
            if errored or not readable:
                break

            for source_sock in readable:
                try:
                    payload = source_sock.recv(65_536)
                except OSError:
                    return

                if not payload:
                    return

                target_sock = upstream_sock if source_sock is client_sock else client_sock
                target_sock.sendall(payload)
