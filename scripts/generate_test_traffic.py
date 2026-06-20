#!/usr/bin/env python3

import sys
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlparse
from urllib.request import Request, urlopen


DEFAULT_BASE_URL = "http://127.0.0.1:5000"
ALLOWED_HOSTS = {"127.0.0.1", "localhost"}


def validate_local_url(base_url: str):
    parsed_url = urlparse(base_url)

    if parsed_url.hostname not in ALLOWED_HOSTS:
        raise ValueError(
            "이 스크립트는 로컬 테스트 환경에서만 실행할 수 있습니다. "
            "base_url은 localhost 또는 127.0.0.1이어야 합니다."
        )

    if parsed_url.scheme not in {"http", "https"}:
        raise ValueError("base_url은 http 또는 https로 시작해야 합니다.")


def request_url(method: str, url: str, data: dict | None = None, user_agent: str = "Mozilla/5.0"):
    encoded_data = None
    headers = {
        "User-Agent": user_agent,
    }

    if data is not None:
        encoded_data = urlencode(data).encode("utf-8")
        headers["Content-Type"] = "application/x-www-form-urlencoded"

    request = Request(
        url=url,
        data=encoded_data,
        headers=headers,
        method=method,
    )

    try:
        with urlopen(request, timeout=5) as response:
            status_code = response.status
            print(f"[{method}] {url} -> {status_code}")

    except HTTPError as error:
        print(f"[{method}] {url} -> {error.code}")

    except URLError as error:
        print(f"[ERROR] 요청 실패: {url}")
        print(f"        원인: {error.reason}")


def send_get(base_url: str, path: str, user_agent: str = "Mozilla/5.0"):
    url = f"{base_url.rstrip('/')}{path}"
    request_url("GET", url, user_agent=user_agent)


def send_post(base_url: str, path: str, data: dict, user_agent: str = "Mozilla/5.0"):
    url = f"{base_url.rstrip('/')}{path}"
    request_url("POST", url, data=data, user_agent=user_agent)


def generate_test_traffic(base_url: str):
    validate_local_url(base_url)

    print("=== 정상 요청 생성 ===")
    send_get(base_url, "/")
    send_get(base_url, "/login")

    time.sleep(0.2)

    print("\n=== SQL Injection 의심 요청 생성 ===")
    send_get(base_url, "/login?id=1%27%20OR%20%271%27%3D%271")
    send_get(base_url, "/products?id=1%20UNION%20SELECT%20username,password%20FROM%20users")
    send_get(base_url, "/search?q=admin%27--")

    time.sleep(0.2)

    print("\n=== XSS 의심 요청 생성 ===")
    send_get(base_url, "/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E")
    send_get(base_url, "/comment?message=%3Cimg%20src=x%20onerror=alert(1)%3E")

    time.sleep(0.2)

    print("\n=== Path Traversal 의심 요청 생성 ===")
    send_get(base_url, "/download?file=..%2F..%2Fetc%2Fpasswd")
    send_get(base_url, "/image?path=..%2F..%2F..%2Fetc%2Fshadow")

    time.sleep(0.2)

    print("\n=== 관리자 페이지 접근 시도 요청 생성 ===")
    send_get(base_url, "/admin")
    send_get(base_url, "/wp-admin")
    send_get(base_url, "/phpmyadmin")

    time.sleep(0.2)

    print("\n=== 스캐너 User-Agent 요청 생성 ===")
    send_get(base_url, "/test?id=1", user_agent="sqlmap/1.6")
    send_get(base_url, "/server-status", user_agent="Nikto/2.1.6")
    send_get(base_url, "/hidden", user_agent="curl/8.0.1")

    time.sleep(0.2)

    print("\n=== 반복 404 요청 생성 ===")
    for index in range(1, 7):
        send_get(base_url, f"/not-found-{index}")

    time.sleep(0.2)

    print("\n=== 로그인 실패 반복 요청 생성 ===")
    for _ in range(5):
        send_post(
            base_url,
            "/login",
            data={"id": "admin", "password": "wrong-password"},
        )

    time.sleep(0.2)

    print("\n=== 반복 실패 후 성공 로그인 요청 생성 ===")
    send_post(
        base_url,
        "/login",
        data={"id": "admin", "password": "password123"},
    )

    print("\n테스트 트래픽 생성 완료")


def main():
    base_url = sys.argv[1] if len(sys.argv) >= 2 else DEFAULT_BASE_URL
    generate_test_traffic(base_url)


if __name__ == "__main__":
    main()