#!/usr/bin/env python3

import re
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path
from urllib.parse import unquote_plus


DEFAULT_ACCESS_LOG = Path("app/logs/access.log")
DEFAULT_LOGIN_LOG = Path("app/logs/login.log")
DEFAULT_THRESHOLD = 5
RESULT_DIR = Path("result")


ACCESS_LOG_PATTERN = re.compile(
    r'^(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) '
    r'HTTP_REQUEST '
    r'ip=(?P<ip>\S+) '
    r'method=(?P<method>\S+) '
    r'path="(?P<path>.*?)" '
    r'query="(?P<query>.*?)" '
    r'status=(?P<status>\d{3}) '
    r'user_agent="(?P<user_agent>.*?)"$'
)

LOGIN_LOG_PATTERN = re.compile(
    r'^(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) '
    r'(?P<event>LOGIN_SUCCESS|LOGIN_FAIL) '
    r'ip=(?P<ip>\S+) '
    r'id=(?P<user_id>\S*) '
    r'user_agent="(?P<user_agent>.*?)"$'
)


SQLI_PATTERNS = [
    "' or",
    '" or',
    " or 1=1",
    "union select",
    "--",
    "#",
    "sleep(",
    "benchmark(",
    "information_schema",
    "select ",
    "drop table",
]

XSS_PATTERNS = [
    "<script",
    "</script>",
    "alert(",
    "onerror=",
    "onload=",
    "javascript:",
    "<img",
    "<svg",
]

PATH_TRAVERSAL_PATTERNS = [
    "../",
    "..\\",
    "/etc/passwd",
    "/etc/shadow",
    "boot.ini",
    "win.ini",
    "/proc/self/environ",
]

ADMIN_PATH_PATTERNS = [
    "/admin",
    "/administrator",
    "/wp-admin",
    "/manager",
    "/phpmyadmin",
    "/login/admin",
]

SCANNER_USER_AGENTS = [
    "sqlmap",
    "nikto",
    "nmap",
    "dirbuster",
    "gobuster",
    "wpscan",
    "curl",
    "wget",
    "python-requests",
]


def parse_access_log_line(line: str):
    match = ACCESS_LOG_PATTERN.search(line.strip())

    if not match:
        return None

    return {
        "timestamp": match.group("timestamp"),
        "ip": match.group("ip"),
        "method": match.group("method"),
        "path": match.group("path"),
        "query": match.group("query"),
        "status": int(match.group("status")),
        "user_agent": match.group("user_agent"),
    }


def parse_login_log_line(line: str):
    match = LOGIN_LOG_PATTERN.search(line.strip())

    if not match:
        return None

    return {
        "timestamp": match.group("timestamp"),
        "event": match.group("event"),
        "ip": match.group("ip"),
        "user_id": match.group("user_id"),
        "user_agent": match.group("user_agent"),
    }


def normalize_request_text(path: str, query: str) -> str:
    raw_text = f"{path}?{query}" if query else path
    decoded_text = unquote_plus(raw_text)

    return decoded_text.lower()


def contains_any_pattern(text: str, patterns: list[str]) -> bool:
    return any(pattern in text for pattern in patterns)


def add_finding(
    findings: list,
    risk: str,
    attack_type: str,
    timestamp: str,
    ip: str,
    method: str,
    path: str,
    query: str,
    status: str,
    user_agent: str,
    reason: str,
    response: str,
):
    findings.append(
        {
            "risk": risk,
            "attack_type": attack_type,
            "timestamp": timestamp,
            "ip": ip,
            "method": method,
            "path": path,
            "query": query,
            "status": status,
            "user_agent": user_agent,
            "reason": reason,
            "response": response,
        }
    )


def analyze_access_log(access_log: Path, threshold: int):
    findings = []
    total_requests = 0

    status_404_by_ip = Counter()
    request_count_by_ip = Counter()

    if not access_log.exists():
        return {
            "total_requests": 0,
            "findings": findings,
            "status_404_by_ip": status_404_by_ip,
            "request_count_by_ip": request_count_by_ip,
            "access_log_exists": False,
        }

    with access_log.open("r", encoding="utf-8") as file:
        for line in file:
            log = parse_access_log_line(line)

            if not log:
                continue

            total_requests += 1

            ip = log["ip"]
            method = log["method"]
            path = log["path"]
            query = log["query"]
            status = log["status"]
            user_agent = log["user_agent"]

            request_count_by_ip[ip] += 1

            if status == 404:
                status_404_by_ip[ip] += 1

            request_text = normalize_request_text(path, query)
            user_agent_lower = user_agent.lower()

            if contains_any_pattern(request_text, SQLI_PATTERNS):
                add_finding(
                    findings=findings,
                    risk="HIGH",
                    attack_type="SQL Injection",
                    timestamp=log["timestamp"],
                    ip=ip,
                    method=method,
                    path=path,
                    query=query,
                    status=str(status),
                    user_agent=user_agent,
                    reason="요청 경로 또는 쿼리 문자열에서 SQL Injection 의심 패턴 발견",
                    response="입력값 검증, Prepared Statement 사용 여부, WAF 룰을 점검합니다.",
                )

            if contains_any_pattern(request_text, XSS_PATTERNS):
                add_finding(
                    findings=findings,
                    risk="HIGH",
                    attack_type="XSS",
                    timestamp=log["timestamp"],
                    ip=ip,
                    method=method,
                    path=path,
                    query=query,
                    status=str(status),
                    user_agent=user_agent,
                    reason="요청 경로 또는 쿼리 문자열에서 XSS 의심 패턴 발견",
                    response="출력 인코딩, 입력값 필터링, CSP 적용 여부를 점검합니다.",
                )

            if contains_any_pattern(request_text, PATH_TRAVERSAL_PATTERNS):
                add_finding(
                    findings=findings,
                    risk="HIGH",
                    attack_type="Path Traversal",
                    timestamp=log["timestamp"],
                    ip=ip,
                    method=method,
                    path=path,
                    query=query,
                    status=str(status),
                    user_agent=user_agent,
                    reason="파일 경로 조작 또는 민감 파일 접근 시도 패턴 발견",
                    response="파일 경로 입력값 검증, 상위 디렉터리 접근 차단 여부를 확인합니다.",
                )

            if contains_any_pattern(request_text, ADMIN_PATH_PATTERNS):
                add_finding(
                    findings=findings,
                    risk="MEDIUM",
                    attack_type="Admin Page Access",
                    timestamp=log["timestamp"],
                    ip=ip,
                    method=method,
                    path=path,
                    query=query,
                    status=str(status),
                    user_agent=user_agent,
                    reason="관리자 페이지 또는 관리 도구 접근 시도 탐지",
                    response="관리자 페이지 접근 IP 제한, 인증 정책, 접근 로그를 확인합니다.",
                )

            if contains_any_pattern(user_agent_lower, SCANNER_USER_AGENTS):
                add_finding(
                    findings=findings,
                    risk="MEDIUM",
                    attack_type="Suspicious User-Agent",
                    timestamp=log["timestamp"],
                    ip=ip,
                    method=method,
                    path=path,
                    query=query,
                    status=str(status),
                    user_agent=user_agent,
                    reason="스캐너 또는 자동화 도구로 의심되는 User-Agent 탐지",
                    response="해당 IP의 요청 패턴을 추가 확인하고 필요 시 차단을 검토합니다.",
                )

    for ip, count in status_404_by_ip.items():
        if count >= threshold:
            add_finding(
                findings=findings,
                risk="MEDIUM",
                attack_type="Repeated 404",
                timestamp="-",
                ip=ip,
                method="-",
                path="-",
                query="-",
                status="404",
                user_agent="-",
                reason=f"동일 IP에서 404 응답이 {count}회 발생",
                response="존재하지 않는 경로를 반복 탐색하는 스캔 행위 가능성을 확인합니다.",
            )

    return {
        "total_requests": total_requests,
        "findings": findings,
        "status_404_by_ip": status_404_by_ip,
        "request_count_by_ip": request_count_by_ip,
        "access_log_exists": True,
    }


def analyze_login_log(login_log: Path, threshold: int):
    findings = []
    total_login_events = 0

    login_fail_by_ip = Counter()
    login_success_by_ip = Counter()

    if not login_log.exists():
        return {
            "total_login_events": 0,
            "findings": findings,
            "login_fail_by_ip": login_fail_by_ip,
            "login_success_by_ip": login_success_by_ip,
            "login_log_exists": False,
        }

    with login_log.open("r", encoding="utf-8") as file:
        for line in file:
            log = parse_login_log_line(line)

            if not log:
                continue

            total_login_events += 1

            ip = log["ip"]

            if log["event"] == "LOGIN_FAIL":
                login_fail_by_ip[ip] += 1

            if log["event"] == "LOGIN_SUCCESS":
                login_success_by_ip[ip] += 1

    for ip, count in login_fail_by_ip.items():
        if count >= threshold:
            risk = "HIGH" if count >= threshold * 2 else "MEDIUM"

            add_finding(
                findings=findings,
                risk=risk,
                attack_type="Repeated Login Failure",
                timestamp="-",
                ip=ip,
                method="POST",
                path="/login",
                query="-",
                status="-",
                user_agent="-",
                reason=f"동일 IP에서 로그인 실패가 {count}회 발생",
                response="계정 대입 공격 가능성을 확인하고, IP 차단 또는 로그인 제한 정책을 검토합니다.",
            )

    for ip, success_count in login_success_by_ip.items():
        fail_count = login_fail_by_ip[ip]

        if fail_count >= threshold and success_count > 0:
            add_finding(
                findings=findings,
                risk="HIGH",
                attack_type="Successful Login After Failures",
                timestamp="-",
                ip=ip,
                method="POST",
                path="/login",
                query="-",
                status="-",
                user_agent="-",
                reason=f"동일 IP에서 로그인 실패 {fail_count}회 후 성공 로그인 {success_count}회 발생",
                response="계정 탈취 가능성을 고려하여 로그인 이력과 계정 상태를 확인합니다.",
            )

    return {
        "total_login_events": total_login_events,
        "findings": findings,
        "login_fail_by_ip": login_fail_by_ip,
        "login_success_by_ip": login_success_by_ip,
        "login_log_exists": True,
    }


def get_risk_counts(findings: list):
    risk_counter = Counter(item["risk"] for item in findings)

    return {
        "HIGH": risk_counter.get("HIGH", 0),
        "MEDIUM": risk_counter.get("MEDIUM", 0),
        "LOW": risk_counter.get("LOW", 0),
    }


def sanitize_markdown(value) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def write_txt_report(
    result_file: Path,
    access_log: Path,
    login_log: Path,
    threshold: int,
    access_analysis: dict,
    login_analysis: dict,
):
    findings = access_analysis["findings"] + login_analysis["findings"]
    risk_counts = get_risk_counts(findings)
    suspicious_ips = sorted({item["ip"] for item in findings if item["ip"] != "-"})

    with result_file.open("w", encoding="utf-8") as report:
        report.write("==================================================\n")
        report.write(" Web Attack Log Analysis Report\n")
        report.write("==================================================\n\n")

        report.write("[분석 정보]\n")
        report.write(f"분석 시간        : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        report.write(f"Access 로그 파일 : {access_log}\n")
        report.write(f"Login 로그 파일  : {login_log}\n")
        report.write(f"반복 탐지 기준   : 동일 IP에서 {threshold}회 이상\n\n")

        report.write("--------------------------------------------------\n")
        report.write("[요약]\n")
        report.write(f"전체 HTTP 요청 수        : {access_analysis['total_requests']}\n")
        report.write(f"전체 로그인 이벤트 수     : {login_analysis['total_login_events']}\n")
        report.write(f"전체 탐지 이벤트 수       : {len(findings)}\n")
        report.write(f"의심 IP 수               : {len(suspicious_ips)}\n")
        report.write(f"HIGH 위험도              : {risk_counts['HIGH']}\n")
        report.write(f"MEDIUM 위험도            : {risk_counts['MEDIUM']}\n\n")

        if not access_analysis["access_log_exists"]:
            report.write("[알림] Access 로그 파일이 존재하지 않습니다.\n\n")

        if not login_analysis["login_log_exists"]:
            report.write("[알림] Login 로그 파일이 존재하지 않습니다.\n\n")

        report.write("--------------------------------------------------\n")
        report.write("[탐지 결과]\n")

        if findings:
            for item in findings:
                report.write("\n")
                report.write(f"[{item['risk']}] {item['attack_type']}\n")
                report.write(f"시간          : {item['timestamp']}\n")
                report.write(f"IP 주소       : {item['ip']}\n")
                report.write(f"Method        : {item['method']}\n")
                report.write(f"Path          : {item['path']}\n")
                report.write(f"Query         : {item['query']}\n")
                report.write(f"Status        : {item['status']}\n")
                report.write(f"User-Agent    : {item['user_agent']}\n")
                report.write(f"탐지 사유     : {item['reason']}\n")
                report.write(f"권장 대응     : {item['response']}\n")
        else:
            report.write("\n[정상] 탐지된 웹 공격 의심 이벤트가 없습니다.\n")

        report.write("\n--------------------------------------------------\n")
        report.write("[최종 결과]\n")
        report.write(f"결과 파일 : {result_file}\n")
        report.write("==================================================\n")


def write_markdown_report(
    markdown_file: Path,
    access_log: Path,
    login_log: Path,
    threshold: int,
    access_analysis: dict,
    login_analysis: dict,
):
    findings = access_analysis["findings"] + login_analysis["findings"]
    risk_counts = get_risk_counts(findings)
    suspicious_ips = sorted({item["ip"] for item in findings if item["ip"] != "-"})

    with markdown_file.open("w", encoding="utf-8") as report:
        report.write("# Web Attack Log Analysis Report\n\n")

        report.write("## 1. Analysis Information\n\n")
        report.write("| 항목 | 값 |\n")
        report.write("|---|---|\n")
        report.write(f"| 분석 시간 | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} |\n")
        report.write(f"| Access 로그 파일 | {access_log} |\n")
        report.write(f"| Login 로그 파일 | {login_log} |\n")
        report.write(f"| 반복 탐지 기준 | 동일 IP에서 {threshold}회 이상 |\n\n")

        report.write("## 2. Summary\n\n")
        report.write("| 항목 | 값 |\n")
        report.write("|---|---:|\n")
        report.write(f"| 전체 HTTP 요청 수 | {access_analysis['total_requests']} |\n")
        report.write(f"| 전체 로그인 이벤트 수 | {login_analysis['total_login_events']} |\n")
        report.write(f"| 전체 탐지 이벤트 수 | {len(findings)} |\n")
        report.write(f"| 의심 IP 수 | {len(suspicious_ips)} |\n")
        report.write(f"| HIGH 위험도 | {risk_counts['HIGH']} |\n")
        report.write(f"| MEDIUM 위험도 | {risk_counts['MEDIUM']} |\n\n")

        report.write("## 3. Detection Results\n\n")
        report.write(
            "| Risk | Attack Type | Time | IP | Method | Path | Query | Status | User-Agent | Reason | Recommended Response |\n"
        )
        report.write("|---|---|---|---|---|---|---|---:|---|---|---|\n")

        if findings:
            for item in findings:
                report.write(
                    f"| {sanitize_markdown(item['risk'])} "
                    f"| {sanitize_markdown(item['attack_type'])} "
                    f"| {sanitize_markdown(item['timestamp'])} "
                    f"| {sanitize_markdown(item['ip'])} "
                    f"| {sanitize_markdown(item['method'])} "
                    f"| {sanitize_markdown(item['path'])} "
                    f"| {sanitize_markdown(item['query'])} "
                    f"| {sanitize_markdown(item['status'])} "
                    f"| {sanitize_markdown(item['user_agent'])} "
                    f"| {sanitize_markdown(item['reason'])} "
                    f"| {sanitize_markdown(item['response'])} |\n"
                )
        else:
            report.write("| INFO | 정상 | - | - | - | - | - | - | - | 탐지된 웹 공격 의심 이벤트 없음 | 추가 조치 불필요 |\n")

        report.write("\n## 4. Detection Rule Summary\n\n")
        report.write("| Rule | Risk | Description |\n")
        report.write("|---|---|---|\n")
        report.write("| SQL Injection | HIGH | SQL Injection 의심 문자열 탐지 |\n")
        report.write("| XSS | HIGH | Script 삽입 또는 이벤트 핸들러 기반 XSS 패턴 탐지 |\n")
        report.write("| Path Traversal | HIGH | ../, /etc/passwd 등 경로 조작 시도 탐지 |\n")
        report.write("| Admin Page Access | MEDIUM | 관리자 페이지 접근 시도 탐지 |\n")
        report.write("| Suspicious User-Agent | MEDIUM | sqlmap, nikto, curl 등 자동화 도구 User-Agent 탐지 |\n")
        report.write("| Repeated 404 | MEDIUM | 동일 IP에서 404 응답 반복 발생 탐지 |\n")
        report.write("| Repeated Login Failure | MEDIUM/HIGH | 동일 IP에서 로그인 실패 반복 발생 탐지 |\n")
        report.write("| Successful Login After Failures | HIGH | 반복 실패 후 성공 로그인 탐지 |\n\n")

        report.write("## 5. Recommended Response Guide\n\n")
        report.write("- SQL Injection 탐지 시 입력값 검증과 DB 쿼리 처리 방식을 확인합니다.\n")
        report.write("- XSS 탐지 시 출력 인코딩, 입력값 필터링, CSP 적용 여부를 확인합니다.\n")
        report.write("- Path Traversal 탐지 시 파일 경로 입력값 검증과 접근 제한을 확인합니다.\n")
        report.write("- 로그인 실패 반복 탐지 시 계정 대입 공격 가능성을 확인합니다.\n")
        report.write("- 스캐너 User-Agent 또는 반복 404 탐지 시 자동화된 스캔 여부를 확인합니다.\n")


def main():
    access_log = Path(sys.argv[1]) if len(sys.argv) >= 2 else DEFAULT_ACCESS_LOG
    login_log = Path(sys.argv[2]) if len(sys.argv) >= 3 else DEFAULT_LOGIN_LOG

    try:
        threshold = int(sys.argv[3]) if len(sys.argv) >= 4 else DEFAULT_THRESHOLD
    except ValueError:
        print("Error: threshold는 숫자로 입력해야 합니다.")
        sys.exit(1)

    if not access_log.exists() and not login_log.exists():
        print(f"Error: 분석할 로그 파일이 없습니다.")
        print(f"- Access log: {access_log}")
        print(f"- Login log : {login_log}")
        sys.exit(1)

    RESULT_DIR.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    result_file = RESULT_DIR / f"web_attack_detection_result_{timestamp}.txt"
    markdown_file = RESULT_DIR / f"web_attack_detection_report_{timestamp}.md"

    access_analysis = analyze_access_log(access_log, threshold)
    login_analysis = analyze_login_log(login_log, threshold)

    write_txt_report(
        result_file=result_file,
        access_log=access_log,
        login_log=login_log,
        threshold=threshold,
        access_analysis=access_analysis,
        login_analysis=login_analysis,
    )

    write_markdown_report(
        markdown_file=markdown_file,
        access_log=access_log,
        login_log=login_log,
        threshold=threshold,
        access_analysis=access_analysis,
        login_analysis=login_analysis,
    )

    print(f"분석 완료. TXT 결과 파일: {result_file}")
    print(f"분석 완료. Markdown 리포트 파일: {markdown_file}")


if __name__ == "__main__":
    main()