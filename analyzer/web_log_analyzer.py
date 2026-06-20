#!/usr/bin/env python3

import argparse
import re
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path
from urllib.parse import unquote_plus


DEFAULT_ACCESS_LOG = Path("logs/access.log")
DEFAULT_LOGIN_LOG = Path("logs/login.log")
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


def find_first_pattern(text: str, patterns: list[str]) -> str:
    for pattern in patterns:
        if pattern in text:
            return pattern

    return "-"


def add_finding(
    findings: list,
    rule_id: str,
    risk: str,
    attack_type: str,
    confidence: str,
    source_log: str,
    timestamp: str,
    ip: str,
    method: str,
    path: str,
    query: str,
    status: str,
    user_agent: str,
    evidence: str,
    reason: str,
    response: str,
):
    findings.append(
        {
            "rule_id": rule_id,
            "risk": risk,
            "severity": risk,
            "attack_type": attack_type,
            "confidence": confidence,
            "source_log": source_log,
            "timestamp": timestamp,
            "ip": ip,
            "method": method,
            "path": path,
            "query": query,
            "status": status,
            "user_agent": user_agent,
            "evidence": evidence,
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
                    rule_id="SQLI-001",
                    risk="HIGH",
                    attack_type="SQL Injection",
                    confidence="HIGH",
                    source_log="access",
                    timestamp=log["timestamp"],
                    ip=ip,
                    method=method,
                    path=path,
                    query=query,
                    status=str(status),
                    user_agent=user_agent,
                    evidence=f"matched_pattern={find_first_pattern(request_text, SQLI_PATTERNS)}",
                    reason="요청 경로 또는 쿼리 문자열에서 SQL Injection 의심 패턴 발견",
                    response="입력값 검증, Prepared Statement 사용 여부, WAF 룰을 점검합니다.",
                )

            if contains_any_pattern(request_text, XSS_PATTERNS):
                add_finding(
                    findings=findings,
                    rule_id="XSS-001",
                    risk="HIGH",
                    attack_type="XSS",
                    confidence="HIGH",
                    source_log="access",
                    timestamp=log["timestamp"],
                    ip=ip,
                    method=method,
                    path=path,
                    query=query,
                    status=str(status),
                    user_agent=user_agent,
                    evidence=f"matched_pattern={find_first_pattern(request_text, XSS_PATTERNS)}",
                    reason="요청 경로 또는 쿼리 문자열에서 XSS 의심 패턴 발견",
                    response="출력 인코딩, 입력값 필터링, CSP 적용 여부를 점검합니다.",
                )

            if contains_any_pattern(request_text, PATH_TRAVERSAL_PATTERNS):
                add_finding(
                    findings=findings,
                    rule_id="PATH-001",
                    risk="HIGH",
                    attack_type="Path Traversal",
                    confidence="HIGH",
                    source_log="access",
                    timestamp=log["timestamp"],
                    ip=ip,
                    method=method,
                    path=path,
                    query=query,
                    status=str(status),
                    user_agent=user_agent,
                    evidence=f"matched_pattern={find_first_pattern(request_text, PATH_TRAVERSAL_PATTERNS)}",
                    reason="파일 경로 조작 또는 민감 파일 접근 시도 패턴 발견",
                    response="파일 경로 입력값 검증, 상위 디렉터리 접근 차단 여부를 확인합니다.",
                )

            if contains_any_pattern(request_text, ADMIN_PATH_PATTERNS):
                add_finding(
                    findings=findings,
                    rule_id="ADMIN-001",
                    risk="MEDIUM",
                    attack_type="Admin Page Access",
                    confidence="MEDIUM",
                    source_log="access",
                    timestamp=log["timestamp"],
                    ip=ip,
                    method=method,
                    path=path,
                    query=query,
                    status=str(status),
                    user_agent=user_agent,
                    evidence=f"matched_path={find_first_pattern(request_text, ADMIN_PATH_PATTERNS)}",
                    reason="관리자 페이지 또는 관리 도구 접근 시도 탐지",
                    response="관리자 페이지 접근 IP 제한, 인증 정책, 접근 로그를 확인합니다.",
                )

            if contains_any_pattern(user_agent_lower, SCANNER_USER_AGENTS):
                add_finding(
                    findings=findings,
                    rule_id="SCAN-001",
                    risk="MEDIUM",
                    attack_type="Suspicious User-Agent",
                    confidence="MEDIUM",
                    source_log="access",
                    timestamp=log["timestamp"],
                    ip=ip,
                    method=method,
                    path=path,
                    query=query,
                    status=str(status),
                    user_agent=user_agent,
                    evidence=f"matched_user_agent={find_first_pattern(user_agent_lower, SCANNER_USER_AGENTS)}",
                    reason="스캐너 또는 자동화 도구로 의심되는 User-Agent 탐지",
                    response="해당 IP의 요청 패턴을 추가 확인하고 필요 시 차단을 검토합니다.",
                )

    for ip, count in status_404_by_ip.items():
        if count >= threshold:
            add_finding(
                findings=findings,
                rule_id="SCAN-002",
                risk="MEDIUM",
                attack_type="Repeated 404",
                confidence="MEDIUM",
                source_log="access",
                timestamp="-",
                ip=ip,
                method="-",
                path="-",
                query="-",
                status="404",
                user_agent="-",
                evidence=f"status_404_count={count}, threshold={threshold}",
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
                rule_id="AUTH-001",
                risk=risk,
                attack_type="Repeated Login Failure",
                confidence="HIGH" if count >= threshold * 2 else "MEDIUM",
                source_log="login",
                timestamp="-",
                ip=ip,
                method="POST",
                path="/login",
                query="-",
                status="-",
                user_agent="-",
                evidence=f"login_fail_count={count}, threshold={threshold}",
                reason=f"동일 IP에서 로그인 실패가 {count}회 발생",
                response="계정 대입 공격 가능성을 확인하고, IP 차단 또는 로그인 제한 정책을 검토합니다.",
            )

    for ip, success_count in login_success_by_ip.items():
        fail_count = login_fail_by_ip[ip]

        if fail_count >= threshold and success_count > 0:
            add_finding(
                findings=findings,
                rule_id="AUTH-002",
                risk="HIGH",
                attack_type="Successful Login After Failures",
                confidence="HIGH",
                source_log="login",
                timestamp="-",
                ip=ip,
                method="POST",
                path="/login",
                query="-",
                status="-",
                user_agent="-",
                evidence=f"login_fail_count={fail_count}, login_success_count={success_count}, threshold={threshold}",
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
                report.write(f"[{item['severity']}] {item['attack_type']} ({item['rule_id']})\n")
                report.write(f"Rule ID       : {item['rule_id']}\n")
                report.write(f"Severity      : {item['severity']}\n")
                report.write(f"Confidence    : {item['confidence']}\n")
                report.write(f"Source Log    : {item['source_log']}\n")
                report.write(f"시간          : {item['timestamp']}\n")
                report.write(f"IP 주소       : {item['ip']}\n")
                report.write(f"Method        : {item['method']}\n")
                report.write(f"Path          : {item['path']}\n")
                report.write(f"Query         : {item['query']}\n")
                report.write(f"Status        : {item['status']}\n")
                report.write(f"User-Agent    : {item['user_agent']}\n")
                report.write(f"Evidence      : {item['evidence']}\n")
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
            "| Rule ID | Severity | Confidence | Source Log | Attack Type | Time | IP | Method | Path | Query | Status | User-Agent | Evidence | Reason | Recommended Response |\n"
        )
        report.write("|---|---|---|---|---|---|---|---|---|---|---:|---|---|---|---|\n")

        if findings:
            for item in findings:
                report.write(
                    f"| {sanitize_markdown(item['rule_id'])} "
                    f"| {sanitize_markdown(item['severity'])} "
                    f"| {sanitize_markdown(item['confidence'])} "
                    f"| {sanitize_markdown(item['source_log'])} "
                    f"| {sanitize_markdown(item['attack_type'])} "
                    f"| {sanitize_markdown(item['timestamp'])} "
                    f"| {sanitize_markdown(item['ip'])} "
                    f"| {sanitize_markdown(item['method'])} "
                    f"| {sanitize_markdown(item['path'])} "
                    f"| {sanitize_markdown(item['query'])} "
                    f"| {sanitize_markdown(item['status'])} "
                    f"| {sanitize_markdown(item['user_agent'])} "
                    f"| {sanitize_markdown(item['evidence'])} "
                    f"| {sanitize_markdown(item['reason'])} "
                    f"| {sanitize_markdown(item['response'])} |\n"
                )
        else:
            report.write("| INFO-000 | INFO | HIGH | - | 정상 | - | - | - | - | - | - | - | - | 탐지된 웹 공격 의심 이벤트 없음 | 추가 조치 불필요 |\n")

        report.write("\n## 4. Detection Rule Summary\n\n")
        report.write("| Rule ID | Rule | Severity | Confidence | Description |\n")
        report.write("|---|---|---|---|---|\n")
        report.write("| SQLI-001 | SQL Injection | HIGH | HIGH | SQL Injection 의심 문자열 탐지 |\n")
        report.write("| XSS-001 | XSS | HIGH | HIGH | Script 삽입 또는 이벤트 핸들러 기반 XSS 패턴 탐지 |\n")
        report.write("| PATH-001 | Path Traversal | HIGH | HIGH | ../, /etc/passwd 등 경로 조작 시도 탐지 |\n")
        report.write("| ADMIN-001 | Admin Page Access | MEDIUM | MEDIUM | 관리자 페이지 접근 시도 탐지 |\n")
        report.write("| SCAN-001 | Suspicious User-Agent | MEDIUM | MEDIUM | sqlmap, nikto, curl 등 자동화 도구 User-Agent 탐지 |\n")
        report.write("| SCAN-002 | Repeated 404 | MEDIUM | MEDIUM | 동일 IP에서 404 응답 반복 발생 탐지 |\n")
        report.write("| AUTH-001 | Repeated Login Failure | MEDIUM/HIGH | MEDIUM/HIGH | 동일 IP에서 로그인 실패 반복 발생 탐지 |\n")
        report.write("| AUTH-002 | Successful Login After Failures | HIGH | HIGH | 반복 실패 후 성공 로그인 탐지 |\n\n")

        report.write("## 5. Recommended Response Guide\n\n")
        report.write("- SQL Injection 탐지 시 입력값 검증과 DB 쿼리 처리 방식을 확인합니다.\n")
        report.write("- XSS 탐지 시 출력 인코딩, 입력값 필터링, CSP 적용 여부를 확인합니다.\n")
        report.write("- Path Traversal 탐지 시 파일 경로 입력값 검증과 접근 제한을 확인합니다.\n")
        report.write("- 로그인 실패 반복 탐지 시 계정 대입 공격 가능성을 확인합니다.\n")
        report.write("- 스캐너 User-Agent 또는 반복 404 탐지 시 자동화된 스캔 여부를 확인합니다.\n")


def parse_args():
    parser = argparse.ArgumentParser(
        description="Analyze web access and login logs for suspicious attack patterns."
    )
    parser.add_argument(
        "legacy_access_log",
        nargs="?",
        type=Path,
        help="Access log path. Deprecated: use --access-log.",
    )
    parser.add_argument(
        "legacy_login_log",
        nargs="?",
        type=Path,
        help="Login log path. Deprecated: use --login-log.",
    )
    parser.add_argument(
        "legacy_threshold",
        nargs="?",
        type=int,
        help="Repeated event threshold. Deprecated: use --threshold.",
    )
    parser.add_argument(
        "--access-log",
        type=Path,
        default=None,
        help=f"Access log path. Default: {DEFAULT_ACCESS_LOG}",
    )
    parser.add_argument(
        "--login-log",
        type=Path,
        default=None,
        help=f"Login log path. Default: {DEFAULT_LOGIN_LOG}",
    )
    parser.add_argument(
        "--threshold",
        type=int,
        default=None,
        help=f"Repeated event threshold. Default: {DEFAULT_THRESHOLD}",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=RESULT_DIR,
        help=f"Directory to save report files. Default: {RESULT_DIR}",
    )

    args = parser.parse_args()

    if args.threshold is not None and args.legacy_threshold is not None:
        parser.error("threshold는 위치 인자와 --threshold 중 하나만 입력해야 합니다.")

    if args.access_log is not None and args.legacy_access_log is not None:
        parser.error("access log는 위치 인자와 --access-log 중 하나만 입력해야 합니다.")

    if args.login_log is not None and args.legacy_login_log is not None:
        parser.error("login log는 위치 인자와 --login-log 중 하나만 입력해야 합니다.")

    if args.threshold is not None and args.threshold < 1:
        parser.error("--threshold는 1 이상의 숫자여야 합니다.")

    if args.legacy_threshold is not None and args.legacy_threshold < 1:
        parser.error("threshold는 1 이상의 숫자여야 합니다.")

    args.access_log = args.access_log or args.legacy_access_log or DEFAULT_ACCESS_LOG
    args.login_log = args.login_log or args.legacy_login_log or DEFAULT_LOGIN_LOG
    args.threshold = args.threshold or args.legacy_threshold or DEFAULT_THRESHOLD

    return args


def main():
    args = parse_args()
    access_log = args.access_log
    login_log = args.login_log
    threshold = args.threshold
    output_dir = args.output_dir

    if not access_log.exists() and not login_log.exists():
        print(f"Error: 분석할 로그 파일이 없습니다.")
        print(f"- Access log: {access_log}")
        print(f"- Login log : {login_log}")
        sys.exit(1)

    output_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    result_file = output_dir / f"web_attack_detection_result_{timestamp}.txt"
    markdown_file = output_dir / f"web_attack_detection_report_{timestamp}.md"

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
