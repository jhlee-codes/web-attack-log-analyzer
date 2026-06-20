#!/usr/bin/env python3

import argparse
import csv
import json
import re
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path
from urllib.parse import unquote_plus, urlsplit


DEFAULT_ACCESS_LOG = Path("logs/access.log")
DEFAULT_LOGIN_LOG = Path("logs/login.log")
DEFAULT_THRESHOLD = 5
RESULT_DIR = Path("result")
DEFAULT_RULES_FILE = Path(__file__).resolve().parent / "rules.json"
SUPPORTED_REPORT_FORMATS = {"txt", "md", "json", "csv"}
SUPPORTED_SEVERITIES = {"HIGH", "MEDIUM", "LOW"}
SUPPORTED_ACCESS_FORMATS = {"custom", "nginx"}


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

NGINX_ACCESS_LOG_PATTERN = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ '
    r'\[(?P<timestamp>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<request_target>\S+) HTTP/[^"]+" '
    r'(?P<status>\d{3}) \S+ '
    r'"(?P<referer>[^"]*)" '
    r'"(?P<user_agent>[^"]*)"$'
)

LOGIN_LOG_PATTERN = re.compile(
    r'^(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) '
    r'(?P<event>LOGIN_SUCCESS|LOGIN_FAIL) '
    r'ip=(?P<ip>\S+) '
    r'id=(?P<user_id>\S*) '
    r'user_agent="(?P<user_agent>.*?)"$'
)


BUILTIN_RULE_SUMMARY = [
    {
        "rule_id": "SCAN-002",
        "attack_type": "Repeated 404",
        "severity": "MEDIUM",
        "confidence": "MEDIUM",
        "description": "동일 IP에서 404 응답 반복 발생 탐지",
    },
    {
        "rule_id": "AUTH-001",
        "attack_type": "Repeated Login Failure",
        "severity": "MEDIUM/HIGH",
        "confidence": "MEDIUM/HIGH",
        "description": "동일 IP에서 로그인 실패 반복 발생 탐지",
    },
    {
        "rule_id": "AUTH-002",
        "attack_type": "Successful Login After Failures",
        "severity": "HIGH",
        "confidence": "HIGH",
        "description": "반복 실패 후 성공 로그인 탐지",
    },
]


def parse_custom_access_log_line(line: str):
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


def parse_nginx_access_log_line(line: str):
    match = NGINX_ACCESS_LOG_PATTERN.search(line.strip())

    if not match:
        return None

    request_target = match.group("request_target")
    parsed_target = urlsplit(request_target)

    return {
        "timestamp": match.group("timestamp"),
        "ip": match.group("ip"),
        "method": match.group("method"),
        "path": parsed_target.path or request_target,
        "query": parsed_target.query,
        "status": int(match.group("status")),
        "user_agent": match.group("user_agent"),
    }


def parse_access_log_line(line: str, access_format: str = "custom"):
    if access_format == "custom":
        return parse_custom_access_log_line(line)

    if access_format == "nginx":
        return parse_nginx_access_log_line(line)

    raise ValueError(f"지원하지 않는 access format입니다: {access_format}")


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


def load_detection_rules(rules_file: Path = DEFAULT_RULES_FILE) -> list[dict]:
    with rules_file.open("r", encoding="utf-8") as file:
        payload = json.load(file)

    rules = payload.get("rules", [])

    if not isinstance(rules, list):
        raise ValueError("rules 파일의 rules 값은 list여야 합니다.")

    required_fields = {
        "rule_id",
        "attack_type",
        "severity",
        "confidence",
        "source",
        "evidence_key",
        "patterns",
        "reason",
        "response",
        "description",
    }

    for rule in rules:
        missing_fields = required_fields - set(rule)

        if missing_fields:
            missing = ", ".join(sorted(missing_fields))
            rule_id = rule.get("rule_id", "UNKNOWN")
            raise ValueError(f"{rule_id} 룰에 필수 필드가 없습니다: {missing}")

        if rule["source"] not in {"request", "user_agent"}:
            raise ValueError(f"{rule['rule_id']} 룰 source는 request 또는 user_agent여야 합니다.")

        if not isinstance(rule["patterns"], list) or not rule["patterns"]:
            raise ValueError(f"{rule['rule_id']} 룰 patterns는 비어 있지 않은 list여야 합니다.")

    return rules


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


def add_pattern_rule_finding(findings: list, rule: dict, log: dict, matched_pattern: str):
    add_finding(
        findings=findings,
        rule_id=rule["rule_id"],
        risk=rule["severity"],
        attack_type=rule["attack_type"],
        confidence=rule["confidence"],
        source_log="access",
        timestamp=log["timestamp"],
        ip=log["ip"],
        method=log["method"],
        path=log["path"],
        query=log["query"],
        status=str(log["status"]),
        user_agent=log["user_agent"],
        evidence=f"{rule['evidence_key']}={matched_pattern}",
        reason=rule["reason"],
        response=rule["response"],
    )


def analyze_access_log(
    access_log: Path,
    threshold: int,
    rules: list[dict] | None = None,
    access_format: str = "custom",
):
    findings = []
    total_requests = 0

    status_404_by_ip = Counter()
    request_count_by_ip = Counter()
    rules = rules or load_detection_rules()

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
            log = parse_access_log_line(line, access_format)

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

            for rule in rules:
                target_text = request_text if rule["source"] == "request" else user_agent_lower

                if contains_any_pattern(target_text, rule["patterns"]):
                    add_pattern_rule_finding(
                        findings=findings,
                        rule=rule,
                        log=log,
                        matched_pattern=find_first_pattern(target_text, rule["patterns"]),
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


def parse_report_formats(value: str) -> set[str]:
    requested_formats = {
        item.strip().lower()
        for item in value.split(",")
        if item.strip()
    }

    if not requested_formats:
        raise argparse.ArgumentTypeError("format은 비어 있을 수 없습니다.")

    if "all" in requested_formats:
        if len(requested_formats) > 1:
            raise argparse.ArgumentTypeError("all은 다른 format과 함께 사용할 수 없습니다.")

        return set(SUPPORTED_REPORT_FORMATS)

    unsupported_formats = requested_formats - SUPPORTED_REPORT_FORMATS

    if unsupported_formats:
        supported = ", ".join(sorted(SUPPORTED_REPORT_FORMATS | {"all"}))
        invalid = ", ".join(sorted(unsupported_formats))
        raise argparse.ArgumentTypeError(
            f"지원하지 않는 format입니다: {invalid}. 사용 가능: {supported}"
        )

    return requested_formats


def parse_csv_values(value: str) -> set[str]:
    values = {
        item.strip()
        for item in value.split(",")
        if item.strip()
    }

    if not values:
        raise argparse.ArgumentTypeError("필터 값은 비어 있을 수 없습니다.")

    return values


def parse_severities(value: str) -> set[str]:
    severities = {item.upper() for item in parse_csv_values(value)}
    unsupported_severities = severities - SUPPORTED_SEVERITIES

    if unsupported_severities:
        supported = ", ".join(sorted(SUPPORTED_SEVERITIES))
        invalid = ", ".join(sorted(unsupported_severities))
        raise argparse.ArgumentTypeError(
            f"지원하지 않는 severity입니다: {invalid}. 사용 가능: {supported}"
        )

    return severities


def finding_matches_filters(finding: dict, filters: dict) -> bool:
    severities = filters.get("severities") or set()
    attack_types = filters.get("attack_types") or set()
    ips = filters.get("ips") or set()

    if severities and finding["severity"].upper() not in severities:
        return False

    if attack_types:
        finding_attack_type = finding["attack_type"].lower()

        if finding_attack_type not in {item.lower() for item in attack_types}:
            return False

    if ips and finding["ip"] not in ips:
        return False

    return True


def apply_finding_filters(analysis: dict, filters: dict) -> dict:
    if not any(filters.values()):
        return analysis

    filtered_analysis = analysis.copy()
    filtered_analysis["findings"] = [
        finding
        for finding in analysis["findings"]
        if finding_matches_filters(finding, filters)
    ]

    return filtered_analysis


def format_filter_values(values: set[str]) -> str:
    return ", ".join(sorted(values)) if values else "-"


def serialize_filters(filters: dict) -> dict:
    return {
        "severities": sorted(filters.get("severities") or []),
        "attack_types": sorted(filters.get("attack_types") or []),
        "ips": sorted(filters.get("ips") or []),
    }


def build_timeline(findings: list[dict]) -> list[dict]:
    timeline = [
        {
            "timestamp": finding["timestamp"],
            "rule_id": finding["rule_id"],
            "attack_type": finding["attack_type"],
            "severity": finding["severity"],
            "ip": finding["ip"],
            "method": finding["method"],
            "path": finding["path"],
            "query": finding["query"],
            "status": finding["status"],
            "evidence": finding["evidence"],
        }
        for finding in findings
        if finding["timestamp"] != "-"
    ]

    return sorted(timeline, key=lambda item: item["timestamp"])


def build_executive_summary(findings: list[dict]) -> dict:
    if not findings:
        return {
            "overall_risk": "NONE",
            "total_findings": 0,
            "top_attack_type": "-",
            "top_suspicious_ip": "-",
            "priority_action": "탐지된 의심 이벤트가 없습니다.",
        }

    risk_counts = get_risk_counts(findings)
    attack_type_counts = Counter(item["attack_type"] for item in findings)
    ip_counts = Counter(item["ip"] for item in findings if item["ip"] != "-")

    if risk_counts["HIGH"] > 0:
        overall_risk = "HIGH"
        priority_action = "HIGH 위험도 탐지 이벤트를 우선 확인하고 관련 IP와 요청 경로를 점검합니다."
    elif risk_counts["MEDIUM"] > 0:
        overall_risk = "MEDIUM"
        priority_action = "반복 요청, 스캔 정황, 로그인 실패 패턴을 검토합니다."
    else:
        overall_risk = "LOW"
        priority_action = "LOW 위험도 이벤트를 참고용으로 검토합니다."

    return {
        "overall_risk": overall_risk,
        "total_findings": len(findings),
        "top_attack_type": attack_type_counts.most_common(1)[0][0],
        "top_suspicious_ip": ip_counts.most_common(1)[0][0] if ip_counts else "-",
        "priority_action": priority_action,
    }


def build_report_payload(
    access_log: Path,
    login_log: Path,
    rules_file: Path,
    access_format: str,
    filters: dict,
    threshold: int,
    access_analysis: dict,
    login_analysis: dict,
):
    findings = access_analysis["findings"] + login_analysis["findings"]
    risk_counts = get_risk_counts(findings)
    suspicious_ips = sorted({item["ip"] for item in findings if item["ip"] != "-"})
    timeline = build_timeline(findings)
    executive_summary = build_executive_summary(findings)

    return {
        "analysis_info": {
            "analysis_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "access_log": str(access_log),
            "login_log": str(login_log),
            "rules_file": str(rules_file),
            "access_format": access_format,
            "threshold": threshold,
            "filters": serialize_filters(filters),
            "access_log_exists": access_analysis["access_log_exists"],
            "login_log_exists": login_analysis["login_log_exists"],
        },
        "summary": {
            "total_requests": access_analysis["total_requests"],
            "total_login_events": login_analysis["total_login_events"],
            "total_findings": len(findings),
            "suspicious_ip_count": len(suspicious_ips),
            "risk_counts": risk_counts,
        },
        "executive_summary": executive_summary,
        "statistics": {
            "suspicious_ips": suspicious_ips,
            "request_count_by_ip": dict(access_analysis["request_count_by_ip"]),
            "status_404_by_ip": dict(access_analysis["status_404_by_ip"]),
            "login_fail_by_ip": dict(login_analysis["login_fail_by_ip"]),
            "login_success_by_ip": dict(login_analysis["login_success_by_ip"]),
        },
        "timeline": timeline,
        "findings": findings,
    }


def write_txt_report(
    result_file: Path,
    access_log: Path,
    login_log: Path,
    rules_file: Path,
    access_format: str,
    filters: dict,
    threshold: int,
    access_analysis: dict,
    login_analysis: dict,
):
    findings = access_analysis["findings"] + login_analysis["findings"]
    risk_counts = get_risk_counts(findings)
    suspicious_ips = sorted({item["ip"] for item in findings if item["ip"] != "-"})
    executive_summary = build_executive_summary(findings)

    with result_file.open("w", encoding="utf-8") as report:
        report.write("==================================================\n")
        report.write(" Web Attack Log Analysis Report\n")
        report.write("==================================================\n\n")

        report.write("[분석 정보]\n")
        report.write(f"분석 시간        : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        report.write(f"Access 로그 파일 : {access_log}\n")
        report.write(f"Login 로그 파일  : {login_log}\n")
        report.write(f"탐지 룰 파일     : {rules_file}\n")
        report.write(f"Access 로그 포맷 : {access_format}\n")
        report.write(f"반복 탐지 기준   : 동일 IP에서 {threshold}회 이상\n\n")
        report.write(f"Severity 필터    : {format_filter_values(filters['severities'])}\n")
        report.write(f"공격 유형 필터   : {format_filter_values(filters['attack_types'])}\n")
        report.write(f"IP 필터          : {format_filter_values(filters['ips'])}\n\n")

        report.write("--------------------------------------------------\n")
        report.write("[요약]\n")
        report.write(f"전체 HTTP 요청 수        : {access_analysis['total_requests']}\n")
        report.write(f"전체 로그인 이벤트 수     : {login_analysis['total_login_events']}\n")
        report.write(f"전체 탐지 이벤트 수       : {len(findings)}\n")
        report.write(f"의심 IP 수               : {len(suspicious_ips)}\n")
        report.write(f"HIGH 위험도              : {risk_counts['HIGH']}\n")
        report.write(f"MEDIUM 위험도            : {risk_counts['MEDIUM']}\n\n")

        report.write("--------------------------------------------------\n")
        report.write("[Executive Summary]\n")
        report.write(f"전체 위험도              : {executive_summary['overall_risk']}\n")
        report.write(f"주요 공격 유형           : {executive_summary['top_attack_type']}\n")
        report.write(f"주요 의심 IP             : {executive_summary['top_suspicious_ip']}\n")
        report.write(f"우선 대응                : {executive_summary['priority_action']}\n\n")

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


def write_json_report(
    json_file: Path,
    access_log: Path,
    login_log: Path,
    rules_file: Path,
    access_format: str,
    filters: dict,
    threshold: int,
    access_analysis: dict,
    login_analysis: dict,
):
    payload = build_report_payload(
        access_log=access_log,
        login_log=login_log,
        rules_file=rules_file,
        access_format=access_format,
        filters=filters,
        threshold=threshold,
        access_analysis=access_analysis,
        login_analysis=login_analysis,
    )

    with json_file.open("w", encoding="utf-8") as report:
        json.dump(payload, report, ensure_ascii=False, indent=2)
        report.write("\n")


def write_csv_report(
    csv_file: Path,
    access_analysis: dict,
    login_analysis: dict,
):
    findings = access_analysis["findings"] + login_analysis["findings"]
    fieldnames = [
        "rule_id",
        "severity",
        "confidence",
        "source_log",
        "attack_type",
        "timestamp",
        "ip",
        "method",
        "path",
        "query",
        "status",
        "user_agent",
        "evidence",
        "reason",
        "response",
    ]

    with csv_file.open("w", encoding="utf-8", newline="") as report:
        writer = csv.DictWriter(report, fieldnames=fieldnames)
        writer.writeheader()

        for finding in findings:
            writer.writerow({field: finding.get(field, "-") for field in fieldnames})


def write_markdown_report(
    markdown_file: Path,
    access_log: Path,
    login_log: Path,
    rules_file: Path,
    rules: list[dict],
    access_format: str,
    filters: dict,
    threshold: int,
    access_analysis: dict,
    login_analysis: dict,
):
    findings = access_analysis["findings"] + login_analysis["findings"]
    risk_counts = get_risk_counts(findings)
    suspicious_ips = sorted({item["ip"] for item in findings if item["ip"] != "-"})
    timeline = build_timeline(findings)
    executive_summary = build_executive_summary(findings)

    with markdown_file.open("w", encoding="utf-8") as report:
        report.write("# Web Attack Log Analysis Report\n\n")

        report.write("## 1. Analysis Information\n\n")
        report.write("| 항목 | 값 |\n")
        report.write("|---|---|\n")
        report.write(f"| 분석 시간 | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} |\n")
        report.write(f"| Access 로그 파일 | {access_log} |\n")
        report.write(f"| Login 로그 파일 | {login_log} |\n")
        report.write(f"| 탐지 룰 파일 | {rules_file} |\n")
        report.write(f"| Access 로그 포맷 | {access_format} |\n")
        report.write(f"| 반복 탐지 기준 | 동일 IP에서 {threshold}회 이상 |\n")
        report.write(f"| Severity 필터 | {format_filter_values(filters['severities'])} |\n")
        report.write(f"| 공격 유형 필터 | {format_filter_values(filters['attack_types'])} |\n")
        report.write(f"| IP 필터 | {format_filter_values(filters['ips'])} |\n\n")

        report.write("## 2. Summary\n\n")
        report.write("| 항목 | 값 |\n")
        report.write("|---|---:|\n")
        report.write(f"| 전체 HTTP 요청 수 | {access_analysis['total_requests']} |\n")
        report.write(f"| 전체 로그인 이벤트 수 | {login_analysis['total_login_events']} |\n")
        report.write(f"| 전체 탐지 이벤트 수 | {len(findings)} |\n")
        report.write(f"| 의심 IP 수 | {len(suspicious_ips)} |\n")
        report.write(f"| HIGH 위험도 | {risk_counts['HIGH']} |\n")
        report.write(f"| MEDIUM 위험도 | {risk_counts['MEDIUM']} |\n\n")

        report.write("## 3. Executive Summary\n\n")
        report.write("| 항목 | 값 |\n")
        report.write("|---|---|\n")
        report.write(f"| 전체 위험도 | {executive_summary['overall_risk']} |\n")
        report.write(f"| 주요 공격 유형 | {sanitize_markdown(executive_summary['top_attack_type'])} |\n")
        report.write(f"| 주요 의심 IP | {sanitize_markdown(executive_summary['top_suspicious_ip'])} |\n")
        report.write(f"| 우선 대응 | {sanitize_markdown(executive_summary['priority_action'])} |\n\n")

        report.write("## 4. Timeline\n\n")
        report.write("| Time | Severity | Rule ID | Attack Type | IP | Method | Path | Evidence |\n")
        report.write("|---|---|---|---|---|---|---|---|\n")

        if timeline:
            for item in timeline:
                report.write(
                    f"| {sanitize_markdown(item['timestamp'])} "
                    f"| {sanitize_markdown(item['severity'])} "
                    f"| {sanitize_markdown(item['rule_id'])} "
                    f"| {sanitize_markdown(item['attack_type'])} "
                    f"| {sanitize_markdown(item['ip'])} "
                    f"| {sanitize_markdown(item['method'])} "
                    f"| {sanitize_markdown(item['path'])} "
                    f"| {sanitize_markdown(item['evidence'])} |\n"
                )
        else:
            report.write("| - | INFO | - | 타임라인 이벤트 없음 | - | - | - | timestamp가 있는 탐지 이벤트 없음 |\n")

        report.write("\n## 5. Detection Results\n\n")
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

        report.write("\n## 6. Detection Rule Summary\n\n")
        report.write("| Rule ID | Rule | Severity | Confidence | Description |\n")
        report.write("|---|---|---|---|---|\n")
        for rule in rules + BUILTIN_RULE_SUMMARY:
            report.write(
                f"| {sanitize_markdown(rule['rule_id'])} "
                f"| {sanitize_markdown(rule['attack_type'])} "
                f"| {sanitize_markdown(rule['severity'])} "
                f"| {sanitize_markdown(rule['confidence'])} "
                f"| {sanitize_markdown(rule['description'])} |\n"
            )
        report.write("\n")

        report.write("## 7. Recommended Response Guide\n\n")
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
        "--access-format",
        choices=sorted(SUPPORTED_ACCESS_FORMATS),
        default="custom",
        help="Access log format. Default: custom",
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
    parser.add_argument(
        "--rules-file",
        type=Path,
        default=DEFAULT_RULES_FILE,
        help=f"Detection rules JSON file. Default: {DEFAULT_RULES_FILE}",
    )
    parser.add_argument(
        "--severity",
        type=parse_severities,
        default=set(),
        help="Comma-separated severity filter: HIGH, MEDIUM, LOW",
    )
    parser.add_argument(
        "--attack-type",
        type=parse_csv_values,
        default=set(),
        help='Comma-separated attack type filter. Example: "SQL Injection,XSS"',
    )
    parser.add_argument(
        "--ip",
        type=parse_csv_values,
        default=set(),
        help="Comma-separated source IP filter.",
    )
    parser.add_argument(
        "--format",
        dest="report_formats",
        type=parse_report_formats,
        default=set(SUPPORTED_REPORT_FORMATS),
        help="Comma-separated report formats: txt, md, json, csv, all. Default: all",
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
    access_format = args.access_format
    login_log = args.login_log
    threshold = args.threshold
    output_dir = args.output_dir
    rules_file = args.rules_file
    report_formats = args.report_formats
    filters = {
        "severities": args.severity,
        "attack_types": args.attack_type,
        "ips": args.ip,
    }

    if not access_log.exists() and not login_log.exists():
        print(f"Error: 분석할 로그 파일이 없습니다.")
        print(f"- Access log: {access_log}")
        print(f"- Login log : {login_log}")
        sys.exit(1)

    if not rules_file.exists():
        print(f"Error: 탐지 룰 파일이 없습니다: {rules_file}")
        sys.exit(1)

    output_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    result_file = output_dir / f"web_attack_detection_result_{timestamp}.txt"
    markdown_file = output_dir / f"web_attack_detection_report_{timestamp}.md"
    json_file = output_dir / f"web_attack_detection_report_{timestamp}.json"
    csv_file = output_dir / f"web_attack_detection_findings_{timestamp}.csv"

    rules = load_detection_rules(rules_file)
    access_analysis = analyze_access_log(access_log, threshold, rules, access_format)
    login_analysis = analyze_login_log(login_log, threshold)
    filtered_access_analysis = apply_finding_filters(access_analysis, filters)
    filtered_login_analysis = apply_finding_filters(login_analysis, filters)

    if "txt" in report_formats:
        write_txt_report(
            result_file=result_file,
            access_log=access_log,
            login_log=login_log,
            rules_file=rules_file,
            access_format=access_format,
            filters=filters,
            threshold=threshold,
            access_analysis=filtered_access_analysis,
            login_analysis=filtered_login_analysis,
        )
        print(f"분석 완료. TXT 결과 파일: {result_file}")

    if "md" in report_formats:
        write_markdown_report(
            markdown_file=markdown_file,
            access_log=access_log,
            login_log=login_log,
            rules_file=rules_file,
            rules=rules,
            access_format=access_format,
            filters=filters,
            threshold=threshold,
            access_analysis=filtered_access_analysis,
            login_analysis=filtered_login_analysis,
        )
        print(f"분석 완료. Markdown 리포트 파일: {markdown_file}")

    if "json" in report_formats:
        write_json_report(
            json_file=json_file,
            access_log=access_log,
            login_log=login_log,
            rules_file=rules_file,
            access_format=access_format,
            filters=filters,
            threshold=threshold,
            access_analysis=filtered_access_analysis,
            login_analysis=filtered_login_analysis,
        )
        print(f"분석 완료. JSON 리포트 파일: {json_file}")

    if "csv" in report_formats:
        write_csv_report(
            csv_file=csv_file,
            access_analysis=filtered_access_analysis,
            login_analysis=filtered_login_analysis,
        )
        print(f"분석 완료. CSV 탐지 결과 파일: {csv_file}")


if __name__ == "__main__":
    main()
