#!/usr/bin/env python3
"""
Security Log Scanner - Rule-based AI Analysis (ไม่ใช้ API)
"""

import re
import json
import sqlite3
from datetime import datetime, timedelta
from collections import Counter

NGINX_LOG = "/var/log/nginx/access.log"
AUTH_LOG = "/var/log/auth.log"
DB_PATH = "/home/student/security-dashboard/security.db"
SCAN_MINUTES = 60

ATTACK_PATTERNS = [
    (r"wp-login\.php", "Brute Force WordPress Login"),
    (r"xmlrpc\.php", "XML-RPC Attack"),
    (r"\.env", "Config File Probe"),
    (r"etc/passwd", "Path Traversal"),
    (r"union.*select", "SQL Injection"),
    (r"\.\./", "Directory Traversal"),
    (r"<script", "XSS Attempt"),
    (r"base64_decode|eval\(", "Code Injection"),
    (r"phpmyadmin|pma/", "phpMyAdmin Probe"),
    (r"\.git/", "Git Exposure Probe"),
    (r"\.php\?.*=http", "Remote File Include"),
    (r"cmd=|exec=|system\(", "Command Injection"),
    (r"wget |curl ", "Downloader Execution"),
    (r"nikto|sqlmap|nmap|masscan", "Scanner Tool Detected"),
]

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        total_requests INTEGER,
        unique_ips INTEGER,
        blocked_countries INTEGER,
        top_attacker_ip TEXT,
        attack_types TEXT,
        ssh_failures INTEGER,
        risk_level TEXT,
        ai_summary TEXT,
        ai_recommendations TEXT,
        raw_stats TEXT
    )''')
    conn.commit()
    conn.close()

def parse_nginx_log(minutes=60):
    stats = {
        "total_requests": 0,
        "ips": Counter(),
        "status_codes": Counter(),
        "suspicious_paths": [],
        "methods": Counter(),
        "attack_type_counts": Counter(),
    }
    cutoff = datetime.now() - timedelta(minutes=minutes)
    try:
        with open(NGINX_LOG, 'r', errors='ignore') as f:
            for line in f:
                match = re.match(
                    r'(\S+) - \S+ \[(.+?)\] "(\S+) (\S+) \S+" (\d+) \d+ ".*?" "(.*?)"',
                    line
                )
                if not match:
                    continue
                ip, time_str, method, path, status, ua = match.groups()
                try:
                    log_time = datetime.strptime(time_str[:20], "%d/%b/%Y:%H:%M:%S")
                    if log_time < cutoff:
                        continue
                except:
                    pass
                stats["total_requests"] += 1
                stats["ips"][ip] += 1
                stats["status_codes"][status] += 1
                stats["methods"][method] += 1
                for pattern, attack_name in ATTACK_PATTERNS:
                    if re.search(pattern, path + ua, re.IGNORECASE):
                        stats["suspicious_paths"].append({
                            "ip": ip, "path": path[:100],
                            "attack": attack_name, "status": status
                        })
                        stats["attack_type_counts"][attack_name] += 1
                        break
    except FileNotFoundError:
        pass
    return stats

def parse_auth_log(minutes=60):
    stats = {
        "failed_attempts": 0,
        "failed_ips": Counter(),
        "invalid_users": Counter(),
        "successful_logins": 0,
    }
    cutoff = datetime.now() - timedelta(minutes=minutes)
    try:
        with open(AUTH_LOG, 'r', errors='ignore') as f:
            for line in f:
                try:
                    year = datetime.now().year
                    log_time = datetime.strptime(f"{year} {line[:15]}", "%Y %b %d %H:%M:%S")
                    if log_time < cutoff:
                        continue
                except:
                    pass
                if "Failed password" in line or "Invalid user" in line:
                    stats["failed_attempts"] += 1
                    ip_match = re.search(r'from (\d+\.\d+\.\d+\.\d+)', line)
                    if ip_match:
                        stats["failed_ips"][ip_match.group(1)] += 1
                    user_match = re.search(r'for (?:invalid user )?(\w+) from', line)
                    if user_match:
                        stats["invalid_users"][user_match.group(1)] += 1
                elif "Accepted publickey" in line:
                    stats["successful_logins"] += 1
    except FileNotFoundError:
        pass
    return stats

def rule_based_analysis(nginx, ssh):
    """วิเคราะห์ด้วยกฎ - ไม่ใช้ AI API"""
    score = 0
    attack_types = list(nginx["attack_type_counts"].keys())
    recommendations = []
    issues = []

    # === คำนวณ Risk Score ===
    sus_count = len(nginx["suspicious_paths"])
    if sus_count > 50:
        score += 40
        issues.append(f"พบ suspicious requests สูงมาก {sus_count} ครั้ง")
    elif sus_count > 20:
        score += 25
        issues.append(f"พบ suspicious requests {sus_count} ครั้ง")
    elif sus_count > 5:
        score += 10
        issues.append(f"พบ suspicious requests {sus_count} ครั้ง")

    if ssh["failed_attempts"] > 100:
        score += 40
        issues.append(f"SSH brute force รุนแรง {ssh['failed_attempts']} ครั้ง")
    elif ssh["failed_attempts"] > 20:
        score += 20
        issues.append(f"SSH failed login {ssh['failed_attempts']} ครั้ง")
    elif ssh["failed_attempts"] > 5:
        score += 10
        issues.append(f"มี SSH failed login {ssh['failed_attempts']} ครั้ง")

    # IP เดียวยิงมาก
    top_ips = nginx["ips"].most_common(1)
    if top_ips and top_ips[0][1] > 500:
        score += 20
        issues.append(f"IP {top_ips[0][0]} ส่ง request มากผิดปกติ ({top_ips[0][1]} ครั้ง)")
    elif top_ips and top_ips[0][1] > 200:
        score += 10

    # ประเภทการโจมตี
    if "SQL Injection" in attack_types:
        score += 15
        recommendations.append("ตรวจสอบ WAF และ prepared statements ใน code")
    if "Brute Force WordPress Login" in attack_types:
        score += 10
        recommendations.append("ติดตั้ง plugin จำกัดการ login เช่น Limit Login Attempts")
    if "Scanner Tool Detected" in attack_types:
        score += 15
        issues.append("ตรวจพบการใช้ scanner tool (nikto/sqlmap/nmap)")

    # คำแนะนำพื้นฐาน
    if ssh["failed_attempts"] > 5:
        recommendations.append("พิจารณาติดตั้ง fail2ban เพื่อแบน IP ที่ login ผิดซ้ำ")
    if sus_count > 10:
        recommendations.append("ตรวจสอบ log เพิ่มเติมและพิจารณาบล็อก IP ต้องสงสัย")
    if not recommendations:
        recommendations.append("ระบบทำงานปกติ ควรตรวจสอบ log เป็นประจำ")

    # === Risk Level ===
    if score >= 60:
        risk = "CRITICAL"
    elif score >= 35:
        risk = "HIGH"
    elif score >= 15:
        risk = "MEDIUM"
    else:
        risk = "LOW"

    # === สรุป ===
    if not issues:
        summary = f"ระบบทำงานปกติในช่วง {SCAN_MINUTES} นาทีที่ผ่านมา พบ request ทั้งหมด {nginx['total_requests']} ครั้ง จาก {len(nginx['ips'])} IP ไม่พบการโจมตีที่น่าเป็นห่วง"
    else:
        summary = f"พบความผิดปกติ {len(issues)} รายการ: {' | '.join(issues[:2])}"
        if len(issues) > 2:
            summary += f" และอื่นๆ อีก {len(issues)-2} รายการ"

    return {
        "risk_level": risk,
        "score": score,
        "attack_types": attack_types,
        "summary": summary,
        "recommendations": recommendations
    }

def save_to_db(nginx, ssh, analysis):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    top_ip = nginx['ips'].most_common(1)
    top_ip_str = f"{top_ip[0][0]} ({top_ip[0][1]} reqs)" if top_ip else "none"
    raw_stats = json.dumps({
        "nginx": {
            "total": nginx["total_requests"],
            "unique_ips": len(nginx["ips"]),
            "top_ips": dict(nginx["ips"].most_common(10)),
            "status_codes": dict(nginx["status_codes"]),
            "suspicious_count": len(nginx["suspicious_paths"]),
            "suspicious_samples": nginx["suspicious_paths"][:10],
            "attack_type_counts": dict(nginx["attack_type_counts"])
        },
        "ssh": {
            "failed_attempts": ssh["failed_attempts"],
            "failed_ips": dict(ssh["failed_ips"].most_common(5)),
            "invalid_users": dict(ssh["invalid_users"].most_common(5)),
            "successful_logins": ssh["successful_logins"]
        }
    }, ensure_ascii=False)
    c.execute('''INSERT INTO scans
        (timestamp, total_requests, unique_ips, blocked_countries,
         top_attacker_ip, attack_types, ssh_failures, risk_level,
         ai_summary, ai_recommendations, raw_stats)
        VALUES (?,?,?,?,?,?,?,?,?,?,?)''', (
        datetime.now().isoformat(),
        nginx["total_requests"],
        len(nginx["ips"]),
        0,
        top_ip_str,
        json.dumps(analysis["attack_types"], ensure_ascii=False),
        ssh["failed_attempts"],
        analysis["risk_level"],
        analysis["summary"],
        json.dumps(analysis["recommendations"], ensure_ascii=False),
        raw_stats
    ))
    conn.commit()
    conn.close()
    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] สแกนเสร็จ - Risk: {analysis['risk_level']} (score={analysis['score']}) | Suspicious: {len(nginx['suspicious_paths'])} | SSH failed: {ssh['failed_attempts']}")

def main():
    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] เริ่มสแกน log (rule-based)...")
    init_db()
    nginx = parse_nginx_log(SCAN_MINUTES)
    ssh = parse_auth_log(SCAN_MINUTES)
    analysis = rule_based_analysis(nginx, ssh)
    save_to_db(nginx, ssh, analysis)

if __name__ == "__main__":
    main()
