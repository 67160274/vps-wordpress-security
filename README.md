# VPS WordPress Security Project

## Architecture
- Ubuntu 24.04 LTS on Azure (Korea Central)
- nginx 1.24.0 (Reverse Proxy + SSL)
- WordPress 7.1.4 + Apache 2.4.69 + PHP 8.3.36 (Docker)
- MariaDB 11.8.9 (Docker)
- iptables + ipset (Thai IP only)
- Security Dashboard (rule-based log analysis)

## Structure

## Security Features
1. SSH PKI only (no password, no root)
2. Firewall: allow only Thailand IPs (iptables + ipset)
3. Reverse proxy with security headers
4. Automated log scanning every hour
5. Security dashboard at /dashboard/

## Files
- `docker-compose.yml` - WordPress + MariaDB containers
- `nginx.conf` - nginx reverse proxy config
- `scan_log.py` - Log scanner (runs every hour via cron)
- `dashboard.py` - Security dashboard web server
