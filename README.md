# การสร้างเว็บไซต์บน WordPress
## วิชา 88633065 Computer Networks
## สาขาวิทยาการคอมพิวเตอร์ คณะวิทยาการสารสนเทศ มหาวิทยาลัยบูรพา
## ภาคเรียนที่ 1 ปีการศึกษา 2569

---

## คณะผู้จัดทำ

| ชื่อ | รหัสนักศึกษา |
|------|--------------|
| นาย ณัฏฐพล สุดสอาด | 67160089 |
| นาย อังกูร กันธพงศ์ | 67160110 |
| นาย กตฌกานต์ ชาติกุล | 67160245 |
| นาย สรธัญ สมแก้ว | 67160274 |
| นาย ศุภกิจ ก่อทรัพย์ทวี | 67160429 |
| นางสาว ภัทราพร ตันเจริญ | 65160188 |

**เสนอ:** ผศ.ภูสิต กุลเกษม

---

## เว็บไซต์
🌐 https://wordduckpress.duckdns.org

---

---

## Version ของซอฟต์แวร์

| โปรแกรม | Version |
|---------|---------|
| Ubuntu | 24.04.5 LTS |
| OpenSSH | 9.6p1 |
| Docker | 29.1.3 |
| nginx | 1.24.0 (host) |
| Apache | 2.4.69 (container) |
| PHP | 8.3.36 (container) |
| WordPress | 7.1.4 (container) |
| MariaDB | 11.8.9 (container) |

---

## ไฟล์ในโปรเจกต์

| ไฟล์ | คำอธิบาย |
|------|----------|
| `Network.pdf` | รายงานฉบับสมบูรณ์ |
| `docker-compose.yml` | ตั้งค่า WordPress + MariaDB containers |
| `nginx.conf` | nginx reverse proxy + SSL config |
| `sshd_config.txt` | SSH security config (PKI only) |
| `iptables-rules.txt` | กฎ firewall (Thai IP only) |
| `ipset-thai.txt` | รายการ IP range ของประเทศไทย |
| `scan_log.py` | สแกน log ทุก 1 ชั่วโมง (rule-based AI) |
| `dashboard.py` | Security dashboard web server |

---

## มาตรการความปลอดภัย

1. **SSH PKI** - ปิด root login, ปิด password authentication
2. **Firewall** - iptables + ipset อนุญาตเฉพาะ IP ไทย (1,196 ranges)
3. **Reverse Proxy** - nginx รับ HTTPS แล้วส่งต่อ WordPress ภายใน
4. **Docker isolation** - WordPress ผูกกับ 127.0.0.1:8080 เท่านั้น
5. **Security Headers** - HSTS, X-Frame-Options, X-Content-Type-Options
6. **Security Dashboard** - สแกน log อัตโนมัติทุก 1 ชั่วโมง

---

## Cloud Provider
- Microsoft Azure (Azure for Students)
- VM: Standard B2ats v2 (2 vCPUs, 1 GiB) - Korea Central
- Public IP: 20.41.114.69 (Static)
