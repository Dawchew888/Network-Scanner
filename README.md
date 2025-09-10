# Network Scanner v0.1

English | [中文](#中文说明)

A versatile network scanning tool written in Python.

---

## About The Project

**Network Scanner** is a command-line tool designed for network reconnaissance and security testing. It supports multiple scanning modes such as brute-force attacks (MySQL, Redis, SSH), host discovery, port scanning, and subdomain enumeration.

---

## Features

- **MySQL/Redis/SSH Brute-force:** Detect weak credentials.
- **Host Discovery:** Find live hosts in a network segment.
- **Port Scanning:** Scan single ports, ranges, or lists.
- **Subdomain Enumeration:** Discover subdomains with default or custom dictionaries.

---

## Usage

The tool uses a command-based structure. Below are some examples:

### 1. MySQL Brute-force (`mysql`)

Scan a single host with default dictionaries:
```bash
python security_tool.py mysql 192.168.1.10
```

Scan an IP range with a specified port and dictionaries:
```bash
python security_tool.py mysql 192.168.1.1-100 -P 3307 -u my_users.txt -p my_pass.txt
```

---

### 2. Redis Brute-force (`redis`)

Scan a single host:
```bash
python security_tool.py redis 192.168.1.11
```

Scan a CIDR network with a specified password dictionary:
```bash
python security_tool.py redis 192.168.1.0/24 -p common_redis_pass.txt
```

---

### 3. SSH Brute-force (`ssh`)

Scan a single host:
```bash
python security_tool.py ssh 192.168.1.12
```

---

### 4. Host Discovery (`host`)

Scan a class C network:
```bash
python security_tool.py host 192.168.1.0/24
```

---

### 5. Port Scan (`port`)

Scan specific ports:
```bash
python security_tool.py port 192.168.1.1 -p 80,443,8080
```

Scan a range of ports:
```bash
python security_tool.py port 192.168.1.1 -p 1-1024
```

---

### 6. Subdomain Scan (`subdomain`)

Scan a domain with the default dictionary:
```bash
python security_tool.py subdomain example.com
```

Scan with a custom dictionary:
```bash
python security_tool.py subdomain example.com -d custom_subs.txt
```

---

## Disclaimer

**This tool is intended for educational purposes and authorized security testing only. Unauthorized scanning of networks is illegal. The author is not responsible for any misuse or damage caused by this tool.**

---

## 中文说明

本工具使用子命令结构来调用不同功能。

### 1. MySQL 弱口令扫描 (`mysql`)

使用默认字典扫描单个主机：
```bash
python security_tool.py mysql 192.168.1.10
```

指定端口和字典文件，扫描一个IP范围：
```bash
python security_tool.py mysql 192.168.1.1-100 -P 3307 -u my_users.txt -p my_pass.txt
```

---

### 2. Redis 弱口令扫描 (`redis`)

扫描单个主机：
```bash
python security_tool.py redis 192.168.1.11
```

指定密码字典，扫描一个C段网络：
```bash
python security_tool.py redis 192.168.1.0/24 -p common_redis_pass.txt
```

---

### 3. SSH 弱口令扫描 (`ssh`)

扫描单个主机：
```bash
python security_tool.py ssh 192.168.1.12
```

---

### 4. 主机发现 (`host`)

扫描一个C段网络：
```bash
python security_tool.py host 192.168.1.0/24
```

---

### 5. 端口扫描 (`port`)

扫描指定端口：
```bash
python security_tool.py port 192.168.1.1 -p 80,443,8080
```

扫描端口范围：
```bash
python security_tool.py port 192.168.1.1 -p 1-1024
```

---

### 6. 子域名扫描 (`subdomain`)

使用默认字典扫描域名：
```bash
python security_tool.py subdomain example.com
```

使用自定义字典进行扫描：
```bash
python security_tool.py subdomain example.com -d custom_subs.txt
```

---

## 免责声明

本工具仅用于教育目的和授权下的安全测试。未经授权扫描网络是违法的。对于因滥用或不当使用此程序而造成的任何损害，作者概不负责。
