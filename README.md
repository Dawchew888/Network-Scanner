# Network Scanner 网络扫描工具

[English](#english) | [中文](#中文)

## English

### Description

Network Scanner is a comprehensive network security testing tool that integrates multiple scanning functionalities. This tool is designed for network security professionals and system administrators to perform security assessments and vulnerability scanning.

### Features

- 🔍 Port Scanning
- 🖥️ Host Discovery
- 🔑 Service Brute Force
  - MySQL weak password scanning
  - Redis unauthorized access and weak password detection
  - SSH weak password scanning
- 🌐 Subdomain Scanning

### Prerequisites

```bash
Python 3.6+
```

### Installation

1. Clone the repository:
```bash
git clone https://github.com/Dawchew888/Network-Scanner.git
cd Network-Scanner
```

2. Install required dependencies:
```bash
pip install -r requirements.txt
```

Required packages:
- paramiko
- pymysql
- redis
- requests

### Usage

The tool provides several scanning modules that can be used independently:

1. **Port Scanning**
```bash
python scan-tools.py port -h [TARGET] -p [PORTS]
# Example: Scan ports 80-1000
python scan-tools.py port 192.168.1.1 -p 80-1000
```

2. **Host Discovery**
```bash
python scan-tools.py host [NETWORK]
# Example: Scan entire subnet
python scan-tools.py host 192.168.1.0/24
```

3. **MySQL Weak Password Scanning**
```bash
python scan-tools.py mysql [TARGET] -P [PORT] -u [USER_DICT] -p [PASS_DICT]
# Example:
python scan-tools.py mysql 192.168.1.1 -P 3306
```

4. **Redis Security Scanning**
```bash
python scan-tools.py redis [TARGET] -P [PORT] -p [PASS_DICT]
# Example:
python scan-tools.py redis 192.168.1.1 -P 6379
```

5. **SSH Weak Password Scanning**
```bash
python scan-tools.py ssh [TARGET] -P [PORT] -u [USER_DICT] -p [PASS_DICT]
# Example:
python scan-tools.py ssh 192.168.1.1 -P 22
```

6. **Subdomain Scanning**
```bash
python scan-tools.py subdomain [DOMAIN] -d [SUBDOMAIN_DICT]
# Example:
python scan-tools.py subdomain example.com
```

### Notes

- This tool is for authorized security testing only
- Please ensure you have proper authorization before scanning any targets
- Some features might require root/administrator privileges

---

## 中文

### 项目描述

Network Scanner 是一个综合性的网络安全测试工具，集成了多种扫描功能。该工具专为网络安全专业人员和系统管理员设计，用于执行安全评估和漏洞扫描。

### 功能特点

- 🔍 端口扫描
- 🖥️ 主机发现
- 🔑 服务弱口令检测
  - MySQL 弱口令扫描
  - Redis 未授权访问和弱口令检测
  - SSH 弱口令扫描
- 🌐 子域名扫描

### 环境要求

```bash
Python 3.6+
```

### 安装说明

1. 克隆仓库：
```bash
git clone https://github.com/Dawchew888/Network-Scanner.git
cd Network-Scanner
```

2. 安装依赖：
```bash
pip install -r requirements.txt
```

所需包：
- paramiko
- pymysql
- redis
- requests

### 使用教程

该工具提供了多个可独立使用的扫描模块：

1. **端口扫描**
```bash
python scan-tools.py port -h [目标] -p [端口范围]
# 示例：扫描80-1000端口
python scan-tools.py port 192.168.1.1 -p 80-1000
```

2. **主机发现**
```bash
python scan-tools.py host [网段]
# 示例：扫描整个子网
python scan-tools.py host 192.168.1.0/24
```

3. **MySQL 弱口令扫描**
```bash
python scan-tools.py mysql [目标] -P [端口] -u [用户名字典] -p [密码字典]
# 示例：
python scan-tools.py mysql 192.168.1.1 -P 3306
```

4. **Redis 安全扫描**
```bash
python scan-tools.py redis [目标] -P [端口] -p [密码字典]
# 示例：
python scan-tools.py redis 192.168.1.1 -P 6379
```

5. **SSH 弱口令扫描**
```bash
python scan-tools.py ssh [目标] -P [端口] -u [用户名字典] -p [密码字典]
# 示例：
python scan-tools.py ssh 192.168.1.1 -P 22
```

6. **子域名扫描**
```bash
python scan-tools.py subdomain [域名] -d [子域名字典]
# 示例：
python scan-tools.py subdomain example.com
```

### 注意事项

- 本工具仅用于授权的安全测试
- 使用前请确保已获得目标系统的授权
- 某些功能可能需要 root/管理员权限
