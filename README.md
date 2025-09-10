Network Scanner v0.1English | 中文EnglishA versatile network scanning tool written in Python.About The ProjectNetwork Scanner is a command-line tool designed for network reconnaissance and security auditing. It integrates multiple scanning modules into one convenient script, making it easy to perform tasks like host discovery, port scanning, and brute-force attacks against common services.FeaturesService Brute-forcing: MySQL, Redis, SSH.Host Discovery: PING-based network host scanning.Port Scanning: Scans for open ports on target hosts.Subdomain Enumeration: Finds subdomains for a given domain.Flexible Target Specification: Supports single IPs, IP ranges (e.g., 192.168.1.1-100), and CIDR notation (e.g., 192.168.1.0/24).Getting StartedPrerequisitesPython 3.6+InstallationClone the repository or download the files.Install the required Python libraries:pip install pymysql redis paramiko requests

UsageThe tool uses a command-based structure.1. MySQL Brute-force (mysql)# Scan a single host with default dictionaries

python security\_tool.py mysql 192.168.1.10



\# Scan an IP range with a specified port and dictionaries

python security\_tool.py mysql 192.168.1.1-100 -P 3307 -u my\_users.txt -p my\_pass.txt

2\. Redis Brute-force (redis)# Scan a single host

python security\_tool.py redis 192.168.1.11



\# Scan a CIDR network with a specified password dictionary

python security\_tool.py redis 192.168.1.0/24 -p common\_redis\_pass.txt

3\. SSH Brute-force (ssh)# Scan a single host

python security\_tool.py ssh 192.168.1.12

4\. Host Discovery (host)# Scan a class C network

python security\_tool.py host 192.168.1.0/24

5\. Port Scan (port)# Scan specific ports

python security\_tool.py port 192.168.1.1 -p 80,443,8080



\# Scan a range of ports

python security\_tool.py port 192.168.1.1 -p 1-1024

6\. Subdomain Scan (subdomain)# Scan a domain with the default dictionary

python security\_tool.py subdomain example.com



\# Scan with a custom dictionary

python security\_tool.py subdomain example.com -d custom\_subs.txt

DisclaimerThis tool is intended for educational purposes and authorized security testing only. Unauthorized scanning of networks is illegal. The author is not responsible for any misuse or damage caused by this program.中文一款基于 Python 的多功能网络扫描工具。关于项目Network Scanner 是一款为网络侦察和安全审计而设计的命令行工具。它将多个扫描模块集成到一个便捷的脚本中，可以轻松执行主机发现、端口扫描以及针对常见服务的弱口令爆破等任务。功能特性服务爆破: 支持 MySQL、Redis、SSH。主机发现: 基于 PING 的网络存活主机扫描。端口扫描: 扫描目标主机开放的端口。子域名枚举: 发现指定域名的子域名。灵活的目标格式: 支持单个IP、IP范围 (如 192.168.1.1-100) 和 CIDR 地址块 (如 192.168.1.0/24)。开始使用环境要求Python 3.6+安装依赖克隆仓库或下载项目文件。安装所需的 Python 库:pip install pymysql redis paramiko requests

使用方法本工具使用子命令结构来调用不同功能。1. MySQL 弱口令扫描 (mysql)# 使用默认字典扫描单个主机

python security\_tool.py mysql 192.168.1.10



\# 指定端口和字典文件，扫描一个IP范围

python security\_tool.py mysql 192.168.1.1-100 -P 3307 -u my\_users.txt -p my\_pass.txt

2\. Redis 弱口令扫描 (redis)# 扫描单个主机

python security\_tool.py redis 192.168.1.11



\# 指定密码字典，扫描一个C段网络

python security\_tool.py redis 192.168.1.0/24 -p common\_redis\_pass.txt

3\. SSH 弱口令扫描 (ssh)# 扫描单个主机

python security\_tool.py ssh 192.168.1.12

4\. 主机发现 (host)# 扫描一个C段网络

python security\_tool.py host 192.168.1.0/24

5\. 端口扫描 (port)# 扫描指定端口

python security\_tool.py port 192.168.1.1 -p 80,443,8080



\# 扫描端口范围

python security\_tool.py port 192.168.1.1 -p 1-1024

6\. 子域名扫描 (subdomain)# 使用默认字典扫描域名

python security\_tool.py subdomain example.com



\# 使用自定义字典进行扫描

python security\_tool.py subdomain example.com -d custom\_subs.txt

免责声明本工具仅用于教育目的和授权下的安全测试。未经授权扫描网络是违法的。对于因滥用或不当使用此程序而造成的任何损害，作者概不负责。

