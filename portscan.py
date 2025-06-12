# made by yours truly, unconnected
import socket
import subprocess
import platform
from concurrent.futures import ThreadPoolExecutor, as_completed
import re
from datetime import datetime

tcp_results = {}
udp_results = {}

def ping_host(ip):
    param = "-n" if platform.system().lower() == "windows" else "-c"
    command = ["ping", param, "1", ip]
    try:
        subprocess.check_output(command)
        print(f"{ip} - resolvable")
    except subprocess.CalledProcessError:
        print(f"{ip} - not resolvable")

def scan_tcp_port(ip, port, show_errors):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.5)
        try:
            result = sock.connect_ex((ip, port))
            if result == 0:
                print(f"TCP {port} - open")
                tcp_results.setdefault(ip, []).append(('TCP', port, 'open'))
                return True
            elif result == socket.timeout:
                print(f"TCP {port} - timed out")
            else:
                if hasattr(socket, 'errno') and result == socket.errno.ECONNREFUSED:
                    print(f"TCP {port} - closed")
                    tcp_results.setdefault(ip, []).append(('TCP', port, 'closed'))
                else:
                    if show_errors:
                        print(f"TCP {port} - error ({result})")
                    tcp_results.setdefault(ip, []).append(('TCP', port, f'error ({result})'))
        except socket.timeout:
            if show_errors:
                print(f"TCP {port} - timed out")
            tcp_results.setdefault(ip, []).append(('TCP', port, 'timeout'))
        except Exception as e:
            if show_errors:
                print(f"TCP {port} - error ({e})")
            tcp_results.setdefault(ip, []).append(('TCP', port, f'exception ({e})'))
    return False

def scan_udp_port(ip, port, show_errors):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(0.5)
        try:
            sock.sendto(b"test", (ip, port))
            data, _ = sock.recvfrom(1024)
            print(f"UDP {port} - open")
            udp_results.setdefault(ip, []).append(('UDP', port, 'open/filtered'))
            return True
        except socket.timeout:
            print(f"UDP {port} - no response (filtered or no service)")
            udp_results.setdefault(ip, []).append(('UDP', port, 'filtered'))
        except socket.error as e:
            if hasattr(e, 'errno'):
                if e.errno == getattr(socket, 'ECONNREFUSED', None):
                    print(f"UDP {port} - port is closed (connection refused)")
                    udp_results.setdefault(ip, []).append(('UDP', port, 'closed'))
                elif e.errno == getattr(socket, 'EHOSTUNREACH', None):
                    print(f"UDP {port} - host unreachable")
                    udp_results.setdefault(ip, []).append(('UDP', port, 'unreachable'))
                elif e.errno == getattr(socket, 'ENETUNREACH', None):
                    print(f"UDP {port} - network unreachable")
                    udp_results.setdefault(ip, []).append(('UDP', port, 'network unreachable'))
                elif e.errno == getattr(socket, 'EPERM', None):
                    print(f"UDP {port} - operation not permitted (firewall or permissions)")
                    udp_results.setdefault(ip, []).append(('UDP', port, 'not permitted'))
                else:
                    if show_errors:
                        print(f"UDP {port} - socket error ({e})")
            else:
                if show_errors:
                    print(f"UDP {port} - socket error ({e})")
        except Exception as e:
            if show_errors:
                print(f"UDP {port} - unexpected error ({e})")
    return False

def is_valid_ip(address):
    pattern = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
    if pattern.match(address):
        parts = address.split('.')
        if all(0 <= int(part) <= 255 for part in parts):
            return True
    return False

def get_show_errors(protocol):
    while True:
        user_input = input(f"include errors for {protocol} scan? (true/false): ").strip().lower()
        if user_input in ['true', 'false']:
            return user_input == 'true'
        else:
            print("bad input - enter 'true' or 'false'")

def get_worker_count():
    default_workers = 100
    max_workers = 100
    while True:
        user_input = input(f"enter a number of worker threads (1-{max_workers}, default {default_workers}): ").strip()
        if not user_input:
            return default_workers
        elif user_input.isdigit():
            worker_count = int(user_input)
            if 1 <= worker_count <= max_workers:
                return worker_count
            else:
                print(f"bad input - enter a number between 1 and {max_workers}.")
        else:
            print("bad input - only positive integers are accepted")

def parse_port_range(prompt_message, default_start=0, default_end=65536):
    user_input = input(prompt_message).strip()
    if not user_input:
        return range(default_start, default_end)
    match = re.match(r'^(\d+)\s*-\s*(\d+)$', user_input)
    if match:
        start, end = int(match.group(1)), int(match.group(2))
        if 0 <= start <= end <= 65535:
            return range(start, end + 1)
        else:
            print("bad range - defaulting to 0-65535")
            return range(default_start, default_end)
    else:
        print("bad input - defaulting to 0-65535")
        return range(default_start, default_end)

def main():
    while True:
        target_input = input("host to scan: ").strip()

        if is_valid_ip(target_input):
            target_ip = target_input
            break
        else:
            try:
                print(f"resolving {target_input}")
                target_ip = socket.gethostbyname(target_input)
                print(f"{target_input} resolved to {target_ip}")
                break
            except socket.gaierror:
                print(f"bad input - '{target_input}' host must be domains or machine addresses (127.0.0.1/example.com)")

    print(f"resolving {target_ip}")
    ping_host(target_ip)

    show_tcp_errors = get_show_errors('TCP')
    show_udp_errors = get_show_errors('UDP')

    max_workers = get_worker_count()

    batch_size = max_workers

    tcp_port_range = parse_port_range("enter TCP port range (e.g., 20-80) or press Enter for default (0-65535): ", 0, 65535)
    udp_port_range = parse_port_range("enter UDP port range (e.g., 20-80) or press Enter for default (0-65535): ", 0, 65535)

    tcp_port_list = list(tcp_port_range)
    udp_port_list = list(udp_port_range)

    print("scanning TCP in batches")
    for i in range(0, len(tcp_port_list), batch_size):
        batch_ports = tcp_port_list[i:i+batch_size]
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [executor.submit(scan_tcp_port, target_ip, port, show_tcp_errors) for port in batch_ports]
            for future in as_completed(futures):
                pass

    print("scanning UDP in batches")
    for i in range(0, len(udp_port_list), batch_size):
        batch_ports = udp_port_list[i:i+batch_size]
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [executor.submit(scan_udp_port, target_ip, port, show_udp_errors) for port in batch_ports]
            for future in as_completed(futures):
                pass

    log_choice = input("log scan results? (true/false): ").strip().lower()
    if log_choice in ['true', 'false']:
        log_results(target_ip, tcp_results, udp_results)

def format_tcp_results(tcp_results):
    lines = ["--TCP--"]
    lines.append(f"{'machineaddress':<15} {'port':<6} {'status'}")
    lines.append("-" * 30)
    for ip, results in tcp_results.items():
        for proto, port, status in results:
            lines.append(f"{ip:<15} {port:<6} {status}")
    return "\n".join(lines)

def format_udp_results(udp_results):
    lines = ["--UDP--"]
    lines.append(f"{'machineaddress':<15} {'port':<6} {'status'}")
    lines.append("-" * 30)
    for ip, results in udp_results.items():
        for proto, port, status in results:
            lines.append(f"{ip:<15} {port:<6} {status}")
    return "\n".join(lines)
    
def log_results(target_ip, tcp_results, udp_results):
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    filename = f"portscan_{timestamp}.log"
    try:
        with open(filename, 'w') as f:
            f.write(f"scan results for {target_ip}\n")
            tcp_table = format_tcp_results(tcp_results)
            f.write(tcp_table + "\n")
            udp_table = format_udp_results(udp_results)
            f.write(udp_table + "\n")
        print(f"wrote {filename}")
    except Exception as e:
        print(f"couldn't write log file: {e}")

if __name__ == "__main__":
    main()
