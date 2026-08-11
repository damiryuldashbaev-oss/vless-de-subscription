#!/usr/bin/env python3
"""
Генератор подписки с двухэтапной проверкой.
Выбирает только немецкие (Germany) VLESS-серверы с портом 443.
Если не найдено ни одного Xray-рабочего ключа, используем TCP-проверенные (запасной вариант).
"""

import urllib.request
import base64
import re
import json
import subprocess
import tempfile
import time
import socket
import os
import requests
from typing import List, Tuple, Optional

# ------------------ Конфигурация ------------------
SOURCE_URLS = [
    "https://raw.githack.com/igareck/vpn-configs-for-russia/main/Vless-Reality-White-Lists-Rus-Mobile.txt"
]
TARGET_COUNT = 15
TCP_TIMEOUT = 1.5
XRAY_TIMEOUT = 5
DELAY_BETWEEN = 0.3
DELAY_BETWEEN_XRAY = 0.5
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
TEST_URL = "https://api.ipify.org?format=json"

# ------------------ TCP-проверка ------------------
def extract_host_port(link: str) -> Tuple[Optional[str], Optional[int]]:
    match = re.search(r'vless://[^@]+@([^:]+):(\d+)', link)
    if match:
        return match.group(1), int(match.group(2))
    return None, None

def is_port_open(host: str, port: int, timeout: float = TCP_TIMEOUT) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except:
        return False

def is_vless_tcp_alive(link: str) -> bool:
    host, port = extract_host_port(link)
    if host is None or port is None:
        return False
    return is_port_open(host, port)

# ------------------ Проверка через Xray ------------------
def get_my_ip() -> str:
    try:
        r = requests.get(TEST_URL, timeout=5)
        data = r.json()
        return data.get('ip', '')
    except Exception as e:
        print(f"Не удалось получить реальный IP: {e}")
        return ''

def is_desired(link: str) -> bool:
    """Проверяет, является ли ссылка немецкой и имеет порт 443."""
    host, port = extract_host_port(link)
    return port == 443 and 'germany' in link.lower()

def parse_vless_link(link: str) -> Optional[dict]:
    if not link.startswith('vless://'):
        return None
    body = link[8:]
    if '@' not in body:
        return None
    uuid_part, rest = body.split('@', 1)
    if '?' in rest:
        host_port, query = rest.split('?', 1)
    else:
        host_port, query = rest, ''
    if ':' not in host_port:
        return None
    host, port_str = host_port.split(':', 1)
    try:
        port = int(port_str)
    except:
        return None
    params = {}
    if query:
        for item in query.split('&'):
            if '=' in item:
                k, v = item.split('=', 1)
                params[k] = v
    return {'uuid': uuid_part, 'host': host, 'port': port, 'params': params}

def build_xray_config(vless_config: dict) -> dict:
    uuid = vless_config['uuid']
    host = vless_config['host']
    port = vless_config['port']
    params = vless_config.get('params', {})

    outbound = {
        "protocol": "vless",
        "settings": {
            "vnext": [{
                "address": host,
                "port": port,
                "users": [{
                    "id": uuid,
                    "encryption": params.get('encryption', 'none'),
                    "flow": params.get('flow', '')
                }]
            }]
        },
        "streamSettings": {
            "network": params.get('type', 'tcp'),
            "security": params.get('security', 'none'),
            "tlsSettings": {},
            "wsSettings": {},
            "grpcSettings": {}
        }
    }

    network = outbound['streamSettings']['network']
    if network == 'ws':
        outbound['streamSettings']['wsSettings'] = {
            "path": params.get('path', '/'),
            "headers": {"Host": params.get('host', host)}
        }
    elif network == 'grpc':
        outbound['streamSettings']['grpcSettings'] = {
            "serviceName": params.get('serviceName', '')
        }
    if params.get('security') == 'tls':
        outbound['streamSettings']['security'] = 'tls'
        outbound['streamSettings']['tlsSettings']['serverName'] = params.get('sni', host)

    inbound = {
        "listen": "127.0.0.1",
        "port": 1080,
        "protocol": "socks",
        "settings": {"auth": "noauth", "udp": True}
    }
    return {"log": {"loglevel": "warning"}, "inbounds": [inbound], "outbounds": [outbound]}

def test_vless_xray(link: str) -> bool:
    parsed = parse_vless_link(link)
    if not parsed:
        print("  [Xray] Не удалось распарсить ссылку")
        return False

    config = build_xray_config(parsed)
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json.dump(config, f, indent=2)
        config_path = f.name

    proc = None
    try:
        proc = subprocess.Popen(
            ['xray', 'run', '-c', config_path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        time.sleep(1.2)
        proxies = {'http': 'socks5://127.0.0.1:1080', 'https': 'socks5://127.0.0.1:1080'}
        r = requests.get(TEST_URL, proxies=proxies, timeout=XRAY_TIMEOUT)
        ip = r.json().get('ip', '')
        real_ip = get_my_ip()
        if ip and ip != real_ip:
            return True
        else:
            if not ip:
                print("  [Xray] Не удалось получить IP через прокси")
            else:
                print(f"  [Xray] IP через прокси {ip} совпадает с реальным {real_ip}?")
    except Exception as e:
        print(f"  [Xray] Ошибка: {e}")
        return False
    finally:
        if proc:
            proc.terminate()
            try:
                proc.wait(timeout=2)
            except:
                proc.kill()
        try:
            os.unlink(config_path)
        except:
            pass
    return False

# ------------------ Загрузка ссылок ------------------
def fetch_links_from_url(url: str) -> List[str]:
    req = urllib.request.Request(url, headers={'User-Agent': USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            content = resp.read().decode('utf-8', errors='ignore')
            return [line.strip() for line in content.splitlines() if line.strip().startswith('vless://')]
    except Exception as e:
        print(f"Ошибка загрузки {url}: {e}")
        return []

def fetch_links_from_sources(urls: List[str]) -> List[str]:
    for url in urls:
        print(f"Загрузка {url} ...")
        links = fetch_links_from_url(url)
        if links:
            print(f"Получено {len(links)} ссылок")
            return links
    return []

# ------------------ Основная логика ------------------
def get_working_links(all_links: List[str]) -> List[str]:
    # Этап 1: TCP-фильтр (только желаемые: Германия + порт 443)
    tcp_passed_desired = []
    print("Этап 1: TCP-проверка (только Germany:443)...")
    for link in all_links:
        if is_desired(link) and is_vless_tcp_alive(link):
            tcp_passed_desired.append(link)
        time.sleep(DELAY_BETWEEN)
    print(f"TCP-проверка: желаемых (Germany:443) – {len(tcp_passed_desired)}")

    if not tcp_passed_desired:
        print("Нет ссылок, прошедших TCP-проверку. Завершение.")
        return []

    # Этап 2: Xray точная проверка
    working = []
    print("Этап 2: Xray-проверка (точная)...")
    for link in tcp_passed_desired:
        if len(working) >= TARGET_COUNT:
            break
        print(f"  Проверка #{len(working)+1} ...", end=' ', flush=True)
        if test_vless_xray(link):
            working.append(link)
            print("✅")
        else:
            print("❌")
        time.sleep(DELAY_BETWEEN_XRAY)

    print(f"Найдено Xray-рабочих (Germany:443): {len(working)}")
    if working:
        return working
    else:
        # Запасной вариант: используем TCP-проверенные (тоже только Germany:443)
        print("ВНИМАНИЕ: Xray не нашёл рабочих ключей. Использую TCP-проверенные (Germany:443) как запасной вариант.")
        return tcp_passed_desired[:TARGET_COUNT]

def save_subscription(links: List[str], txt_path: str, b64_path: str):
    with open(txt_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(links))
    combined = '\n'.join(links)
    b64_bytes = base64.b64encode(combined.encode('utf-8'))
    with open(b64_path, 'wb') as f:
        f.write(b64_bytes)
    print(f"Сохранено: {txt_path} ({len(links)} строк), {b64_path}")

def main():
    print("=== Генератор подписки VLESS (только Germany :443) ===")
    real_ip = get_my_ip()
    print(f"Ваш реальный IP: {real_ip}")
    all_links = fetch_links_from_sources(SOURCE_URLS)
    if not all_links:
        print("Не удалось загрузить ссылки. Завершение.")
        return

    working = get_working_links(all_links)
    if not working:
        print("Не найден ни один рабочий ключ (даже TCP). Сохраняем пустой список.")
    save_subscription(working, "sub_de.txt", "sub_de_b64.txt")
    print("Готово!")

if __name__ == "__main__":
    main()
