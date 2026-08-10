#!/usr/bin/env python3
"""
Генератор подписки с реальной проверкой VLESS-серверов через Xray-core.
Отбирает до 30 рабочих ключей (приоритет немецким) и сохраняет в plain text и Base64.
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
    "https://raw.githack.com/igareck/vpn-configs-for-russia/main/WHITE-CIDR-RU-all.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/WHITE-CIDR-RU-all.txt"
]
TARGET_COUNT = 30
TEST_URL = "https://api.ipify.org?format=json"
TIMEOUT = 8  # таймаут на проверку одного ключа (сек)
DELAY = 1    # пауза между запусками Xray
GERMAN_TAGS = ["DE", "Germany", "Frankfurt", "de", "germany", "frankfurt"]
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

# ------------------ Вспомогательные функции ------------------
def get_my_ip() -> str:
    """Возвращает реальный внешний IP (без прокси)."""
    try:
        r = requests.get(TEST_URL, timeout=5)
        return r.json().get('ip', '')
    except:
        return ''

def is_german(link: str) -> bool:
    link_lower = link.lower()
    return any(tag.lower() in link_lower for tag in GERMAN_TAGS)

def parse_vless_link(link: str) -> Optional[dict]:
    """
    Разбирает vless:// ссылку и возвращает словарь с параметрами.
    Формат: vless://UUID@HOST:PORT?params
    """
    # Убираем префикс
    if not link.startswith('vless://'):
        return None
    body = link[8:]  # после vless://
    # Разделяем на часть до @ и после
    if '@' not in body:
        return None
    uuid_part, rest = body.split('@', 1)
    # rest содержит host:port?params
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
    # Парсим параметры query
    params = {}
    if query:
        for item in query.split('&'):
            if '=' in item:
                k, v = item.split('=', 1)
                params[k] = v
    # Формируем конфиг
    config = {
        'uuid': uuid_part,
        'host': host,
        'port': port,
        'params': params
    }
    return config

def build_xray_config(vless_config: dict) -> dict:
    """
    Создаёт JSON-конфиг для Xray с inbounds (SOCKS5) и outbound (VLESS).
    """
    uuid = vless_config['uuid']
    host = vless_config['host']
    port = vless_config['port']
    params = vless_config.get('params', {})

    # Базовый outbound
    outbound = {
        "protocol": "vless",
        "settings": {
            "vnext": [
                {
                    "address": host,
                    "port": port,
                    "users": [
                        {
                            "id": uuid,
                            "encryption": params.get('encryption', 'none'),
                            "flow": params.get('flow', '')
                        }
                    ]
                }
            ]
        },
        "streamSettings": {
            "network": params.get('type', 'tcp'),
            "security": params.get('security', 'none'),
            "tlsSettings": {},
            "wsSettings": {},
            "grpcSettings": {}
        }
    }

    # Настройка транспорта
    network = outbound['streamSettings']['network']
    if network == 'ws':
        outbound['streamSettings']['wsSettings'] = {
            "path": params.get('path', '/'),
            "headers": {
                "Host": params.get('host', host)
            }
        }
    elif network == 'grpc':
        outbound['streamSettings']['grpcSettings'] = {
            "serviceName": params.get('serviceName', '')
        }
    elif network == 'tcp' and 'security' in params and params['security'] == 'tls':
        outbound['streamSettings']['tlsSettings'] = {
            "serverName": params.get('sni', host),
            "allowInsecure": False
        }

    if params.get('security') == 'tls':
        outbound['streamSettings']['security'] = 'tls'
        outbound['streamSettings']['tlsSettings']['serverName'] = params.get('sni', host)

    # Inbounds (SOCKS5 на локальном порту)
    inbound = {
        "listen": "127.0.0.1",
        "port": 1080,
        "protocol": "socks",
        "settings": {
            "auth": "noauth",
            "udp": True
        }
    }

    full_config = {
        "log": {"loglevel": "warning"},
        "inbounds": [inbound],
        "outbounds": [outbound]
    }
    return full_config

def test_vless_link(link: str) -> bool:
    """
    Проверяет, работает ли VLESS-ссылка, запуская Xray и делая запрос через SOCKS5.
    Возвращает True, если удалось получить внешний IP через прокси и он отличается от реального.
    """
    parsed = parse_vless_link(link)
    if not parsed:
        return False

    config = build_xray_config(parsed)

    # Создаём временный файл конфига
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json.dump(config, f, indent=2)
        config_path = f.name

    # Запускаем Xray
    proc = None
    try:
        proc = subprocess.Popen(
            ['xray', 'run', '-c', config_path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        # Даём время на запуск
        time.sleep(1.5)

        # Проверяем через SOCKS5
        proxies = {
            'http': 'socks5://127.0.0.1:1080',
            'https': 'socks5://127.0.0.1:1080'
        }
        try:
            r = requests.get(TEST_URL, proxies=proxies, timeout=TIMEOUT)
            ip = r.json().get('ip', '')
            # Если IP получен и не равен нашему реальному IP – считаем успехом
            if ip and ip != get_my_ip():
                return True
        except:
            return False
        finally:
            # Убиваем процесс
            if proc:
                proc.terminate()
                proc.wait(timeout=2)
    except Exception:
        return False
    finally:
        # Удаляем конфиг
        try:
            os.unlink(config_path)
        except:
            pass
        if proc and proc.poll() is None:
            proc.kill()
            proc.wait()
    return False

def fetch_links_from_url(url: str) -> List[str]:
    req = urllib.request.Request(url, headers={'User-Agent': USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            content = resp.read().decode('utf-8', errors='ignore')
            lines = content.splitlines()
            return [line.strip() for line in lines if line.strip().startswith('vless://')]
    except Exception as e:
        print(f"Ошибка загрузки {url}: {e}")
        return []

def fetch_links_from_sources(urls: List[str]) -> List[str]:
    for url in urls:
        print(f"Пытаемся загрузить {url}")
        links = fetch_links_from_url(url)
        if links:
            print(f"Загружено {len(links)} ссылок")
            return links
    return []

def get_working_links(all_links: List[str], target: int = TARGET_COUNT) -> List[str]:
    """
    Последовательно проверяет ссылки, начиная с немецких.
    Возвращает список рабочих ссылок (до target).
    """
    # Разделяем на немецкие и остальные
    german = []
    other = []
    for link in all_links:
        if is_german(link):
            german.append(link)
        else:
            other.append(link)

    working = []
    # Сначала проверяем немецкие
    for link in german:
        if len(working) >= target:
            break
        print(f"Проверка немецкого #{len(working)+1}...")
        if test_vless_link(link):
            working.append(link)
            print(f"  ✅ Рабочий немецкий ({len(working)}/{target})")
        else:
            print("  ❌ Не работает")
        time.sleep(DELAY)

    # Если не хватает, проверяем остальные
    if len(working) < target:
        needed = target - len(working)
        for link in other:
            if len(working) >= target:
                break
            print(f"Проверка другого региона #{len(working)+1}...")
            if test_vless_link(link):
                working.append(link)
                print(f"  ✅ Рабочий другой ({len(working)}/{target})")
            else:
                print("  ❌ Не работает")
            time.sleep(DELAY)

    print(f"Итоговое количество рабочих ключей: {len(working)}")
    return working

def save_subscription(links: List[str], txt_path: str, b64_path: str):
    with open(txt_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(links))
    combined = '\n'.join(links)
    b64_bytes = base64.b64encode(combined.encode('utf-8'))
    with open(b64_path, 'wb') as f:
        f.write(b64_bytes)
    print(f"Сохранено: {txt_path} ({len(links)} строк), {b64_path}")

def main():
    print("=== Генератор подписки с реальной проверкой VLESS (Xray) ===")
    all_links = fetch_links_from_sources(SOURCE_URLS)
    if not all_links:
        print("Не удалось загрузить ссылки. Завершение.")
        return

    working = get_working_links(all_links, TARGET_COUNT)
    if not working:
        print("Не найден ни один рабочий ключ. Сохраняем пустой список.")
    save_subscription(working, "sub_de.txt", "sub_de_b64.txt")
    print("Готово!")

if __name__ == "__main__":
    main()
