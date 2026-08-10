import urllib.request
import base64
import re
import socket
import time
from typing import List, Tuple

# ------------------ Конфигурация ------------------
SOURCE_URL = "https://raw.githack.com/igareck/vpn-configs-for-russia/main/WHITE-CIDR-RU-all.txt"
TARGET_COUNT = 30
TIMEOUT = 3  # секунды на TCP-проверку
DELAY = 0.2  # задержка между проверками, чтобы не банили
GERMAN_TAGS = ["DE", "Germany", "Frankfurt", "de", "germany", "frankfurt"]  # регистронезависимые

# ------------------ Вспомогательные функции ------------------
def is_german(link: str) -> bool:
    """Проверяет, содержит ли ссылка признаки немецкого сервера."""
    link_lower = link.lower()
    return any(tag.lower() in link_lower for tag in GERMAN_TAGS)

def extract_host_port(link: str) -> Tuple[str, int]:
    """
    Извлекает хост и порт из vless-ссылки.
    Формат: vless://UUID@HOST:PORT?params...
    Возвращает (host, port) или (None, None) при ошибке.
    """
    match = re.search(r'vless://[^@]+@([^:]+):(\d+)', link)
    if match:
        return match.group(1), int(match.group(2))
    return None, None

def is_port_open(host: str, port: int, timeout: float = TIMEOUT) -> bool:
    """Проверяет, открыт ли TCP-порт на указанном хосте."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False

def is_vless_alive(link: str) -> bool:
    """Проверяет работоспособность VLESS-сервера через TCP-соединение."""
    host, port = extract_host_port(link)
    if host is None or port is None:
        return False
    return is_port_open(host, port)

def fetch_links_from_url(url: str) -> List[str]:
    """Загружает данные по URL и возвращает список строк, начинающихся с vless://."""
    try:
        with urllib.request.urlopen(url, timeout=10) as response:
            content = response.read().decode('utf-8', errors='ignore')
            lines = content.splitlines()
            return [line.strip() for line in lines if line.strip().startswith('vless://')]
    except Exception as e:
        print(f"Ошибка загрузки источника: {e}")
        return []

def get_working_links(all_links: List[str], target: int = TARGET_COUNT) -> List[str]:
    """
    Возвращает список рабочих ссылок длиной до target.
    Сначала собирает все немецкие рабочие, потом добивает другими рабочими.
    """
    german_working = []
    other_working = []

    print(f"Всего найдено ссылок: {len(all_links)}")
    for i, link in enumerate(all_links):
        # Проверяем только если ещё не набрали нужное количество
        if len(german_working) >= target:
            break
        # Определяем немецкий ли
        is_de = is_german(link)
        # Проверяем работоспособность
        if is_vless_alive(link):
            if is_de:
                german_working.append(link)
                print(f"✓ Найден рабочий немецкий #{len(german_working)}")
            else:
                other_working.append(link)
                print(f"✓ Найден рабочий другой регион (всего {len(other_working)})")
        time.sleep(DELAY)  # пауза, чтобы не перегружать серверы

    # Формируем финальный список
    result = german_working[:target]
    if len(result) < target:
        needed = target - len(result)
        result.extend(other_working[:needed])
        print(f"Добавлено {len(other_working[:needed])} серверов из других регионов")

    print(f"Итоговое количество ключей: {len(result)}")
    return result

def save_subscription(links: List[str], txt_path: str, b64_path: str):
    """Сохраняет список ссылок в два файла: plain text и Base64."""
    # Обычный текст (каждая ссылка с новой строки)
    with open(txt_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(links))

    # Base64 (строки, объединённые через \n, затем кодировка)
    combined = '\n'.join(links)
    b64_bytes = base64.b64encode(combined.encode('utf-8'))
    with open(b64_path, 'wb') as f:
        f.write(b64_bytes)

    print(f"Сохранено: {txt_path} ({len(links)} строк), {b64_path}")

# ------------------ Основная функция ------------------
def main():
    print("=== Генератор подписки VLESS (рабочие ключи) ===")
    # 1. Загрузка ссылок
    all_links = fetch_links_from_url(SOURCE_URL)
    if not all_links:
        print("Не удалось получить ссылки. Завершение.")
        return

    # 2. Отбор рабочих
    working_links = get_working_links(all_links, TARGET_COUNT)

    # 3. Сохранение
    save_subscription(working_links, "sub_de.txt", "sub_de_b64.txt")
    print("Готово!")

if __name__ == "__main__":
    main()
