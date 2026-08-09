import urllib.request
import base64
import json
import re

# Стабильные публичные агрегаторы VLESS / V2Ray
SOURCES = [
    "https://raw.githubusercontent.com/yebekhe/TelegramV2rayCollector/main/sub/base64",
    "https://raw.githubusercontent.com/barry-far/V2ray-Configs/main/All_Configs_Sub.txt",
    "https://raw.githubusercontent.com/mftb-group/v2ray-configs/main/v2ray.txt",
    "https://raw.githubusercontent.com/sub-sharing/v2ray-sub/main/subscriptions/v2ray/base64"
]

MAX_SERVERS = 15

def decode_content(content):
    """Декодирует Base64, если источник зашифрован"""
    content = content.strip()
    try:
        # Проверяем, похоже ли на Base64
        decoded = base64.b64decode(content).decode('utf-8', errors='ignore')
        if "vless://" in decoded or "vmess://" in decoded:
            return decoded
    except Exception:
        pass
    return content

def fetch_configs():
    raw_links = []
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
    
    for src in SOURCES:
        try:
            req = urllib.request.Request(src, headers=headers)
            with urllib.request.urlopen(req, timeout=12) as response:
                content = response.read().decode('utf-8', errors='ignore')
                decoded_content = decode_content(content)
                
                for line in decoded_content.splitlines():
                    line = line.strip()
                    if line.startswith("vless://"):
                        raw_links.append(line)
        except Exception as e:
            print(f"Ошибка при скачивании {src}: {e}")
            
    return raw_links

def is_germany_server(link):
    """Проверяет, относится ли сервер к Германии"""
    # 1. Проверка по тегу/названию в конце ссылки (#DE, #Germany и т.д.)
    tag = link.split("#")[-1] if "#" in link else ""
    tag_decoded = urllib.parse.unquote(tag)
    
    de_keywords = r'(🇩🇪|DE|Germany|Germany|Германия|Frankfurt|Nuremberg|Falkenstein)'
    if re.search(de_keywords, tag_decoded, re.IGNORECASE):
        return True
        
    return False

def main():
    print("Начинаем сбор VLESS-ссылок...")
    raw_links = fetch_configs()
    print(f"Всего получено VLESS ссылок: {len(raw_links)}")

    de_servers = []
    seen = set()

    for link in raw_links:
        if link not in seen and is_germany_server(link):
            seen.add(link)
            de_servers.append(link)
            if len(de_servers) >= MAX_SERVERS:
                break

    print(f"Найдено подходящих немецких серверов: {len(de_servers)}")

    if not de_servers:
        print("Внимание: немецкие серверы не найдены. Создаём резервный список из первых доступных VLESS.")
        # Если немецких не нашлось, берём любые 5 VLESS, чтобы подписка не была пустой
        de_servers = list(dict.fromkeys(raw_links))[:5]

    plain_text = "\n".join(de_servers)
    
    # 1. Сохраняем в обычный txt
    with open("sub_de.txt", "w", encoding="utf-8") as f:
        f.write(plain_text)
        
    # 2. Сохраняем в base64 txt
    b64_text = base64.b64encode(plain_text.encode('utf-8')).decode('utf-8')
    with open("sub_de_b64.txt", "w", encoding="utf-8") as f:
        f.write(b64_text)
        
    print("Файлы подписки успешно обновлены!")

if __name__ == "__main__":
    main()
