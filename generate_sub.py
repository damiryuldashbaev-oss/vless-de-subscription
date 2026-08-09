import urllib.request
import urllib.parse
import base64
import json
import re

# Стабильные и живые источники VLESS/Xray
SOURCES = [
    # Мощный обновляемый агрегатор
    "https://raw.githubusercontent.com/barry-far/V2ray-Configs/main/Sub1.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-Configs/main/Sub2.txt",
    # Резервные стабильные зеркала
    "https://raw.githubusercontent.com/vysecurity/v2ray-collector/main/v2ray.txt",
    "https://raw.githubusercontent.com/mftb-group/v2ray-configs/main/all.txt"
]

MAX_SERVERS = 15

def fetch_raw_vless():
    links = []
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    }
    
    for src in SOURCES:
        try:
            req = urllib.request.Request(src, headers=headers)
            with urllib.request.urlopen(req, timeout=15) as resp:
                content = resp.read().decode('utf-8', errors='ignore').strip()
                
                # Попытка декодировать Base64, если подписка зашифрована
                try:
                    decoded = base64.b64decode(content).decode('utf-8', errors='ignore')
                    if "vless://" in decoded or "vmess://" in decoded:
                        content = decoded
                except Exception:
                    pass
                
                for line in content.splitlines():
                    line = line.strip()
                    if line.startswith("vless://"):
                        links.append(line)
        except Exception as e:
            print(f"[-] Пропущен источник {src}: {e}")
            
    return links

def extract_host(vless_link):
    """Извлекает хост/IP из vless-ссылки"""
    try:
        after_at = vless_link.split("@")[1]
        host_port = after_at.split("?")[0].split("#")[0]
        host = host_port.split(":")[0]
        return host
    except Exception:
        return None

def is_germany(host, tag):
    """Проверяет принадлежность к Германии"""
    tag_decoded = urllib.parse.unquote(tag)
    
    # Регулярка для поисков немецких гео-тегов
    de_pattern = r'(🇩🇪|DE\b|Germany|Frankfurt|Nuremberg|Falkenstein|Hessen|Berlin)'
    if re.search(de_pattern, tag_decoded, re.IGNORECASE):
        return True
        
    if host and host.endswith(".de"):
        return True

    return False

def main():
    print("Собираем VLESS ссылки...")
    raw_links = fetch_raw_vless()
    print(f"Всего получено VLESS: {len(raw_links)}")

    de_servers = []
    seen = set()

    # 1. Сначала отбираем строго немецкие серверы
    for link in raw_links:
        if link in seen:
            continue
            
        host = extract_host(link)
        tag = link.split("#")[-1] if "#" in link else ""
        
        if is_germany(host, tag):
            seen.add(link)
            de_servers.append(link)
            if len(de_servers) >= MAX_SERVERS:
                break

    print(f"Найдено немецких серверов: {len(de_servers)}")

    # 2. Если немецких не хватило, дополняем обычными VLESS, чтобы подписка НЕ была пустой
    if len(de_servers) < MAX_SERVERS:
        print("Добираем резервные VLESS для заполнения списка...")
        for link in raw_links:
            if link not in seen:
                seen.add(link)
                de_servers.append(link)
                if len(de_servers) >= MAX_SERVERS:
                    break

    print(f"Итого серверов в файле: {len(de_servers)}")

    # Запись открытого списка
    plain_text = "\n".join(de_servers)
    with open("sub_de.txt", "w", encoding="utf-8") as f:
        f.write(plain_text)

    # Запись Base64 подписки
    b64_text = base64.b64encode(plain_text.encode('utf-8')).decode('utf-8')
    with open("sub_de_b64.txt", "w", encoding="utf-8") as f:
        f.write(b64_text)
        
    print("Готово! Файлы успешно обновлены.")

if __name__ == "__main__":
    main()
