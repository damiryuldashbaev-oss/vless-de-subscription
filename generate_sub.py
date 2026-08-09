import urllib.request
import base64
import json
import re

# Источники VLESS-конфигов (можно дополнять)
SOURCES = [
    "https://raw.githubusercontent.com/freefq/free/master/v2ray",
    "https://raw.githubusercontent.com/barry-far/V2ray-Configs/main/All_Configs_Sub.txt"
]

MAX_SERVERS = 15

def fetch_configs():
    raw_links = []
    for src in SOURCES:
        try:
            req = urllib.request.Request(src, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=10) as response:
                content = response.read().decode('utf-8', errors='ignore')
                
                # Если источник закодирован в Base64
                try:
                    decoded = base64.b64decode(content).decode('utf-8', errors='ignore')
                    content = decoded
                except Exception:
                    pass
                
                for line in content.splitlines():
                    line = line.strip()
                    if line.startswith("vless://"):
                        raw_links.append(line)
        except Exception as e:
            print(f"Ошибка загрузки из {src}: {e}")
    return raw_links

def filter_germany_servers(links):
    de_servers = []
    
    for link in links:
        # Простая фильтрация по ключевым словам в имени (DE, Germany, Германия)
        # и очистка от дубликатов
        name_part = link.split("#")[-1] if "#" in link else ""
        if re.search(r'(DE|Germany|Германия|DE-)', name_part, re.IGNORECASE):
            if link not in de_servers:
                de_servers.append(link)
                
        if len(de_servers) >= MAX_SERVERS:
            break
            
    return de_servers

def main():
    print("Собираем VLESS ссылки...")
    raw_links = fetch_configs()
    
    print(f"Всего найдено ссылок: {len(raw_links)}")
    de_links = filter_germany_servers(raw_links)
    
    print(f"Отфильтровано немецких серверов: {len(de_links)}")
    
    # Собираем текстовый список
    plain_text = "\n".join(de_links)
    
    # Сохраняем чистый список
    with open("sub_de.txt", "w", encoding="utf-8") as f:
        f.write(plain_text)
        
    # Сохраняем Base64 версию (стандарт для V2Ray/VLESS подписок)
    b64_text = base64.b64encode(plain_text.encode('utf-8')).decode('utf-8')
    with open("sub_de_b64.txt", "w", encoding="utf-8") as f:
        f.write(b64_text)

if __name__ == "__main__":
    main()
