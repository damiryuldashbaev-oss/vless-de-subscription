import urllib.request
import urllib.parse
import base64
import json
import re

SOURCES = [
    "https://raw.githubusercontent.com/yebekhe/TelegramV2rayCollector/main/sub/base64",
    "https://raw.githubusercontent.com/barry-far/V2ray-Configs/main/All_Configs_Sub.txt",
    "https://raw.githubusercontent.com/mftb-group/v2ray-configs/main/v2ray.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-Configs/main/Splitted-By-Protocol/vless.txt"
]

MAX_SERVERS = 15

def fetch_raw_vless():
    links = []
    headers = {'User-Agent': 'Mozilla/5.0'}
    for src in SOURCES:
        try:
            req = urllib.request.Request(src, headers=headers)
            with urllib.request.urlopen(req, timeout=10) as resp:
                content = resp.read().decode('utf-8', errors='ignore').strip()
                # Если base64
                try:
                    decoded = base64.b64decode(content).decode('utf-8', errors='ignore')
                    if "vless://" in decoded:
                        content = decoded
                except Exception:
                    pass
                
                for line in content.splitlines():
                    line = line.strip()
                    if line.startswith("vless://"):
                        links.append(line)
        except Exception as e:
            print(f"Ошибка загрузки {src}: {e}")
    return links

def extract_host(vless_link):
    """Извлекает IP или домен из vless://uuid@host:port"""
    try:
        after_at = vless_link.split("@")[1]
        host_port = after_at.split("?")[0].split("#")[0]
        host = host_port.split(":")[0]
        return host
    except Exception:
        return None

def is_germany(host, tag):
    """Проверяет Германию сначала по тегу, а затем по IP/домену"""
    # 1. Быстрая проверка по имени (#DE, #Germany)
    tag_decoded = urllib.parse.unquote(tag)
    if re.search(r'(🇩🇪|DE|Germany|Frankfurt|Nuremberg|Falkenstein)', tag_decoded, re.IGNORECASE):
        return True
        
    # 2. Проверка по домену (заканчивается на .de)
    if host and host.endswith(".de"):
        return True

    return False

def main():
    print("Собираем VLESS ссылки...")
    raw_links = fetch_raw_vless()
    print(f"Найдено всего VLESS: {len(raw_links)}")

    de_servers = []
    seen = set()

    for link in raw_links:
        if link in seen:
            continue
            
        host = extract_host(link)
        tag = link.split("#")[-1] if "#" in link else ""
        
        if is_germany(host, tag):
            seen.add(link)
            de_servers.append(link)
            print(f"[+] Добавлен немецкий сервер: {tag or host}")
            if len(de_servers) >= MAX_SERVERS:
                break

    # Страховка: если немецких не нашлось вовсе, берем первые рабочие VLESS,
    # чтобы файл подписки не оказался пустым
    if not de_servers:
        print("⚠️ Немецкие серверы не найдены. Заполняем резервными VLESS...")
        de_servers = list(dict.fromkeys(raw_links))[:MAX_SERVERS]

    print(f"Итого серверов в файле: {len(de_servers)}")

    plain_text = "\n".join(de_servers)
    
    with open("sub_de.txt", "w", encoding="utf-8") as f:
        f.write(plain_text)

    b64_text = base64.b64encode(plain_text.encode('utf-8')).decode('utf-8')
    with open("sub_de_b64.txt", "w", encoding="utf-8") as f:
        f.write(b64_text)

if __name__ == "__main__":
    main()
