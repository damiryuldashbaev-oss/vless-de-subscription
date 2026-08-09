import urllib.request
import urllib.parse
import base64
import json
import re

# Рабочие и актуальные источники подписок VLESS
SOURCES = [
    "https://raw.githubusercontent.com/yebekhe/TVC/main/subscriptions/xray/base64",
    "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/sub_merge.txt",
    "https://raw.githubusercontent.com/EbrahimAfrasiabi/v2ray-subscription/main/data/v2ray.txt",
    "https://raw.githubusercontent.com/freefq/free/master/v2ray"
]

MAX_SERVERS = 15

def fetch_raw_vless():
    links = []
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
    
    for src in SOURCES:
        try:
            req = urllib.request.Request(src, headers=headers)
            with urllib.request.urlopen(req, timeout=12) as resp:
                content = resp.read().decode('utf-8', errors='ignore').strip()
                
                # Если файл зашифрован в Base64 (стандарт подписок)
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
    """Проверяет принадлежность к Германии по названию или домену"""
    tag_decoded = urllib.parse.unquote(tag)
    
    # Ключевые слова немецких локаций
    if re.search(r'(🇩🇪|DE|Germany|Frankfurt|Nuremberg|Falkenstein|Hessen|Berlin)', tag_decoded, re.IGNORECASE):
        return True
        
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
            print(f"[+] Добавлен немецкий сервер: {tag_decoded if 'tag_decoded' in locals() else tag or host}")
            if len(de_servers) >= MAX_SERVERS:
                break

    # Страховка: если по тегам DE не нашлось 15 штук, добираем из общего списка VLESS
    if len(de_servers) < 5:
        print("⚠️ Немецких серверов мало или не найдено. Добавляем доступные VLESS...")
        for link in raw_links:
            if link not in seen:
                seen.add(link)
                de_servers.append(link)
                if len(de_servers) >= MAX_SERVERS:
                    break

    print(f"Итого серверов в подписке: {len(de_servers)}")

    plain_text = "\n".join(de_servers)
    
    with open("sub_de.txt", "w", encoding="utf-8") as f:
        f.write(plain_text)

    b64_text = base64.b64encode(plain_text.encode('utf-8')).decode('utf-8')
    with open("sub_de_b64.txt", "w", encoding="utf-8") as f:
        f.write(b64_text)
        
    print("Файлы подписки успешно обновлены!")

if __name__ == "__main__":
    main()
