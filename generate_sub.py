import urllib.request
import urllib.parse
import base64
import re

SOURCE_URL = "https://raw.githack.com/igareck/vpn-configs-for-russia/main/WHITE-CIDR-RU-all.txt"
MAX_SERVERS = 15

def fetch_vless_links():
links = []
headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}

try:
    req = urllib.request.Request(SOURCE_URL, headers=headers)
    with urllib.request.urlopen(req, timeout=20) as resp:
        content = resp.read().decode('utf-8', errors='ignore').strip()
        
        # Если вся подписка зашифрована в Base64
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
    print(f"Ошибка загрузки источника: {e}")
    
return links


def is_germany(link):
"""Проверка на Германию по тегу в конце VLESS ссылки"""
tag = link.split("#")[-1] if "#" in link else ""
tag_decoded = urllib.parse.unquote(tag)

# Ключевые слова для поиска немецких серверов
pattern = r'(🇩🇪|DE\b|Germany|Германия|Frankfurt|Nuremberg|Falkenstein|Hessen|Berlin)'
if re.search(pattern, tag_decoded, re.IGNORECASE):
    return True
    
return False


def main():
print("Скачиваем полную базу CIDR-RU...")
all_vless = fetch_vless_links()
print(f"Найдено VLESS конфигураций: {len(all_vless)}")

if not all_vless:
    print("❌ Не удалось спарсить VLESS ссылки.")
    return

de_servers = []
other_servers = []
seen = set()

for link in all_vless:
    if link in seen:
        continue
    seen.add(link)

    if is_germany(link):
        de_servers.append(link)
    else:
        other_servers.append(link)

print(f"Из них немецких серверов: {len(de_servers)}")

# Берем немецкие серверы (до 15 штук)
final_list = de_servers[:MAX_SERVERS]

# Если немецких серверов меньше 15, добираем из общего списка
if len(final_list) < MAX_SERVERS:
    needed = MAX_SERVERS - len(final_list)
    print(f"Добираем {needed} резервных серверов из общего списка...")
    final_list.extend(other_servers[:needed])

print(f"Итого серверов записано: {len(final_list)}")

# 1. Сохраняем текстовый список (sub_de.txt)
plain_text = "\n".join(final_list)
with open("sub_de.txt", "w", encoding="utf-8") as f:
    f.write(plain_text)

# 2. Сохраняем Base64 подписку (sub_de_b64.txt)
b64_text = base64.b64encode(plain_text.encode('utf-8')).decode('utf-8')
with open("sub_de_b64.txt", "w", encoding="utf-8") as f:
    f.write(b64_text)

print("✅ Успешно! Файлы подписки обновлены.")


if name == "main":
main()
