import urllib.request
import urllib.parse
import base64
import socket
import ssl
import re
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed


# ============================================================
# НАСТРОЙКИ
# ============================================================

SOURCE_URL = (
    "https://raw.githack.com/igareck/"
    "vpn-configs-for-russia/main/WHITE-CIDR-RU-all.txt"
)

MAX_SERVERS = 30

# Сколько потоков использовать для проверки
MAX_WORKERS = 30

# Таймаут TCP-проверки
TCP_TIMEOUT = 4

# Таймаут TLS-проверки
TLS_TIMEOUT = 5

# Если True, сначала идут Германия, потом остальные страны
PREFER_GERMANY = True


# ============================================================
# ЗАГРУЗКА VLESS
# ============================================================

def fetch_vless_links():
    links = []

    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 Chrome/151.0 Safari/537.36"
        )
    }

    try:
        print("📥 Скачиваем базу...")

        req = urllib.request.Request(
            SOURCE_URL,
            headers=headers
        )

        with urllib.request.urlopen(req, timeout=20) as resp:
            content = resp.read().decode(
                "utf-8",
                errors="ignore"
            ).strip()

        # ----------------------------------------------------
        # Попытка определить Base64
        # ----------------------------------------------------

        try:
            decoded = base64.b64decode(
                content,
                validate=False
            ).decode(
                "utf-8",
                errors="ignore"
            )

            if "vless://" in decoded:
                content = decoded
                print("🔐 Источник распознан как Base64")

        except Exception:
            pass

        # ----------------------------------------------------
        # Извлекаем VLESS
        # ----------------------------------------------------

        for line in content.splitlines():

            line = line.strip()

            if line.startswith("vless://"):
                links.append(line)

    except Exception as e:
        print(f"❌ Ошибка загрузки источника: {e}")

    return links


# ============================================================
# BASE64 URL DECODING
# ============================================================

def safe_unquote(value):
    try:
        return urllib.parse.unquote(value)
    except Exception:
        return value


# ============================================================
# ОПРЕДЕЛЕНИЕ IP
# ============================================================

def is_ip(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


# ============================================================
# ОПРЕДЕЛЕНИЕ ГЕРМАНИИ ПО ТЕГУ
# ============================================================

def is_germany_by_tag(link):

    try:
        tag = link.split("#", 1)[1] if "#" in link else ""
        tag = safe_unquote(tag)

        pattern = (
            r"(🇩🇪|"
            r"\bDE\b|"
            r"Germany|"
            r"Deutschland|"
            r"Германия|"
            r"Frankfurt|"
            r"Nuremberg|"
            r"Falkenstein|"
            r"Hessen|"
            r"Berlin|"
            r"Munich|"
            r"Munchen|"
            r"Leipzig|"
            r"Dusseldorf|"
            r"Hamburg)"
        )

        return bool(
            re.search(
                pattern,
                tag,
                re.IGNORECASE
            )
        )

    except Exception:
        return False


# ============================================================
# РАЗБОР VLESS
# ============================================================

def parse_vless(link):

    try:
        parsed = urllib.parse.urlparse(link)

        if parsed.scheme.lower() != "vless":
            return None

        username = parsed.username

        host = parsed.hostname
        port = parsed.port

        if not host or not port:
            return None

        query = urllib.parse.parse_qs(
            parsed.query,
            keep_blank_values=True
        )

        def get_param(name, default=""):
            value = query.get(name, [default])
            return value[0] if value else default

        config = {
            "link": link,

            "uuid": username or "",

            "host": host,

            "port": port,

            "type": get_param("type", "tcp"),

            "security": get_param("security", "none"),

            "sni": get_param("sni", ""),

            "fp": get_param("fp", ""),

            "alpn": get_param("alpn", ""),

            "flow": get_param("flow", ""),

            "path": get_param("path", ""),

            "host_header": get_param("host", ""),

            "serviceName": get_param("serviceName", ""),

            "tag": (
                safe_unquote(
                    link.split("#", 1)[1]
                )
                if "#" in link
                else ""
            )
        }

        return config

    except Exception:
        return None


# ============================================================
# TCP ПРОВЕРКА
# ============================================================

def check_tcp(host, port):

    try:

        with socket.create_connection(
            (host, port),
            timeout=TCP_TIMEOUT
        ):
            return True

    except Exception:
        return False


# ============================================================
# TLS ПРОВЕРКА
# ============================================================

def check_tls(host, port, sni=None):

    # Если SNI не указан, используем host,
    # но для IP это допустимо только как техническая проверка TLS.
    server_name = sni or host

    try:

        context = ssl.create_default_context()

        # Мы проверяем доступность TLS,
        # а не валидность сертификата конкретного VPN.
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection(
            (host, port),
            timeout=TLS_TIMEOUT
        ) as sock:

            sock.settimeout(TLS_TIMEOUT)

            with context.wrap_socket(
                sock,
                server_hostname=server_name
            ) as tls_sock:

                tls_sock.do_handshake()

                return True

    except Exception:
        return False


# ============================================================
# ПРОВЕРКА ОДНОГО СЕРВЕРА
# ============================================================

def check_server(config):

    host = config["host"]
    port = config["port"]

    ip_based = is_ip(host)

    tcp_ok = check_tcp(
        host,
        port
    )

    if not tcp_ok:

        return {
            **config,
            "tcp_ok": False,
            "tls_ok": False,
            "working": False,
            "score": 0
        }

    security = config["security"].lower()

    tls_ok = False

    # --------------------------------------------------------
    # Если конфигурация явно использует TLS
    # --------------------------------------------------------

    if security in (
        "tls",
        "reality"
    ):

        tls_ok = check_tls(
            host,
            port,
            config["sni"]
        )

    # --------------------------------------------------------
    # Если TLS не указан, TCP всё равно считается рабочим
    # на уровне сетевого подключения.
    # --------------------------------------------------------

    working = tcp_ok

    # ========================================================
    # РЕЙТИНГ
    # ========================================================

    score = 0

    if working:
        score += 100

    # IP предпочтительнее домена
    if ip_based:
        score += 20

    # --------------------------------------------------------
    # Главный приоритет:
    # IP:443
    # --------------------------------------------------------

    if ip_based and port == 443:
        score += 200

    # IP:443 + TLS
    if ip_based and port == 443 and tls_ok:
        score += 100

    # Обычный 443
    if port == 443:
        score += 50

    # TLS
    if tls_ok:
        score += 50

    # Германия по тегу
    if is_germany_by_tag(config["link"]):
        score += 30

    return {
        **config,
        "tcp_ok": tcp_ok,
        "tls_ok": tls_ok,
        "working": working,
        "score": score
    }


# ============================================================
# ПЕЧАТЬ РЕЗУЛЬТАТА
# ============================================================

def print_result(result):

    host = result["host"]
    port = result["port"]

    location = "🇩🇪 DE" if is_germany_by_tag(
        result["link"]
    ) else "🌍 OTHER"

    ip_marker = "IP" if is_ip(host) else "DOMAIN"

    tls_marker = ""

    if result["tls_ok"]:
        tls_marker = " 🔒TLS"

    print(
        f"  ✅ {location} "
        f"{ip_marker} "
        f"{host}:{port}"
        f"{tls_marker} "
        f"[score={result['score']}]"
    )


# ============================================================
# СОХРАНЕНИЕ
# ============================================================

def save_subscription(servers):

    links = [
        server["link"]
        for server in servers
    ]

    plain_text = "\n".join(links)

    # --------------------------------------------------------
    # Обычный список
    # --------------------------------------------------------

    with open(
        "sub_de.txt",
        "w",
        encoding="utf-8"
    ) as f:

        f.write(plain_text)

    # --------------------------------------------------------
    # Base64
    # --------------------------------------------------------

    b64_text = base64.b64encode(
        plain_text.encode("utf-8")
    ).decode("utf-8")

    with open(
        "sub_de_b64.txt",
        "w",
        encoding="utf-8"
    ) as f:

        f.write(b64_text)

    print()
    print("💾 Файлы сохранены:")
    print("   sub_de.txt")
    print("   sub_de_b64.txt")


# ============================================================
# MAIN
# ============================================================

def main():

    print("=" * 65)
    print(" VLESS SERVER CHECKER")
    print("=" * 65)
    print()

    # --------------------------------------------------------
    # 1. Загружаем базу
    # --------------------------------------------------------

    all_links = fetch_vless_links()

    print(
        f"📊 Найдено VLESS конфигураций: "
        f"{len(all_links)}"
    )

    if not all_links:
        print("❌ VLESS-конфигурации не найдены.")
        return

    # --------------------------------------------------------
    # 2. Удаляем дубликаты
    # --------------------------------------------------------

    unique_links = list(
        dict.fromkeys(all_links)
    )

    print(
        f"🧹 После удаления дубликатов: "
        f"{len(unique_links)}"
    )

    # --------------------------------------------------------
    # 3. Парсим
    # --------------------------------------------------------

    configs = []

    for link in unique_links:

        config = parse_vless(link)

        if config:
            configs.append(config)

    print(
        f"🔎 Удалось разобрать: "
        f"{len(configs)}"
    )

    if not configs:
        print("❌ Не удалось разобрать VLESS.")
        return

    # --------------------------------------------------------
    # 4. Проверяем параллельно
    # --------------------------------------------------------

    print()
    print(
        f"⚡ Проверяем доступность "
        f"{len(configs)} серверов..."
    )
    print(
        f"   Потоков: {MAX_WORKERS}"
    )
    print()

    results = []

    with ThreadPoolExecutor(
        max_workers=MAX_WORKERS
    ) as executor:

        futures = {
            executor.submit(
                check_server,
                config
            ): config
            for config in configs
        }

        completed = 0

        for future in as_completed(futures):

            completed += 1

            try:
                result = future.result()

                if result["working"]:
                    results.append(result)

                    print_result(result)

            except Exception as e:
                print(
                    f"  ⚠️ Ошибка проверки: {e}"
                )

    # --------------------------------------------------------
    # 5. Статистика
    # --------------------------------------------------------

    print()
    print("=" * 65)

    print(
        f"🟢 Рабочих серверов: "
        f"{len(results)}"
    )

    ip_443 = [
        r for r in results
        if is_ip(r["host"])
        and r["port"] == 443
    ]

    ip_443_tls = [
        r for r in results
        if is_ip(r["host"])
        and r["port"] == 443
        and r["tls_ok"]
    ]

    germany = [
        r for r in results
        if is_germany_by_tag(r["link"])
    ]

    print(
        f"🎯 Рабочих IP:443: "
        f"{len(ip_443)}"
    )

    print(
        f"🔒 Рабочих IP:443 + TLS: "
        f"{len(ip_443_tls)}"
    )

    print(
        f"🇩🇪 Помеченных как Германия: "
        f"{len(germany)}"
    )

    # --------------------------------------------------------
    # 6. Сортировка
    # --------------------------------------------------------

    #
    # Основная сортировка:
    #
    # 1. Рабочие
    # 2. IP
    # 3. порт 443
    # 4. TLS
    # 5. Германия
    # 6. общий score
    #

    def sort_key(r):

        ip = is_ip(r["host"])
        port_443 = r["port"] == 443
        germany = is_germany_by_tag(
            r["link"]
        )

        return (
            r["working"],
            ip and port_443,
            ip_443_tls and ip and port_443 and r["tls_ok"],
            port_443,
            r["tls_ok"],
            germany if PREFER_GERMANY else False,
            r["score"]
        )

    results.sort(
        key=sort_key,
        reverse=True
    )

    # --------------------------------------------------------
    # 7. Берём лучшие
    # --------------------------------------------------------

    final_servers = results[:MAX_SERVERS]

    # --------------------------------------------------------
    # 8. Выводим итоговый рейтинг
    # --------------------------------------------------------

    print()
    print("=" * 65)
    print(
        f"🏆 ТОП-{len(final_servers)}"
    )
    print("=" * 65)

    for index, server in enumerate(
        final_servers,
        start=1
    ):

        host = server["host"]
        port = server["port"]

        country = (
            "🇩🇪"
            if is_germany_by_tag(
                server["link"]
            )
            else "🌍"
        )

        tls = (
            "TLS"
            if server["tls_ok"]
            else "TCP"
        )

        print(
            f"{index:02d}. "
            f"{country} "
            f"{host}:{port} "
            f"[{tls}] "
            f"score={server['score']}"
        )

    # --------------------------------------------------------
    # 9. Сохраняем
    # --------------------------------------------------------

    if final_servers:

        save_subscription(
            final_servers
        )

    else:

        print()
        print(
            "❌ Ни одного рабочего сервера "
            "не найдено."
        )

    print()
    print("=" * 65)
    print("Готово.")
    print("=" * 65)


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":
    main()
