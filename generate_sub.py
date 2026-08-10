```python
import base64
import hashlib
import ipaddress
import json
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed


# ============================================================
# НАСТРОЙКИ
# ============================================================

SOURCE_URL = (
    "https://raw.githack.com/igareck/"
    "vpn-configs-for-russia/main/WHITE-CIDR-RU-all.txt"
)

MAX_SERVERS = 30
MAX_WORKERS = 8

# Сколько секунд ждать запуск Xray
XRAY_START_TIMEOUT = 8

# Сколько секунд ждать ответ через прокси
PROXY_TIMEOUT = 10

# Порт локального SOCKS будет начинаться отсюда
LOCAL_PORT_START = 18080

# Оставляем только выходные IP, которые определились как Германия
GERMANY_ONLY = True

# Если Германия не набралась до MAX_SERVERS,
# можно добрать рабочими серверами других стран.
FILL_WITH_OTHER_COUNTRIES = False

# Если True, Xray будет скачан автоматически
AUTO_DOWNLOAD_XRAY = True

# Официальный репозиторий Xray-core
XRAY_RELEASE_API = (
    "https://api.github.com/repos/XTLS/Xray-core/releases/latest"
)


# ============================================================
# ОБЩИЕ ФУНКЦИИ
# ============================================================

def safe_unquote(value):
    try:
        return urllib.parse.unquote(value)
    except Exception:
        return value


def is_ip(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def clean_b64(value):
    value = value.strip()
    value = value.replace("-", "+").replace("_", "/")
    value += "=" * (-len(value) % 4)
    return value


# ============================================================
# ЗАГРУЗКА VLESS
# ============================================================

def fetch_vless_links():
    print("📥 Загружаем базу VLESS...")

    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 Chrome/151.0 Safari/537.36"
        )
    }

    try:
        req = urllib.request.Request(
            SOURCE_URL,
            headers=headers
        )

        with urllib.request.urlopen(req, timeout=30) as response:
            content = response.read().decode(
                "utf-8",
                errors="ignore"
            ).strip()

    except Exception as e:
        print(f"❌ Ошибка загрузки: {e}")
        return []

    # --------------------------------------------------------
    # Проверяем Base64
    # --------------------------------------------------------

    try:
        decoded = base64.b64decode(
            clean_b64(content),
            validate=False
        ).decode(
            "utf-8",
            errors="ignore"
        )

        if "vless://" in decoded:
            content = decoded
            print("🔐 Обнаружена Base64-подписка")

    except Exception:
        pass

    links = []

    for line in content.splitlines():
        line = line.strip()

        if line.startswith("vless://"):
            links.append(line)

    # Убираем дубликаты, сохраняя порядок
    links = list(dict.fromkeys(links))

    print(f"📊 Найдено уникальных VLESS: {len(links)}")

    return links


# ============================================================
# PARSE VLESS
# ============================================================

def parse_vless(link):
    try:
        parsed = urllib.parse.urlparse(link)

        if parsed.scheme.lower() != "vless":
            return None

        uuid = parsed.username
        host = parsed.hostname
        port = parsed.port

        if not uuid or not host or not port:
            return None

        query = urllib.parse.parse_qs(
            parsed.query,
            keep_blank_values=True
        )

        def q(name, default=""):
            value = query.get(name, [default])
            return value[0] if value else default

        tag = ""

        if "#" in link:
            tag = safe_unquote(
                link.split("#", 1)[1]
            )

        return {
            "link": link,
            "uuid": uuid,
            "host": host,
            "port": port,

            "type": q("type", "tcp").lower(),

            "security": q("security", "none").lower(),

            "sni": q("sni", ""),
            "fp": q("fp", ""),
            "pbk": q("pbk", ""),
            "sid": q("sid", ""),

            "flow": q("flow", ""),

            "alpn": q("alpn", ""),

            "path": q("path", ""),
            "host_header": q("host", ""),

            "service_name": q(
                "serviceName",
                ""
            ),

            "authority": q(
                "authority",
                ""
            ),

            "mode": q(
                "mode",
                ""
            ),

            "header_type": q(
                "headerType",
                ""
            ),

            "tag": tag
        }

    except Exception:
        return None


# ============================================================
# XRAY DOWNLOAD
# ============================================================

def find_xray():

    local_candidates = [
        os.path.join(
            os.getcwd(),
            "xray.exe"
        ),
        os.path.join(
            os.path.dirname(
                os.path.abspath(__file__)
            ),
            "xray.exe"
        )
    ]

    for path in local_candidates:
        if os.path.isfile(path):
            return path

    return None


def download_xray():

    print()
    print("🧩 xray.exe не найден.")

    if not AUTO_DOWNLOAD_XRAY:
        print(
            "❌ AUTO_DOWNLOAD_XRAY отключён."
        )
        return None

    print("📥 Получаем последнюю официальную Windows-сборку Xray...")

    headers = {
        "User-Agent": "VLESS-Checker/1.0",
        "Accept": "application/vnd.github+json"
    }

    try:
        req = urllib.request.Request(
            XRAY_RELEASE_API,
            headers=headers
        )

        with urllib.request.urlopen(
            req,
            timeout=30
        ) as response:

            release = json.loads(
                response.read().decode(
                    "utf-8"
                )
            )

    except Exception as e:
        print(
            f"❌ Не удалось получить релиз Xray: {e}"
        )
        return None

    assets = release.get(
        "assets",
        []
    )

    asset = None

    # Windows x64
    for item in assets:

        name = item.get(
            "name",
            ""
        )

        if name.lower() == "xray-windows-64.zip":
            asset = item
            break

    if not asset:
        print(
            "❌ В последнем релизе "
            "не найдена Xray-windows-64.zip"
        )
        return None

    download_url = asset.get(
        "browser_download_url"
    )

    if not download_url:
        print("❌ Нет URL загрузки Xray.")
        return None

    base_dir = os.path.dirname(
        os.path.abspath(__file__)
    )

    zip_path = os.path.join(
        base_dir,
        "xray_windows.zip"
    )

    print(
        f"⬇️ Скачиваем {asset['name']}..."
    )

    try:

        req = urllib.request.Request(
            download_url,
            headers={
                "User-Agent": "VLESS-Checker/1.0"
            }
        )

        with urllib.request.urlopen(
            req,
            timeout=120
        ) as response:

            with open(
                zip_path,
                "wb"
            ) as f:

                shutil.copyfileobj(
                    response,
                    f
                )

    except Exception as e:
        print(
            f"❌ Ошибка скачивания Xray: {e}"
        )

        if os.path.exists(zip_path):
            os.remove(zip_path)

        return None

    print("📦 Распаковываем Xray...")

    try:

        with zipfile.ZipFile(
            zip_path,
            "r"
        ) as z:

            xray_name = None

            for name in z.namelist():

                if name.lower().endswith(
                    "/xray.exe"
                ) or name.lower() == "xray.exe":

                    xray_name = name
                    break

            if not xray_name:
                print(
                    "❌ xray.exe отсутствует в архиве."
                )
                return None

            data = z.read(xray_name)

        xray_path = os.path.join(
            base_dir,
            "xray.exe"
        )

        with open(
            xray_path,
            "wb"
        ) as f:

            f.write(data)

        try:
            os.remove(zip_path)
        except Exception:
            pass

        print(
            f"✅ Xray установлен: {xray_path}"
        )

        return xray_path

    except Exception as e:
        print(
            f"❌ Ошибка распаковки: {e}"
        )
        return None


def get_xray():

    xray = find_xray()

    if xray:
        print(
            f"✅ Используем Xray: {xray}"
        )
        return xray

    return download_xray()


# ============================================================
# XRAY CONFIG
# ============================================================

def build_xray_config(config, socks_port):

    stream_type = config["type"]
    security = config["security"]

    stream = {
        "network": stream_type
    }

    # --------------------------------------------------------
    # TCP
    # --------------------------------------------------------

    if stream_type == "tcp":

        header_type = config["header_type"]

        if header_type:
            stream["tcpSettings"] = {
                "header": {
                    "type": header_type
                }
            }

    # --------------------------------------------------------
    # WebSocket
    # --------------------------------------------------------

    elif stream_type == "ws":

        ws_settings = {}

        if config["path"]:
            ws_settings["path"] = config["path"]

        if config["host_header"]:
            ws_settings["headers"] = {
                "Host": config["host_header"]
            }

        stream["wsSettings"] = ws_settings

    # --------------------------------------------------------
    # gRPC
    # --------------------------------------------------------

    elif stream_type == "grpc":

        grpc_settings = {}

        if config["service_name"]:
            grpc_settings["serviceName"] = (
                config["service_name"]
            )

        if config["authority"]:
            grpc_settings["authority"] = (
                config["authority"]
            )

        if config["mode"]:
            grpc_settings["multiMode"] = (
                config["mode"].lower() == "multi"
            )

        stream["grpcSettings"] = grpc_settings

    # --------------------------------------------------------
    # HTTPUpgrade
    # --------------------------------------------------------

    elif stream_type == "httpupgrade":

        settings = {}

        if config["path"]:
            settings["path"] = config["path"]

        if config["host_header"]:
            settings["host"] = config["host_header"]

        stream["httpupgradeSettings"] = settings

    # --------------------------------------------------------
    # XHTTP / SplitHTTP
    # --------------------------------------------------------

    elif stream_type in (
        "xhttp",
        "splithttp"
    ):

        settings = {}

        if config["path"]:
            settings["path"] = config["path"]

        if config["host_header"]:
            settings["host"] = config["host_header"]

        if config["mode"]:
            settings["mode"] = config["mode"]

        stream["xhttpSettings"] = settings

    # --------------------------------------------------------
    # SECURITY
    # --------------------------------------------------------

    if security == "tls":

        tls_settings = {
            "serverName": (
                config["sni"]
                or config["host"]
            ),

            "allowInsecure": True
        }

        if config["alpn"]:

            tls_settings["alpn"] = [
                x.strip()
                for x in config["alpn"].split(",")
                if x.strip()
            ]

        if config["fp"]:
            tls_settings["fingerprint"] = (
                config["fp"]
            )

        stream["security"] = "tls"
        stream["tlsSettings"] = tls_settings

    elif security == "reality":

        reality_settings = {
            "serverName": (
                config["sni"]
                or config["host"]
            ),

            "fingerprint": (
                config["fp"]
                or "chrome"
            ),

            "publicKey": config["pbk"],
            "shortId": config["sid"]
        }

        stream["security"] = "reality"
        stream["realitySettings"] = (
            reality_settings
        )

    else:

        stream["security"] = "none"

    # --------------------------------------------------------
    # VLESS OUTBOUND
    # --------------------------------------------------------

    vnext = {
        "address": config["host"],
        "port": config["port"],

        "users": [
            {
                "id": config["uuid"],
                "encryption": "none"
            }
        ]
    }

    if config["flow"]:
        vnext["users"][0]["flow"] = (
            config["flow"]
        )

    outbound = {
        "protocol": "vless",

        "settings": {
            "vnext": [
                vnext
            ]
        },

        "streamSettings": stream,

        "tag": "proxy"
    }

    # --------------------------------------------------------
    # LOCAL SOCKS
    # --------------------------------------------------------

    return {
        "log": {
            "loglevel": "warning"
        },

        "inbounds": [
            {
                "listen": "127.0.0.1",

                "port": socks_port,

                "protocol": "socks",

                "settings": {
                    "auth": "noauth",
                    "udp": False
                },

                "sniffing": {
                    "enabled": True,
                    "destOverride": [
                        "http",
                        "tls"
                    ]
                }
            }
        ],

        "outbounds": [
            outbound,

            {
                "protocol": "freedom",
                "tag": "direct"
            },

            {
                "protocol": "blackhole",
                "tag": "block"
            }
        ],

        "routing": {
            "domainStrategy": "AsIs",

            "rules": [
                {
                    "type": "field",
                    "ip": [
                        "geoip:private"
                    ],
                    "outboundTag": "direct"
                }
            ]
        }
    }


# ============================================================
# ПРОВЕРКА ПОРТА
# ============================================================

def wait_for_port(port, timeout):

    deadline = time.time() + timeout

    while time.time() < deadline:

        try:

            with socket.create_connection(
                ("127.0.0.1", port),
                timeout=0.5
            ):
                return True

        except Exception:
            time.sleep(0.15)

    return False


# ============================================================
# HTTPS ЧЕРЕЗ SOCKS5
# ============================================================

def socks5_connect(
    proxy_host,
    proxy_port,
    target_host,
    target_port
):

    sock = socket.create_connection(
        (proxy_host, proxy_port),
        timeout=PROXY_TIMEOUT
    )

    sock.settimeout(
        PROXY_TIMEOUT
    )

    # --------------------------------------------------------
    # SOCKS5 greeting
    # --------------------------------------------------------

    sock.sendall(
        b"\x05\x01\x00"
    )

    response = sock.recv(2)

    if response != b"\x05\x00":
        sock.close()
        raise RuntimeError(
            "SOCKS5 authentication failed"
        )

    # --------------------------------------------------------
    # Target address
    # --------------------------------------------------------

    try:
        ip = ipaddress.ip_address(
            target_host
        )

        if ip.version == 4:

            request = (
                b"\x05\x01\x00\x01"
                + ip.packed
                + target_port.to_bytes(
                    2,
                    "big"
                )
            )

        else:

            request = (
                b"\x05\x01\x00\x04"
                + ip.packed
                + target_port.to_bytes(
                    2,
                    "big"
                )
            )

    except ValueError:

        encoded = target_host.encode(
            "idna"
        )

        if len(encoded) > 255:
            sock.close()
            raise RuntimeError(
                "Hostname too long"
            )

        request = (
            b"\x05\x01\x00\x03"
            + bytes([len(encoded)])
            + encoded
            + target_port.to_bytes(
                2,
                "big"
            )
        )

    sock.sendall(request)

    # --------------------------------------------------------
    # Reply
    # --------------------------------------------------------

    header = sock.recv(4)

    if len(header) != 4:
        sock.close()
        raise RuntimeError(
            "Invalid SOCKS5 response"
        )

    if header[1] != 0x00:
        sock.close()
        raise RuntimeError(
            f"SOCKS5 connection failed: "
            f"{header[1]}"
        )

    address_type = header[3]

    if address_type == 1:
        sock.recv(4)

    elif address_type == 3:

        length_data = sock.recv(1)

        if not length_data:
            sock.close()
            raise RuntimeError(
                "Invalid SOCKS5 domain response"
            )

        sock.recv(
            length_data[0]
        )

    elif address_type == 4:
        sock.recv(16)

    sock.recv(2)

    return sock


def https_get_through_socks(
    socks_port,
    hostname,
    path
):

    sock = socks5_connect(
        "127.0.0.1",
        socks_port,
        hostname,
        443
    )

    context = ssl.create_default_context()

    # Нам нужно проверить маршрут, а не сертификат
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    tls_sock = context.wrap_socket(
        sock,
        server_hostname=hostname
    )

    request = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {hostname}\r\n"
        f"User-Agent: VLESS-Checker/1.0\r\n"
        f"Accept: application/json,text/plain,*/*\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode(
        "ascii",
        errors="ignore"
    )

    tls_sock.sendall(request)

    data = b""

    while len(data) < 65536:

        chunk = tls_sock.recv(8192)

        if not chunk:
            break

        data += chunk

    tls_sock.close()

    header_end = data.find(
        b"\r\n\r\n"
    )

    if header_end == -1:
        raise RuntimeError(
            "Invalid HTTPS response"
        )

    body = data[
        header_end + 4:
    ]

    return body.decode(
        "utf-8",
        errors="ignore"
    )


# ============================================================
# ПОЛУЧАЕМ ВНЕШНИЙ IP ЧЕРЕЗ ПРОКСИ
# ============================================================

def get_exit_ip(socks_port):

    # ipify возвращает только внешний IP.
    body = https_get_through_socks(
        socks_port,
        "api.ipify.org",
        "/"
    )

    ip = body.strip()

    try:
        ipaddress.ip_address(ip)
    except ValueError:
        raise RuntimeError(
            f"Некорректный внешний IP: {ip}"
        )

    return ip


# ============================================================
# ГЕОЛОКАЦИЯ EXIT IP
# ============================================================

def geolocate_ip(ip):

    url = (
        "https://ipwho.is/"
        + urllib.parse.quote(ip)
    )

    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "VLESS-Checker/1.0"
        }
    )

    with urllib.request.urlopen(
        req,
        timeout=10
    ) as response:

        data = json.loads(
            response.read().decode(
                "utf-8",
                errors="ignore"
            )
        )

    return {
        "country": data.get(
            "country",
            ""
        ),

        "country_code": data.get(
            "country_code",
            ""
        ),

        "city": data.get(
            "city",
            ""
        ),

        "org": data.get(
            "connection",
            {}
        ).get(
            "org",
            ""
        )
    }


# ============================================================
# ЗАПУСК XRAY
# ============================================================

def start_xray(
    xray_path,
    config,
    work_dir,
    socks_port
):

    config_path = os.path.join(
        work_dir,
        "config.json"
    )

    with open(
        config_path,
        "w",
        encoding="utf-8"
    ) as f:

        json.dump(
            config,
            f,
            ensure_ascii=False,
            indent=2
        )

    # --------------------------------------------------------
    # Сначала проверяем конфигурацию
    # --------------------------------------------------------

    test = subprocess.run(
        [
            xray_path,
            "run",
            "-test",
            "-config",
            config_path
        ],

        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,

        text=True,

        timeout=10,

        creationflags=(
            subprocess.CREATE_NO_WINDOW
            if os.name == "nt"
            else 0
        )
    )

    if test.returncode != 0:
        return None, (
            "Xray config error: "
            + test.stderr[-1000:]
        )

    # --------------------------------------------------------
    # Запускаем
    # --------------------------------------------------------

    log_path = os.path.join(
        work_dir,
        "xray.log"
    )

    log_file = open(
        log_path,
        "w",
        encoding="utf-8"
    )

    process = subprocess.Popen(
        [
            xray_path,
            "run",
            "-config",
            config_path
        ],

        stdout=log_file,
        stderr=subprocess.STDOUT,

        creationflags=(
            subprocess.CREATE_NO_WINDOW
            if os.name == "nt"
            else 0
        )
    )

    if not wait_for_port(
        socks_port,
        XRAY_START_TIMEOUT
    ):

        try:
            process.kill()
        except Exception:
            pass

        log_file.close()

        try:
            with open(
                log_path,
                "r",
                encoding="utf-8",
                errors="ignore"
            ) as f:
                log = f.read()[-1500:]
        except Exception:
            log = ""

        return None, (
            "Xray did not start. "
            + log
        )

    return (
        process,
        log_file
    ), None


# ============================================================
# ПРОВЕРКА ОДНОГО VLESS
# ============================================================

def check_server(
    xray_path,
    config_data,
    socks_port
):

    host = config_data["host"]
    port = config_data["port"]

    # --------------------------------------------------------
    # Быстрый TCP тест
    # --------------------------------------------------------

    try:

        with socket.create_connection(
            (host, port),
            timeout=4
        ):
            pass

    except Exception as e:

        return {
            **config_data,
            "working": False,
            "reason": f"TCP: {e}"
        }

    temp_dir = tempfile.mkdtemp(
        prefix="vless_check_"
    )

    process = None
    log_file = None

    try:

        xray_config = build_xray_config(
            config_data,
            socks_port
        )

        started, error = start_xray(
            xray_path,
            xray_config,
            temp_dir,
            socks_port
        )

        if not started:

            return {
                **config_data,
                "working": False,
                "reason": error
            }

        process, log_file = started

        # ----------------------------------------------------
        # Получаем внешний IP
        # ----------------------------------------------------

        exit_ip = get_exit_ip(
            socks_port
        )

        # ----------------------------------------------------
        # Геолокация
        # ----------------------------------------------------

        geo = geolocate_ip(
            exit_ip
        )

        country_code = (
            geo["country_code"]
            or ""
        ).upper()

        is_germany = (
            country_code == "DE"
        )

        # ----------------------------------------------------
        # Проверяем, что внешний IP
        # действительно не наш локальный IP
        #
        # Сам факт получения IP через Xray уже является
        # главным тестом работоспособности маршрута.
        # ----------------------------------------------------

        score = 100

        is_server_ip = (
            exit_ip == host
        )

        # IP сервера совпадает с exit IP:
        # это хороший признак прямого выхода через него.
        if is_server_ip:
            score += 40

        # Главный приоритет
        if is_ip(host) and port == 443:
            score += 300

        if port == 443:
            score += 80

        if is_ip(host):
            score += 40

        if is_germany:
            score += 200

        # TLS / Reality
        if config_data["security"] in (
            "tls",
            "reality"
        ):
            score += 30

        return {
            **config_data,

            "working": True,

            "exit_ip": exit_ip,

            "country": geo["country"],
            "country_code": country_code,
            "city": geo["city"],
            "org": geo["org"],

            "exit_equals_server": is_server_ip,

            "score": score,

            "reason": "OK"
        }

    except Exception as e:

        return {
            **config_data,
            "working": False,
            "reason": str(e)
        }

    finally:

        if process:

            try:
                process.terminate()
                process.wait(timeout=2)
            except Exception:
                try:
                    process.kill()
                except Exception:
                    pass

        if log_file:

            try:
                log_file.close()
            except Exception:
                pass

        shutil.rmtree(
            temp_dir,
            ignore_errors=True
        )


# ============================================================
# СОРТИРОВКА
# ============================================================

def sort_servers(servers):

    def key(server):

        host = server["host"]
        port = server["port"]

        ip_443 = (
            is_ip(host)
            and port == 443
        )

        germany = (
            server["country_code"]
            == "DE"
        )

        exit_is_server = (
            server["exit_equals_server"]
        )

        return (
            # Германия
            germany,

            # IP:443
            ip_443,

            # Exit IP совпадает с IP узла
            exit_is_server,

            # 443
            port == 443,

            # IP вместо домена
            is_ip(host),

            # Итоговый score
            server["score"]
        )

    return sorted(
        servers,
        key=key,
        reverse=True
    )


# ============================================================
# СОХРАНЕНИЕ
# ============================================================

def save_results(servers):

    links = [
        server["link"]
        for server in servers
    ]

    text = "\n".join(
        links
    )

    with open(
        "sub_de.txt",
        "w",
        encoding="utf-8"
    ) as f:

        f.write(text)

    b64 = base64.b64encode(
        text.encode("utf-8")
    ).decode("ascii")

    with open(
        "sub_de_b64.txt",
        "w",
        encoding="utf-8"
    ) as f:

        f.write(b64)

    # --------------------------------------------------------
    # Дополнительно сохраняем отчёт
    # --------------------------------------------------------

    report = []

    for index, server in enumerate(
        servers,
        1
    ):

        report.append({
            "rank": index,
            "host": server["host"],
            "port": server["port"],
            "exit_ip": server.get(
                "exit_ip",
                ""
            ),
            "country": server.get(
                "country",
                ""
            ),
            "country_code": server.get(
                "country_code",
                ""
            ),
            "city": server.get(
                "city",
                ""
            ),
            "organization": server.get(
                "org",
                ""
            ),
            "exit_equals_server": server.get(
                "exit_equals_server",
                False
            ),
            "score": server.get(
                "score",
                0
            ),
            "tag": server.get(
                "tag",
                ""
            )
        })

    with open(
        "servers_report.json",
        "w",
        encoding="utf-8"
    ) as f:

        json.dump(
            report,
            f,
            ensure_ascii=False,
            indent=2
        )

    print()
    print("💾 СОХРАНЕНО:")
    print("   sub_de.txt")
    print("   sub_de_b64.txt")
    print("   servers_report.json")


# ============================================================
# MAIN
# ============================================================

def main():

    print("=" * 72)
    print(" VLESS EXIT-IP CHECKER")
    print("=" * 72)
    print()

    # --------------------------------------------------------
    # Проверяем Windows
    # --------------------------------------------------------

    if os.name != "nt":

        print(
            "⚠️ Этот вариант рассчитан на Windows."
        )

    # --------------------------------------------------------
    # Xray
    # --------------------------------------------------------

    xray_path = get_xray()

    if not xray_path:

        print()
        print(
            "❌ Без xray.exe полноценная "
            "проверка VLESS невозможна."
        )

        return

    # --------------------------------------------------------
    # Получаем VLESS
    # --------------------------------------------------------

    links = fetch_vless_links()

    if not links:

        print(
            "❌ VLESS-ссылки не найдены."
        )

        return

    # --------------------------------------------------------
    # Парсим
    # --------------------------------------------------------

    configs = []

    for link in links:

        config = parse_vless(
            link
        )

        if config:
            configs.append(config)

    print(
        f"🔎 Корректно разобрано: "
        f"{len(configs)}"
    )

    # --------------------------------------------------------
    # В первую очередь проверяем IP:443
    # --------------------------------------------------------

    configs.sort(
        key=lambda x: (
            is_ip(x["host"])
            and x["port"] == 443,
            x["port"] == 443,
            is_ip(x["host"])
        ),
        reverse=True
    )

    # --------------------------------------------------------
    # Проверка
    # --------------------------------------------------------

    print()
    print(
        "⚡ Начинаем реальную проверку "
        "через Xray..."
    )
    print(
        "   Проверяется не только порт, "
        "но и внешний IP."
    )
    print()

    results = []

    # Чтобы разные Xray не использовали один SOCKS
    next_port = LOCAL_PORT_START

    port_map = {}

    for config in configs:

        port_map[
            config["link"]
        ] = next_port

        next_port += 1

        if next_port > 30000:
            next_port = LOCAL_PORT_START

    with ThreadPoolExecutor(
        max_workers=MAX_WORKERS
    ) as executor:

        futures = {}

        for config in configs:

            future = executor.submit(
                check_server,
                xray_path,
                config,
                port_map[
                    config["link"]
                ]
            )

            futures[future] = config

        completed = 0

        for future in as_completed(
            futures
        ):

            completed += 1

            config = futures[future]

            try:

                result = future.result()

                if result["working"]:

                    results.append(
                        result
                    )

                    country = (
                        result["country_code"]
                        or "??"
                    )

                    print(
                        f"✅ "
                        f"{completed:4}/{len(configs)} "
                        f"{country:2} "
                        f"{result['host']}:"
                        f"{result['port']} "
                        f"→ "
                        f"{result['exit_ip']} "
                        f"score="
                        f"{result['score']}"
                    )

                else:

                    print(
                        f"❌ "
                        f"{completed:4}/{len(configs)} "
                        f"{config['host']}:"
                        f"{config['port']} "
                        f"{result.get('reason', '')[:70]}"
                    )

            except Exception as e:

                print(
                    f"❌ Ошибка: {e}"
                )

    # --------------------------------------------------------
    # Рабочие
    # --------------------------------------------------------

    print()
    print("=" * 72)

    print(
        f"🟢 Реально работающих: "
        f"{len(results)}"
    )

    germany = [
        x
        for x in results
        if x["country_code"] == "DE"
    ]

    ip443 = [
        x
        for x in results
        if is_ip(x["host"])
        and x["port"] == 443
    ]

    germany_ip443 = [
        x
        for x in results
        if (
            x["country_code"] == "DE"
            and is_ip(x["host"])
            and x["port"] == 443
        )
    ]

    print(
        f"🇩🇪 Выходных IP Германии: "
        f"{len(germany)}"
    )

    print(
        f"🎯 Рабочих IP:443: "
        f"{len(ip443)}"
    )

    print(
        f"🏆 Германия + IP:443: "
        f"{len(germany_ip443)}"
    )

    # --------------------------------------------------------
    # Сортировка
    # --------------------------------------------------------

    results = sort_servers(
        results
    )

    # --------------------------------------------------------
    # Фильтр Германии
    # --------------------------------------------------------

    if GERMANY_ONLY:

        selected = [
            x
            for x in results
            if x["country_code"] == "DE"
        ]

        if (
            len(selected) < MAX_SERVERS
            and FILL_WITH_OTHER_COUNTRIES
        ):

            selected_links = {
                x["link"]
                for x in selected
            }

            for server in results:

                if (
                    server["link"]
                    not in selected_links
                ):

                    selected.append(
                        server
                    )

                    if (
                        len(selected)
                        >= MAX_SERVERS
                    ):
                        break

    else:

        selected = results

    # --------------------------------------------------------
    # TOP 30
    # --------------------------------------------------------

    selected = selected[
        :MAX_SERVERS
    ]

    print()
    print("=" * 72)
    print(
        f"🏆 TOP {len(selected)} "
        f"EXIT-SERVERS"
    )
    print("=" * 72)

    for index, server in enumerate(
        selected,
        1
    ):

        ip443 = (
            is_ip(server["host"])
            and server["port"] == 443
        )

        marker = (
            "🔥 IP:443"
            if ip443
            else "   "
        )

        same = (
            "DIRECT"
            if server["exit_equals_server"]
            else "EXIT"
        )

        print(
            f"{index:02d}. "
            f"{marker:10} "
            f"{server['host']}:"
            f"{server['port']} "
            f"→ "
            f"{server['exit_ip']} "
            f"🇩🇪 "
            f"{server['city']} "
            f"[{same}] "
            f"{server['score']}"
        )

    # --------------------------------------------------------
    # Сохранение
    # --------------------------------------------------------

    if selected:

        save_results(
            selected
        )

    else:

        print()
        print(
            "❌ Подходящих немецких "
            "серверов не найдено."
        )

        # Чтобы не осталось старой подписки
        for filename in (
            "sub_de.txt",
            "sub_de_b64.txt"
        ):

            try:
                if os.path.exists(filename):
                    os.remove(filename)
            except Exception:
                pass

    print()
    print("=" * 72)
    print("Готово.")
    print("=" * 72)


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":
    main()
```
