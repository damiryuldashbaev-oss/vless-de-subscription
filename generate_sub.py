```python
import base64
import json
import os
import shutil
import socket
import subprocess
import tempfile
import threading
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

# Сколько серверов одновременно проверять.
# Для GitHub Actions лучше не ставить слишком много.
MAX_WORKERS = 5

# Начальный диапазон локальных SOCKS-портов.
LOCAL_PORT_START = 20000

# Таймауты
TCP_TIMEOUT = 4
XRAY_START_TIMEOUT = 6
EXIT_IP_TIMEOUT = 10

# Только реальные немецкие EXIT IP.
GERMANY_ONLY = True

# Если немецких серверов меньше MAX_SERVERS,
# добирать серверами других стран?
FILL_WITH_OTHER_COUNTRIES = False

# Сколько раз проверить каждый сервер.
# 1 = быстрее.
# 2 = надёжнее.
CHECK_ATTEMPTS = 2

# Версия Xray.
# Если None, берём latest release.
XRAY_VERSION = None


# ============================================================
# GLOBAL
# ============================================================

print_lock = threading.Lock()


def log(message):
    with print_lock:
        print(message, flush=True)


# ============================================================
# HTTP
# ============================================================

def http_get(url, timeout=30, headers=None):

    if headers is None:
        headers = {}

    request = urllib.request.Request(
        url,
        headers=headers
    )

    with urllib.request.urlopen(
        request,
        timeout=timeout
    ) as response:

        return response.read()


# ============================================================
# ЗАГРУЗКА VLESS
# ============================================================

def fetch_vless_links():

    log("📥 Загружаем VLESS-базу...")

    try:

        data = http_get(
            SOURCE_URL,
            timeout=30,
            headers={
                "User-Agent": (
                    "Mozilla/5.0 "
                    "VLESS-Checker/1.0"
                )
            }
        )

        content = data.decode(
            "utf-8",
            errors="ignore"
        ).strip()

    except Exception as e:

        log(f"❌ Ошибка загрузки базы: {e}")
        return []

    # --------------------------------------------------------
    # Попытка Base64
    # --------------------------------------------------------

    try:

        normalized = content.replace(
            "\n",
            ""
        ).replace(
            "\r",
            ""
        )

        normalized += "=" * (
            (-len(normalized)) % 4
        )

        decoded = base64.b64decode(
            normalized,
            validate=False
        ).decode(
            "utf-8",
            errors="ignore"
        )

        if "vless://" in decoded:
            content = decoded
            log("🔐 Обнаружена Base64-подписка")

    except Exception:
        pass

    links = []

    for line in content.splitlines():

        line = line.strip()

        if line.startswith("vless://"):
            links.append(line)

    # Удаляем дубликаты
    links = list(
        dict.fromkeys(links)
    )

    log(
        f"📊 Уникальных VLESS: {len(links)}"
    )

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

        params = urllib.parse.parse_qs(
            parsed.query,
            keep_blank_values=True
        )

        def get(name, default=""):

            value = params.get(
                name,
                [default]
            )

            return value[0] if value else default

        tag = ""

        if "#" in link:

            tag = urllib.parse.unquote(
                link.split("#", 1)[1]
            )

        return {
            "link": link,
            "uuid": uuid,
            "host": host,
            "port": port,

            "type": get(
                "type",
                "tcp"
            ).lower(),

            "security": get(
                "security",
                "none"
            ).lower(),

            "sni": get(
                "sni"
            ),

            "fp": get(
                "fp"
            ),

            "pbk": get(
                "pbk"
            ),

            "sid": get(
                "sid"
            ),

            "flow": get(
                "flow"
            ),

            "alpn": get(
                "alpn"
            ),

            "path": get(
                "path"
            ),

            "host_header": get(
                "host"
            ),

            "service_name": get(
                "serviceName"
            ),

            "authority": get(
                "authority"
            ),

            "mode": get(
                "mode"
            ),

            "header_type": get(
                "headerType"
            ),

            "tag": tag
        }

    except Exception:

        return None


# ============================================================
# XRAY
# ============================================================

def get_xray_path():

    local = os.path.join(
        os.path.dirname(
            os.path.abspath(__file__)
        ),
        "xray"
    )

    if os.path.isfile(local):
        os.chmod(local, 0o755)
        return local

    return download_xray(local)


def download_xray(output_path):

    log("📦 Xray не найден. Скачиваем Linux x64...")

    if XRAY_VERSION:

        version = XRAY_VERSION

        if not version.startswith("v"):
            version = "v" + version

        url = (
            "https://github.com/XTLS/Xray-core/"
            f"releases/download/{version}/"
            "Xray-linux-64.zip"
        )

    else:

        api_url = (
            "https://api.github.com/repos/"
            "XTLS/Xray-core/releases/latest"
        )

        try:

            data = http_get(
                api_url,
                timeout=30,
                headers={
                    "User-Agent": "VLESS-Checker/1.0",
                    "Accept": (
                        "application/vnd.github+json"
                    )
                }
            )

            release = json.loads(
                data.decode("utf-8")
            )

            version = release["tag_name"]

            url = (
                "https://github.com/XTLS/Xray-core/"
                f"releases/download/{version}/"
                "Xray-linux-64.zip"
            )

        except Exception as e:

            log(
                f"❌ Не удалось получить "
                f"последнюю версию Xray: {e}"
            )

            return None

    log(
        f"⬇️ Скачиваем Xray {version}..."
    )

    zip_path = os.path.join(
        tempfile.gettempdir(),
        "xray-linux-64.zip"
    )

    try:

        data = http_get(
            url,
            timeout=120,
            headers={
                "User-Agent": "VLESS-Checker/1.0"
            }
        )

        with open(
            zip_path,
            "wb"
        ) as f:

            f.write(data)

    except Exception as e:

        log(
            f"❌ Ошибка скачивания Xray: {e}"
        )

        return None

    try:

        with zipfile.ZipFile(
            zip_path,
            "r"
        ) as archive:

            xray_member = None

            for name in archive.namelist():

                if name.endswith("/xray"):
                    xray_member = name
                    break

                if name == "xray":
                    xray_member = name
                    break

            if not xray_member:

                log(
                    "❌ xray отсутствует в архиве"
                )

                return None

            with archive.open(
                xray_member
            ) as source:

                with open(
                    output_path,
                    "wb"
                ) as target:

                    shutil.copyfileobj(
                        source,
                        target
                    )

        os.chmod(
            output_path,
            0o755
        )

        log(
            f"✅ Xray установлен: {output_path}"
        )

        return output_path

    except Exception as e:

        log(
            f"❌ Ошибка распаковки Xray: {e}"
        )

        return None

    finally:

        try:
            os.remove(zip_path)
        except Exception:
            pass


# ============================================================
# XRAY CONFIG
# ============================================================

def build_xray_config(
    server,
    socks_port
):

    network = server["type"]
    security = server["security"]

    stream = {
        "network": network
    }

    # --------------------------------------------------------
    # TCP
    # --------------------------------------------------------

    if network == "tcp":

        tcp_settings = {}

        if server["header_type"]:

            tcp_settings["header"] = {
                "type": server["header_type"]
            }

        if tcp_settings:
            stream["tcpSettings"] = tcp_settings

    # --------------------------------------------------------
    # WebSocket
    # --------------------------------------------------------

    elif network == "ws":

        ws = {}

        if server["path"]:
            ws["path"] = server["path"]

        if server["host_header"]:

            ws["headers"] = {
                "Host": server["host_header"]
            }

        stream["wsSettings"] = ws

    # --------------------------------------------------------
    # gRPC
    # --------------------------------------------------------

    elif network == "grpc":

        grpc = {}

        if server["service_name"]:

            grpc["serviceName"] = (
                server["service_name"]
            )

        if server["authority"]:

            grpc["authority"] = (
                server["authority"]
            )

        stream["grpcSettings"] = grpc

    # --------------------------------------------------------
    # HTTPUpgrade
    # --------------------------------------------------------

    elif network == "httpupgrade":

        settings = {}

        if server["path"]:
            settings["path"] = server["path"]

        if server["host_header"]:
            settings["host"] = server["host_header"]

        stream[
            "httpupgradeSettings"
        ] = settings

    # --------------------------------------------------------
    # XHTTP
    # --------------------------------------------------------

    elif network in (
        "xhttp",
        "splithttp"
    ):

        settings = {}

        if server["path"]:
            settings["path"] = server["path"]

        if server["host_header"]:
            settings["host"] = server["host_header"]

        if server["mode"]:
            settings["mode"] = server["mode"]

        stream[
            "xhttpSettings"
        ] = settings

    # --------------------------------------------------------
    # TLS
    # --------------------------------------------------------

    if security == "tls":

        tls = {
            "serverName": (
                server["sni"]
                or server["host"]
            ),

            "allowInsecure": True
        }

        if server["alpn"]:

            tls["alpn"] = [
                x.strip()
                for x in server["alpn"].split(",")
                if x.strip()
            ]

        if server["fp"]:
            tls["fingerprint"] = (
                server["fp"]
            )

        stream["security"] = "tls"
        stream["tlsSettings"] = tls

    # --------------------------------------------------------
    # REALITY
    # --------------------------------------------------------

    elif security == "reality":

        reality = {
            "serverName": (
                server["sni"]
                or server["host"]
            ),

            "fingerprint": (
                server["fp"]
                or "chrome"
            ),

            "publicKey": server["pbk"],

            "shortId": server["sid"]
        }

        stream["security"] = "reality"
        stream["realitySettings"] = reality

    else:

        stream["security"] = "none"

    # --------------------------------------------------------
    # USER
    # --------------------------------------------------------

    user = {
        "id": server["uuid"],
        "encryption": "none"
    }

    if server["flow"]:
        user["flow"] = server["flow"]

    # --------------------------------------------------------
    # OUTBOUND
    # --------------------------------------------------------

    outbound = {
        "protocol": "vless",

        "settings": {
            "vnext": [
                {
                    "address": server["host"],
                    "port": server["port"],
                    "users": [
                        user
                    ]
                }
            ]
        },

        "streamSettings": stream,

        "tag": "proxy"
    }

    # --------------------------------------------------------
    # FINAL CONFIG
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
                }
            }

        ],

        "outbounds": [

            outbound,

            {
                "protocol": "freedom",
                "tag": "direct"
            }

        ]
    }


# ============================================================
# TCP PORT
# ============================================================

def tcp_check(
    host,
    port
):

    try:

        with socket.create_connection(
            (host, port),
            timeout=TCP_TIMEOUT
        ):
            return True

    except Exception:

        return False


# ============================================================
# LOCAL PORT
# ============================================================

def wait_port(
    port,
    timeout
):

    deadline = (
        time.time()
        + timeout
    )

    while time.time() < deadline:

        try:

            with socket.create_connection(
                ("127.0.0.1", port),
                timeout=0.5
            ):
                return True

        except Exception:

            time.sleep(0.1)

    return False


# ============================================================
# ЗАПУСК XRAY
# ============================================================

def start_xray(
    xray_path,
    config_path,
    log_path
):

    # Сначала проверяем JSON-конфигурацию
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

        timeout=10
    )

    if test.returncode != 0:

        return None, (
            "Config error: "
            + test.stderr[-1000:]
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
        stderr=subprocess.STDOUT
    )

    return (
        process,
        log_file
    ), None


# ============================================================
# SOCKS5
# ============================================================

def socks5_connect(
    proxy_port,
    target_host,
    target_port
):

    sock = socket.create_connection(
        (
            "127.0.0.1",
            proxy_port
        ),
        timeout=EXIT_IP_TIMEOUT
    )

    sock.settimeout(
        EXIT_IP_TIMEOUT
    )

    # Greeting
    sock.sendall(
        b"\x05\x01\x00"
    )

    response = sock.recv(2)

    if response != b"\x05\x00":

        sock.close()

        raise RuntimeError(
            "SOCKS5 handshake failed"
        )

    # --------------------------------------------------------
    # Address
    # --------------------------------------------------------

    try:

        ip = socket.inet_pton(
            socket.AF_INET,
            target_host
        )

        request = (
            b"\x05\x01\x00\x01"
            + ip
            + target_port.to_bytes(
                2,
                "big"
            )
        )

    except OSError:

        hostname = target_host.encode(
            "idna"
        )

        request = (
            b"\x05\x01\x00\x03"
            + bytes([len(hostname)])
            + hostname
            + target_port.to_bytes(
                2,
                "big"
            )
        )

    sock.sendall(
        request
    )

    response = sock.recv(4)

    if len(response) != 4:

        sock.close()

        raise RuntimeError(
            "Invalid SOCKS5 response"
        )

    if response[1] != 0:

        code = response[1]

        sock.close()

        raise RuntimeError(
            f"SOCKS5 error {code}"
        )

    address_type = response[3]

    if address_type == 1:

        sock.recv(4)

    elif address_type == 3:

        length = sock.recv(1)[0]

        sock.recv(length)

    elif address_type == 4:

        sock.recv(16)

    sock.recv(2)

    return sock


# ============================================================
# HTTP ЧЕРЕЗ SOCKS
# ============================================================

def get_exit_ip(
    socks_port
):

    sock = socks5_connect(
        socks_port,
        "api.ipify.org",
        443
    )

    # TLS
    import ssl

    context = ssl.create_default_context()

    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    tls = context.wrap_socket(
        sock,
        server_hostname="api.ipify.org"
    )

    request = (
        "GET / HTTP/1.1\r\n"
        "Host: api.ipify.org\r\n"
        "User-Agent: VLESS-Checker\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode()

    tls.sendall(
        request
    )

    data = b""

    while len(data) < 16384:

        chunk = tls.recv(4096)

        if not chunk:
            break

        data += chunk

    tls.close()

    if b"\r\n\r\n" not in data:

        raise RuntimeError(
            "Invalid HTTP response"
        )

    body = data.split(
        b"\r\n\r\n",
        1
    )[1].decode(
        "utf-8",
        errors="ignore"
    ).strip()

    # Иногда ответ содержит несколько строк.
    ip = body.split()[0]

    # Проверяем, что это действительно IP
    import ipaddress

    ipaddress.ip_address(ip)

    return ip


# ============================================================
# GEO IP
# ============================================================

def geo_ip(ip):

    url = (
        "https://ipwho.is/"
        + urllib.parse.quote(ip)
    )

    try:

        data = http_get(
            url,
            timeout=10,
            headers={
                "User-Agent":
                    "VLESS-Checker/1.0"
            }
        )

        result = json.loads(
            data.decode(
                "utf-8",
                errors="ignore"
            )
        )

        return {
            "country": result.get(
                "country",
                ""
            ),

            "country_code": result.get(
                "country_code",
                ""
            ).upper(),

            "city": result.get(
                "city",
                ""
            ),

            "org": result.get(
                "connection",
                {}
            ).get(
                "org",
                ""
            )
        }

    except Exception:

        return {
            "country": "",
            "country_code": "",
            "city": "",
            "org": ""
        }


# ============================================================
# ОДИН ТЕСТ
# ============================================================

def check_server(
    xray_path,
    server,
    socks_port
):

    # --------------------------------------------------------
    # Быстрая проверка TCP
    # --------------------------------------------------------

    if not tcp_check(
        server["host"],
        server["port"]
    ):

        return {
            **server,
            "working": False,
            "reason": "TCP unavailable"
        }

    last_error = ""

    for attempt in range(
        1,
        CHECK_ATTEMPTS + 1
    ):

        work_dir = tempfile.mkdtemp(
            prefix="vless_"
        )

        process = None
        log_file = None

        try:

            config = build_xray_config(
                server,
                socks_port
            )

            config_path = os.path.join(
                work_dir,
                "config.json"
            )

            log_path = os.path.join(
                work_dir,
                "xray.log"
            )

            with open(
                config_path,
                "w",
                encoding="utf-8"
            ) as f:

                json.dump(
                    config,
                    f,
                    ensure_ascii=False
                )

            started, error = start_xray(
                xray_path,
                config_path,
                log_path
            )

            if not started:

                last_error = error
                continue

            process, log_file = started

            if not wait_port(
                socks_port,
                XRAY_START_TIMEOUT
            ):

                last_error = (
                    "Xray SOCKS did not start"
                )

                continue

            # ------------------------------------------------
            # Получаем реальный EXIT IP
            # ------------------------------------------------

            exit_ip = get_exit_ip(
                socks_port
            )

            geo = geo_ip(
                exit_ip
            )

            country_code = geo[
                "country_code"
            ]

            germany = (
                country_code == "DE"
            )

            # ------------------------------------------------
            # Рейтинг
            # ------------------------------------------------

            score = 100

            # Самый важный приоритет
            if (
                server["host"].replace(
                    ".",
                    ""
                ).isdigit()
                and server["port"] == 443
            ):

                score += 300

            # 443
            if server["port"] == 443:
                score += 100

            # Германия
            if germany:
                score += 200

            # Exit IP совпадает с адресом сервера
            if exit_ip == server["host"]:
                score += 100

            # TLS / Reality
            if server["security"] in (
                "tls",
                "reality"
            ):

                score += 30

            return {
                **server,

                "working": True,

                "exit_ip": exit_ip,

                "country": geo["country"],

                "country_code": country_code,

                "city": geo["city"],

                "org": geo["org"],

                "exit_equals_server": (
                    exit_ip == server["host"]
                ),

                "score": score,

                "attempt": attempt
            }

        except Exception as e:

            last_error = str(e)

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
                work_dir,
                ignore_errors=True
            )

    return {
        **server,
        "working": False,
        "reason": last_error
    }


# ============================================================
# SORT
# ============================================================

def sort_servers(servers):

    def is_ip(value):

        try:
            import ipaddress
            ipaddress.ip_address(value)
            return True
        except Exception:
            return False

    def key(server):

        ip_443 = (
            is_ip(server["host"])
            and server["port"] == 443
        )

        germany = (
            server["country_code"]
            == "DE"
        )

        exit_same = (
            server["exit_equals_server"]
        )

        return (
            germany,
            ip_443,
            exit_same,
            server["port"] == 443,
            server["score"]
        )

    return sorted(
        servers,
        key=key,
        reverse=True
    )


# ============================================================
# SAVE
# ============================================================

def save_results(
    servers
):

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

    encoded = base64.b64encode(
        text.encode("utf-8")
    ).decode("ascii")

    with open(
        "sub_de_b64.txt",
        "w",
        encoding="utf-8"
    ) as f:

        f.write(encoded)

    # --------------------------------------------------------
    # JSON report
    # --------------------------------------------------------

    report = []

    for index, server in enumerate(
        servers,
        1
    ):

        report.append({

            "rank": index,

            "server": (
                f"{server['host']}:"
                f"{server['port']}"
            ),

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

            "score": server.get(
                "score",
                0
            ),

            "exit_equals_server": server.get(
                "exit_equals_server",
                False
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

    log("")
    log("💾 Файлы сохранены:")
    log("   sub_de.txt")
    log("   sub_de_b64.txt")
    log("   servers_report.json")


# ============================================================
# MAIN
# ============================================================

def main():

    log("=" * 70)
    log(" VLESS DE EXIT-IP CHECKER")
    log("=" * 70)

    # --------------------------------------------------------
    # Xray
    # --------------------------------------------------------

    xray_path = get_xray()

    if not xray_path:

        log(
            "❌ Xray не удалось установить."
        )

        raise SystemExit(1)

    # --------------------------------------------------------
    # VLESS
    # --------------------------------------------------------

    links = fetch_vless_links()

    if not links:

        log(
            "❌ VLESS-конфигурации не найдены."
        )

        raise SystemExit(1)

    servers = []

    for link in links:

        parsed = parse_vless(
            link
        )

        if parsed:
            servers.append(parsed)

    log(
        f"🔎 Корректных конфигураций: "
        f"{len(servers)}"
    )

    if not servers:

        raise SystemExit(1)

    # --------------------------------------------------------
    # IP:443 ставим на проверку первыми
    # --------------------------------------------------------

    def priority(server):

        try:

            import ipaddress

            is_server_ip = True

            ipaddress.ip_address(
                server["host"]
            )

        except Exception:

            is_server_ip = False

        return (
            is_server_ip
            and server["port"] == 443,

            server["port"] == 443,

            is_server_ip
        )

    servers.sort(
        key=priority,
        reverse=True
    )

    # --------------------------------------------------------
    # Проверяем
    # --------------------------------------------------------

    log("")
    log(
        f"⚡ Проверяем {len(servers)} "
        f"конфигураций через Xray..."
    )

    log(
        f"   Параллельно: {MAX_WORKERS}"
    )

    log(
        f"   Проверок на сервер: "
        f"{CHECK_ATTEMPTS}"
    )

    results = []

    # --------------------------------------------------------
    # Уникальные локальные порты
    # --------------------------------------------------------

    jobs = []

    for index, server in enumerate(
        servers
    ):

        socks_port = (
            LOCAL_PORT_START
            + index
        )

        jobs.append(
            (
                server,
                socks_port
            )
        )

    # --------------------------------------------------------
    # ThreadPool
    # --------------------------------------------------------

    completed = 0

    with ThreadPoolExecutor(
        max_workers=MAX_WORKERS
    ) as executor:

        futures = {}

        for server, port in jobs:

            future = executor.submit(
                check_server,
                xray_path,
                server,
                port
            )

            futures[future] = server

        for future in as_completed(
            futures
        ):

            completed += 1

            server = futures[future]

            try:

                result = future.result()

                if result["working"]:

                    results.append(
                        result
                    )

                    log(
                        f"✅ "
                        f"{completed}/"
                        f"{len(jobs)} "
                        f"{result['host']}:"
                        f"{result['port']} "
                        f"→ "
                        f"{result['exit_ip']} "
                        f"{result['country_code']} "
                        f"score="
                        f"{result['score']}"
                    )

                else:

                    log(
                        f"❌ "
                        f"{completed}/"
                        f"{len(jobs)} "
                        f"{server['host']}:"
                        f"{server['port']} "
                        f"{result.get('reason', '')[:60]}"
                    )

            except Exception as e:

                log(
                    f"❌ Ошибка проверки "
                    f"{server['host']}: "
                    f"{e}"
                )

    # --------------------------------------------------------
    # Statistics
    # --------------------------------------------------------

    log("")
    log("=" * 70)

    germany = [
        x for x in results
        if x["country_code"] == "DE"
    ]

    germany_ip443 = [
        x for x in germany
        if (
            x["port"] == 443
            and "." in x["host"]
        )
    ]

    log(
        f"🟢 Рабочих VLESS: "
        f"{len(results)}"
    )

    log(
        f"🇩🇪 Немецких EXIT IP: "
        f"{len(germany)}"
    )

    log(
        f"🔥 Германия + IP:443: "
        f"{len(germany_ip443)}"
    )

    # --------------------------------------------------------
    # Sort
    # --------------------------------------------------------

    results = sort_servers(
        results
    )

    # --------------------------------------------------------
    # Germany filter
    # --------------------------------------------------------

    if GERMANY_ONLY:

        selected = [
            x for x in results
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

                    if len(selected) >= MAX_SERVERS:
                        break

    else:

        selected = results

    selected = selected[
        :MAX_SERVERS
    ]

    # --------------------------------------------------------
    # TOP
    # --------------------------------------------------------

    log("")
    log("=" * 70)
    log(
        f"🏆 TOP {len(selected)}"
    )
    log("=" * 70)

    for index, server in enumerate(
        selected,
        1
    ):

        ip443 = (
            "." in server["host"]
            and server["port"] == 443
        )

        marker = (
            "🔥"
            if ip443
            else " "
        )

        log(
            f"{index:02d}. "
            f"{marker} "
            f"{server['host']}:"
            f"{server['port']} "
            f"→ "
            f"{server['exit_ip']} "
            f"🇩🇪 "
            f"{server['city']} "
            f"[{server['score']}]"
        )

    # --------------------------------------------------------
    # Save
    # --------------------------------------------------------

    if selected:

        save_results(
            selected
        )

    else:

        log("")
        log(
            "❌ Подходящих немецких "
            "серверов не найдено."
        )

        # Чтобы не оставить старую подписку
        for filename in (
            "sub_de.txt",
            "sub_de_b64.txt"
        ):

            try:

                if os.path.exists(
                    filename
                ):
                    os.remove(
                        filename
                    )

            except Exception:
                pass

        # GitHub Actions должен видеть
        # отсутствие результата как ошибку.
        raise SystemExit(2)

    log("")
    log("=" * 70)
    log("✅ Готово")
    log("=" * 70)


if __name__ == "__main__":
    main()
```
