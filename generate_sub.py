```python
import base64
import ipaddress
import json
import os
import shutil
import socket
import ssl
import subprocess
import tempfile
import time
import urllib.parse
import urllib.request
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed


SOURCE_URL = (
    "https://raw.githack.com/igareck/"
    "vpn-configs-for-russia/main/WHITE-CIDR-RU-all.txt"
)

MAX_SERVERS = 30
MAX_WORKERS = 5
CHECK_ATTEMPTS = 2

XRAY_DIR = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    ".xray"
)

LOCAL_PORT_START = 20000

TCP_TIMEOUT = 5
XRAY_START_TIMEOUT = 8
PROXY_TIMEOUT = 15


def log(text):
    print(text, flush=True)


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
# DOWNLOAD VLESS DATABASE
# ============================================================

def fetch_vless_links():

    log("📥 Загружаем базу VLESS...")

    try:

        data = http_get(
            SOURCE_URL,
            timeout=30,
            headers={
                "User-Agent": "Mozilla/5.0"
            }
        )

        content = data.decode(
            "utf-8",
            errors="ignore"
        ).strip()

    except Exception as e:

        log(f"❌ Ошибка загрузки: {e}")
        return []

    # --------------------------------------------------------
    # Base64 subscription
    # --------------------------------------------------------

    try:

        clean = (
            content
            .replace("\n", "")
            .replace("\r", "")
            .replace(" ", "")
        )

        clean += "=" * (
            (-len(clean)) % 4
        )

        decoded = base64.b64decode(
            clean,
            validate=False
        ).decode(
            "utf-8",
            errors="ignore"
        )

        if "vless://" in decoded:
            content = decoded

    except Exception:
        pass

    links = []

    for line in content.splitlines():

        line = line.strip()

        if line.startswith("vless://"):
            links.append(line)

    links = list(dict.fromkeys(links))

    log(
        f"📊 Найдено уникальных VLESS: "
        f"{len(links)}"
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

        if not parsed.username:
            return None

        if not parsed.hostname:
            return None

        if not parsed.port:
            return None

        params = urllib.parse.parse_qs(
            parsed.query,
            keep_blank_values=True
        )

        def get(name, default=""):

            values = params.get(name)

            if not values:
                return default

            return values[0]

        tag = ""

        if "#" in link:

            tag = urllib.parse.unquote(
                link.split("#", 1)[1]
            )

        return {
            "link": link,
            "uuid": parsed.username,
            "host": parsed.hostname,
            "port": parsed.port,

            "type": get(
                "type",
                "tcp"
            ).lower(),

            "security": get(
                "security",
                "none"
            ).lower(),

            "sni": get("sni"),
            "fp": get("fp"),
            "pbk": get("pbk"),
            "sid": get("sid"),
            "flow": get("flow"),
            "alpn": get("alpn"),

            "path": get("path"),

            "host_header": get("host"),

            "service_name": get(
                "serviceName"
            ),

            "authority": get(
                "authority"
            ),

            "mode": get("mode"),

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

def get_xray():

    os.makedirs(
        XRAY_DIR,
        exist_ok=True
    )

    xray_path = os.path.join(
        XRAY_DIR,
        "xray"
    )

    if os.path.isfile(xray_path):

        os.chmod(
            xray_path,
            0o755
        )

        return xray_path

    log("📦 Xray не найден. Скачиваем...")

    api_url = (
        "https://api.github.com/repos/"
        "XTLS/Xray-core/releases/latest"
    )

    try:

        data = http_get(
            api_url,
            timeout=30,
            headers={
                "User-Agent":
                    "VLESS-Checker"
            }
        )

        release = json.loads(
            data.decode("utf-8")
        )

        version = release["tag_name"]

    except Exception as e:

        log(
            f"❌ Не удалось получить версию Xray: {e}"
        )

        return None

    url = (
        "https://github.com/XTLS/Xray-core/"
        f"releases/download/{version}/"
        "Xray-linux-64.zip"
    )

    zip_path = os.path.join(
        XRAY_DIR,
        "xray.zip"
    )

    try:

        data = http_get(
            url,
            timeout=120,
            headers={
                "User-Agent":
                    "VLESS-Checker"
            }
        )

        with open(
            zip_path,
            "wb"
        ) as f:

            f.write(data)

        with zipfile.ZipFile(
            zip_path,
            "r"
        ) as archive:

            names = archive.namelist()

            xray_member = None

            for name in names:

                if name == "xray":
                    xray_member = name
                    break

                if name.endswith("/xray"):
                    xray_member = name
                    break

            if not xray_member:
                raise RuntimeError(
                    "xray отсутствует в архиве"
                )

            with archive.open(
                xray_member
            ) as source:

                with open(
                    xray_path,
                    "wb"
                ) as target:

                    shutil.copyfileobj(
                        source,
                        target
                    )

        os.chmod(
            xray_path,
            0o755
        )

        log(
            f"✅ Xray {version} установлен"
        )

        return xray_path

    except Exception as e:

        log(
            f"❌ Ошибка Xray: {e}"
        )

        return None

    finally:

        try:
            os.remove(zip_path)
        except Exception:
            pass


# ============================================================
# BUILD XRAY CONFIG
# ============================================================

def build_config(server, socks_port):

    network = server["type"]
    security = server["security"]

    stream = {
        "network": network
    }

    # TCP
    if network == "tcp":

        settings = {}

        if server["header_type"]:

            settings["header"] = {
                "type":
                    server["header_type"]
            }

        if settings:
            stream["tcpSettings"] = settings

    # WebSocket
    elif network == "ws":

        settings = {}

        if server["path"]:
            settings["path"] = server["path"]

        if server["host_header"]:

            settings["headers"] = {
                "Host":
                    server["host_header"]
            }

        stream["wsSettings"] = settings

    # gRPC
    elif network == "grpc":

        settings = {}

        if server["service_name"]:

            settings["serviceName"] = (
                server["service_name"]
            )

        if server["authority"]:

            settings["authority"] = (
                server["authority"]
            )

        stream["grpcSettings"] = settings

    # HTTPUpgrade
    elif network == "httpupgrade":

        settings = {}

        if server["path"]:
            settings["path"] = server["path"]

        if server["host_header"]:
            settings["host"] = (
                server["host_header"]
            )

        stream[
            "httpupgradeSettings"
        ] = settings

    # XHTTP / SplitHTTP
    elif network in (
        "xhttp",
        "splithttp"
    ):

        settings = {}

        if server["path"]:
            settings["path"] = server["path"]

        if server["host_header"]:
            settings["host"] = (
                server["host_header"]
            )

        if server["mode"]:
            settings["mode"] = (
                server["mode"]
            )

        stream[
            "xhttpSettings"
        ] = settings

    # TLS
    if security == "tls":

        tls = {
            "serverName": (
                server["sni"]
                or server["host"]
            ),

            "allowInsecure": True
        }

        if server["fp"]:

            tls["fingerprint"] = (
                server["fp"]
            )

        if server["alpn"]:

            tls["alpn"] = [
                x.strip()
                for x in
                server["alpn"].split(",")
                if x.strip()
            ]

        stream["security"] = "tls"

        stream["tlsSettings"] = tls

    # REALITY
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

            "publicKey":
                server["pbk"],

            "shortId":
                server["sid"]
        }

        stream["security"] = "reality"

        stream[
            "realitySettings"
        ] = reality

    else:

        stream["security"] = "none"

    # VLESS user
    user = {
        "id": server["uuid"],
        "encryption": "none"
    }

    if server["flow"]:
        user["flow"] = server["flow"]

    return {

        "log": {
            "loglevel": "error"
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

            {
                "protocol": "vless",

                "settings": {
                    "vnext": [
                        {
                            "address":
                                server["host"],

                            "port":
                                server["port"],

                            "users": [
                                user
                            ]
                        }
                    ]
                },

                "streamSettings":
                    stream,

                "tag": "proxy"
            },

            {
                "protocol": "freedom",
                "tag": "direct"
            }
        ]
    }


# ============================================================
# TCP CHECK
# ============================================================

def tcp_check(host, port):

    try:

        with socket.create_connection(
            (host, port),
            timeout=TCP_TIMEOUT
        ):

            return True

    except Exception:

        return False


# ============================================================
# WAIT SOCKS
# ============================================================

def wait_port(port):

    deadline = (
        time.time()
        + XRAY_START_TIMEOUT
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
# START XRAY
# ============================================================

def start_xray(
    xray_path,
    config_path,
    log_path
):

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

        return None

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

    return process, log_file


# ============================================================
# SOCKS5 CONNECTION
# ============================================================

def socks5_connect(
    proxy_port,
    host,
    port
):

    sock = socket.create_connection(
        (
            "127.0.0.1",
            proxy_port
        ),

        timeout=PROXY_TIMEOUT
    )

    sock.settimeout(
        PROXY_TIMEOUT
    )

    # Greeting
    sock.sendall(
        b"\x05\x01\x00"
    )

    response = sock.recv(2)

    if response != b"\x05\x00":

        sock.close()

        raise RuntimeError(
            "SOCKS authentication failed"
        )

    # --------------------------------------------------------
    # Address
    # --------------------------------------------------------

    try:

        ip = socket.inet_pton(
            socket.AF_INET,
            host
        )

        request = (
            b"\x05\x01\x00\x01"
            + ip
            + port.to_bytes(
                2,
                "big"
            )
        )

    except OSError:

        hostname = host.encode(
            "idna"
        )

        request = (
            b"\x05\x01\x00\x03"
            + bytes([len(hostname)])
            + hostname
            + port.to_bytes(
                2,
                "big"
            )
        )

    sock.sendall(request)

    response = sock.recv(4)

    if len(response) != 4:

        sock.close()

        raise RuntimeError(
            "Invalid SOCKS response"
        )

    if response[1] != 0:

        code = response[1]

        sock.close()

        raise RuntimeError(
            f"SOCKS connection failed: {code}"
        )

    # Read bind address
    if response[3] == 1:

        sock.recv(4)

    elif response[3] == 3:

        length = sock.recv(1)[0]
        sock.recv(length)

    elif response[3] == 4:

        sock.recv(16)

    sock.recv(2)

    return sock


# ============================================================
# GET EXIT IP
# ============================================================

def get_exit_ip(socks_port):

    sock = socks5_connect(
        socks_port,
        "api.ipify.org",
        443
    )

    context = ssl.create_default_context()

    context.check_hostname = False

    context.verify_mode = (
        ssl.CERT_NONE
    )

    tls = context.wrap_socket(
        sock,
        server_hostname="api.ipify.org"
    )

    request = (
        "GET / HTTP/1.1\r\n"
        "Host: api.ipify.org\r\n"
        "User-Agent: Mozilla/5.0\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode()

    tls.sendall(request)

    data = b""

    while True:

        chunk = tls.recv(4096)

        if not chunk:
            break

        data += chunk

        if len(data) > 16384:
            break

    tls.close()

    body = data.split(
        b"\r\n\r\n",
        1
    )[1].decode(
        "utf-8",
        errors="ignore"
    ).strip()

    ip = body.split()[0]

    ipaddress.ip_address(ip)

    return ip


# ============================================================
# GEO IP
# ============================================================

def get_geo(ip):

    try:

        data = http_get(
            "https://ipwho.is/"
            + urllib.parse.quote(ip),

            timeout=10,

            headers={
                "User-Agent":
                    "Mozilla/5.0"
            }
        )

        result = json.loads(
            data.decode(
                "utf-8",
                errors="ignore"
            )
        )

        connection = result.get(
            "connection",
            {}
        )

        return {
            "country":
                result.get(
                    "country",
                    ""
                ),

            "country_code":
                result.get(
                    "country_code",
                    ""
                ).upper(),

            "city":
                result.get(
                    "city",
                    ""
                ),

            "org":
                connection.get(
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
# CHECK ONE SERVER
# ============================================================

def check_server(
    xray_path,
    server,
    socks_port
):

    # --------------------------------------------------------
    # TCP
    # --------------------------------------------------------

    if not tcp_check(
        server["host"],
        server["port"]
    ):

        return None

    for attempt in range(
        CHECK_ATTEMPTS
    ):

        work_dir = tempfile.mkdtemp(
            prefix="vless-check-"
        )

        process = None
        log_file = None

        try:

            config = build_config(
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

            started = start_xray(
                xray_path,
                config_path,
                log_path
            )

            if not started:
                continue

            process, log_file = started

            if not wait_port(
                socks_port
            ):

                continue

            # ------------------------------------------------
            # REAL EXIT IP
            # ------------------------------------------------

            exit_ip = get_exit_ip(
                socks_port
            )

            geo = get_geo(
                exit_ip
            )

            country_code = geo[
                "country_code"
            ]

            is_germany = (
                country_code == "DE"
            )

            # ------------------------------------------------
            # SCORE
            # ------------------------------------------------

            score = 0

            # Реальная Германия
            if is_germany:
                score += 1000

            # IP:443
            try:

                ipaddress.ip_address(
                    server["host"]
                )

                server_is_ip = True

            except ValueError:

                server_is_ip = False

            if server_is_ip:
                score += 100

            if server["port"] == 443:
                score += 300

            # Особый приоритет IP:443
            if (
                server_is_ip
                and server["port"] == 443
            ):

                score += 1000

            # Если EXIT IP совпадает с IP сервера
            if exit_ip == server["host"]:

                score += 150

            # TLS / Reality
            if server["security"] in (
                "tls",
                "reality"
            ):

                score += 50

            return {
                **server,

                "exit_ip":
                    exit_ip,

                "country":
                    geo["country"],

                "country_code":
                    country_code,

                "city":
                    geo["city"],

                "org":
                    geo["org"],

                "score":
                    score,

                "server_is_ip":
                    server_is_ip,

                "working":
                    True
            }

        except Exception:

            pass

        finally:

            if process:

                try:

                    process.terminate()

                    process.wait(
                        timeout=2
                    )

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

    return None


# ============================================================
# SAVE
# ============================================================

def save_files(servers):

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

    report = []

    for index, server in enumerate(
        servers,
        1
    ):

        report.append({
            "rank": index,

            "server":
                f"{server['host']}:"
                f"{server['port']}",

            "exit_ip":
                server["exit_ip"],

            "country":
                server["country"],

            "country_code":
                server["country_code"],

            "city":
                server["city"],

            "organization":
                server["org"],

            "score":
                server["score"],

            "tag":
                server["tag"]
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


# ============================================================
# MAIN
# ============================================================

def main():

    log("=" * 70)
    log(" VLESS SERVER CHECKER")
    log("=" * 70)

    # --------------------------------------------------------
    # Xray
    # --------------------------------------------------------

    xray_path = get_xray()

    if not xray_path:

        raise SystemExit(
            "Xray не установлен"
        )

    # --------------------------------------------------------
    # Download
    # --------------------------------------------------------

    links = fetch_vless_links()

    if not links:

        raise SystemExit(
            "VLESS ссылки не найдены"
        )

    servers = []

    for link in links:

        server = parse_vless(
            link
        )

        if server:
            servers.append(
                server
            )

    log(
        f"🔍 К проверке: "
        f"{len(servers)}"
    )

    # --------------------------------------------------------
    # Сначала IP:443
    # --------------------------------------------------------

    def first_priority(server):

        try:

            ipaddress.ip_address(
                server["host"]
            )

            is_ip = True

        except ValueError:

            is_ip = False

        return (
            is_ip and server["port"] == 443,
            server["port"] == 443,
            is_ip
        )

    servers.sort(
        key=first_priority,
        reverse=True
    )

    # --------------------------------------------------------
    # CHECK
    # --------------------------------------------------------

    working = []

    log("")
    log(
        "⚡ Проверяем реальные EXIT IP..."
    )

    with ThreadPoolExecutor(
        max_workers=MAX_WORKERS
    ) as executor:

        futures = {}

        for index, server in enumerate(
            servers
        ):

            port = (
                LOCAL_PORT_START
                + index
            )

            future = executor.submit(
                check_server,
                xray_path,
                server,
                port
            )

            futures[future] = server

        done = 0

        for future in as_completed(
            futures
        ):

            done += 1

            server = futures[future]

            try:

                result = future.result()

            except Exception:

                result = None

            if result:

                working.append(
                    result
                )

                log(
                    f"✅ {done}/"
                    f"{len(servers)} "
                    f"{result['host']}:"
                    f"{result['port']} "
                    f"→ "
                    f"{result['exit_ip']} "
                    f"{result['country_code']} "
                    f"{result['city']}"
                )

            else:

                log(
                    f"❌ {done}/"
                    f"{len(servers)} "
                    f"{server['host']}:"
                    f"{server['port']}"
                )

    # --------------------------------------------------------
    # Только Германия
    # --------------------------------------------------------

    germany = [
        server
        for server in working
        if server["country_code"] == "DE"
    ]

    # --------------------------------------------------------
    # Сортировка
    #
    # 1. Германия
    # 2. IP:443
    # 3. порт 443
    # 4. реальный рабочий EXIT IP
    # --------------------------------------------------------

    germany.sort(
        key=lambda server: (
            (
                server["server_is_ip"]
                and server["port"] == 443
            ),
            server["port"] == 443,
            server["score"]
        ),
        reverse=True
    )

    selected = germany[
        :MAX_SERVERS
    ]

    # --------------------------------------------------------
    # RESULT
    # --------------------------------------------------------

    log("")
    log("=" * 70)
    log(
        f"🟢 Рабочих: {len(working)}"
    )
    log(
        f"🇩🇪 Германия: {len(germany)}"
    )
    log(
        f"🔥 Германия IP:443: "
        f"{sum(
            1
            for x in germany
            if (
                x["server_is_ip"]
                and x["port"] == 443
            )
        )}"
    )
    log(
        f"🏆 В подписку: {len(selected)}"
    )
    log("=" * 70)

    # --------------------------------------------------------
    # TOP
    # --------------------------------------------------------

    for index, server in enumerate(
        selected,
        1
    ):

        special = (
            "🔥"
            if (
                server["server_is_ip"]
                and server["port"] == 443
            )
            else " "
        )

        log(
            f"{index:02d}. "
            f"{special} "
            f"{server['host']}:"
            f"{server['port']} "
            f"→ "
            f"{server['exit_ip']} "
            f"🇩🇪 "
            f"{server['city']} "
            f"score={server['score']}"
        )

    # --------------------------------------------------------
    # SAVE
    # --------------------------------------------------------

    if not selected:

        log(
            "❌ Рабочих немецких серверов "
            "не найдено."
        )

        # Не оставляем старую подписку
        for filename in (
            "sub_de.txt",
            "sub_de_b64.txt",
            "servers_report.json"
        ):

            try:

                os.remove(filename)

            except FileNotFoundError:
                pass

        raise SystemExit(2)

    save_files(
        selected
    )

    log("")
    log("✅ Подписка обновлена.")
    log("   sub_de.txt")
    log("   sub_de_b64.txt")
    log("   servers_report.json")


if __name__ == "__main__":
    main()
```
