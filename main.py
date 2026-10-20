#!/usr/bin/env python3
# Engineerix Finder
# Copyright (c) 2026 Julio Castro Canales. Todos los derechos reservados.
# Software propietario: queda prohibida su copia, modificacion o distribucion
# sin autorizacion por escrito del autor.
"""
Engineerix Finder - descubre y administra equipos Engineerix en una o varias subredes.

Funciona en Windows y Linux SIN instalar nada mas que Python.
  (En Linux, tkinter viene en un paquete aparte: sudo apt install python3-tk)

Que usa de cada sistema
  - Lista de adaptadores: PowerShell (Windows) o "ip -j addr" (Linux).
  - Detectar segmento:    Linux  -> socket AF_PACKET (necesita sudo)
                          Windows-> pktmon, la herramienta de captura que trae Windows 10 (1809+) y 11
                                    (necesita administrador; el boton "Reabrir como administrador" lo hace)
  - IP temporal del PC:   netsh (Windows) o "ip addr" (Linux), tambien con permisos de administrador.

Como funciona
  1. Escaneo: barrido TCP al puerto 80 de cada IP de las subredes y consulta
     web_cgi_main.cgi?get_network_base_data con el usuario admin y la contrasena
     escrita en el programa (no se guarda en disco).
  2. Detectar segmento: escucha trafico ARP/DHCP para ver las IP y MAC de lo conectado
     (aunque no sepas su rango), propone el segmento y, si tu PC no esta en el,
     agrega una IP temporal al adaptador.
  3. La MAC sale de la tabla ARP (solo en tu misma LAN/VLAN).

Pendiente: el boton Send queda desactivado hasta conocer la peticion set_network
de los equipos (ver build_set_request).
"""
import base64
import csv
import getpass
import hashlib
import hmac
import ipaddress
import json
import os
import platform
import queue
import re
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk

USER = "admin"
TCP_TIMEOUT = 0.7
HTTP_TIMEOUT = 4.0
MAX_HOSTS = 4096
WORKERS = 64
DETECT_SECONDS = 20
ENGINEERIX_OUIS = {"90:A9:F7"}  # confirmado solo en un equipo; otros modelos pueden diferir
IS_WINDOWS = platform.system() == "Windows"
IS_LINUX = platform.system() == "Linux"
SET_READY = False  # pasar a True cuando build_set_request este implementada

COLUMNS = [
    ("ip", "IP Address", 120),
    ("mask", "Subnet Mask", 120),
    ("gw", "Default Gateway", 120),
    ("mac", "MAC Address", 140),
    ("vendor", "Vendor", 90),
    ("mode", "Modo", 80),
    ("dns", "DNS", 170),
    ("status", "Estado", 190),
]

MAC_RE = r"[0-9A-Fa-f]{2}(?:[-:][0-9A-Fa-f]{2}){5}"

# Paleta corporativa
COLOR_BG = "#121212"             # fondo principal
COLOR_CARD = "#1E1E1E"           # tarjetas / contenedores
COLOR_FIELD = "#2A2A2A"          # campos de texto y botones secundarios
COLOR_PRIMARY = "#8B263E"        # rojo guinda del logo
COLOR_PRIMARY_HOVER = "#A32D4B"
COLOR_TEXT = "#FFFFFF"
COLOR_MUTED = "#AAAAAA"
COLOR_BORDER = "#333333"
COLOR_WARN = "#E57373"


# --------------------------------------------------------------------------
# Autoria y acceso
# --------------------------------------------------------------------------
AUTHOR = "Julio Castro Canales"
COPYRIGHT_YEAR = "2026"
COPYRIGHT_TEXT = f"© {COPYRIGHT_YEAR} {AUTHOR}. Todos los derechos reservados."
__author__ = AUTHOR
_NOTICE_SHA256 = "b4f2ce24c4d387abe928250acb989a984576e4ea5238038aa19272f03e11f1a8"  # si cambias AUTHOR o COPYRIGHT_YEAR, actualiza este valor

# Contraseña de acceso al programa. Vacio = sin contraseña.
# Para crearla ejecuta:  python engineerix_finder.py --make-hash   y pega aqui la linea que imprime.
# Si la olvidas, vuelve a dejar ACCESS_HASH = "" en el codigo.
ACCESS_HASH = ""


def notice_intact():
    """Comprueba que la nota de autoria no fue alterada (disuasivo, no es una proteccion absoluta)."""
    return hashlib.sha256(f"{AUTHOR}|{COPYRIGHT_YEAR}".encode("utf-8")).hexdigest() == _NOTICE_SHA256


def make_access_hash(password, iterations=200_000):
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return f"pbkdf2${iterations}${salt.hex()}${dk.hex()}"


def check_access(password, stored):
    try:
        scheme, iters, salt_hex, hash_hex = stored.split("$")
        dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt_hex), int(iters))
        return scheme == "pbkdf2" and hmac.compare_digest(dk.hex(), hash_hex)
    except Exception:
        return False


def make_hash_cli():
    p1 = getpass.getpass("Nueva contraseña de acceso: ")
    p2 = getpass.getpass("Repítela: ")
    if not p1 or p1 != p2:
        print("Las contraseñas no coinciden o están vacías.")
        return 1
    print('\nPega esta línea en engineerix_finder.py, reemplazando  ACCESS_HASH = "" :\n')
    print(f'ACCESS_HASH = "{make_access_hash(p1)}"')
    return 0


def ask_access():
    root = tk.Tk()
    root.withdraw()
    try:
        for _ in range(3):
            pw = simpledialog.askstring("Acceso restringido",
                                        f"Software de {AUTHOR}.\nEscribe la contraseña de acceso:",
                                        show="*", parent=root)
            if pw is None:
                return False
            if check_access(pw, ACCESS_HASH):
                return True
            messagebox.showerror("Acceso denegado", "Contraseña incorrecta.", parent=root)
        return False
    finally:
        root.destroy()


def main():
    if "--make-hash" in sys.argv:
        sys.exit(make_hash_cli())
    if not notice_intact():
        root = tk.Tk()
        root.withdraw()
        messagebox.showerror("Software protegido",
                             f"Este software es propiedad de {AUTHOR}.\n"
                             "La nota de autoría fue modificada, así que el programa no se ejecutará.")
        sys.exit(1)
    if ACCESS_HASH and not ask_access():
        sys.exit(1)
    App().mainloop()


def resource_path(name):
    """Ruta de un archivo junto al script o dentro del .exe de PyInstaller."""
    base = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base, name)


def setup_styles(root):
    root.configure(bg=COLOR_BG)
    for opt, val in (("background", COLOR_FIELD), ("foreground", COLOR_TEXT),
                     ("selectBackground", COLOR_PRIMARY), ("selectForeground", COLOR_TEXT)):
        root.option_add(f"*TCombobox*Listbox.{opt}", val)
    style = ttk.Style(root)
    style.theme_use("clam")
    style.configure(".", background=COLOR_CARD, foreground=COLOR_TEXT, fieldbackground=COLOR_CARD)
    style.configure("Treeview", background=COLOR_CARD, foreground=COLOR_TEXT,
                    fieldbackground=COLOR_CARD, rowheight=25, borderwidth=0)
    style.configure("Treeview.Heading", background="#262626", foreground=COLOR_TEXT,
                    font=("Segoe UI", 10, "bold"), relief="flat")
    style.map("Treeview", background=[("selected", COLOR_PRIMARY)], foreground=[("selected", COLOR_TEXT)])
    style.map("Treeview.Heading", background=[("active", COLOR_BORDER)])
    style.configure("TCombobox", fieldbackground=COLOR_FIELD, background=COLOR_FIELD, foreground=COLOR_TEXT,
                    arrowcolor=COLOR_TEXT, bordercolor=COLOR_BORDER)
    style.map("TCombobox", fieldbackground=[("readonly", COLOR_FIELD)], foreground=[("readonly", COLOR_TEXT)],
              selectbackground=[("readonly", COLOR_FIELD)], selectforeground=[("readonly", COLOR_TEXT)])
    style.configure("TSpinbox", fieldbackground=COLOR_FIELD, background=COLOR_FIELD, foreground=COLOR_TEXT,
                    arrowcolor=COLOR_TEXT, insertcolor=COLOR_TEXT, bordercolor=COLOR_BORDER)
    style.configure("TEntry", fieldbackground=COLOR_FIELD, foreground=COLOR_TEXT, insertcolor=COLOR_TEXT,
                    bordercolor=COLOR_BORDER)
    style.configure("TButton", background=COLOR_FIELD, foreground=COLOR_TEXT, bordercolor=COLOR_BORDER,
                    focuscolor=COLOR_FIELD)
    style.map("TButton", background=[("active", COLOR_PRIMARY)])
    style.configure("Vertical.TScrollbar", background=COLOR_FIELD, troughcolor=COLOR_CARD,
                    arrowcolor=COLOR_TEXT, bordercolor=COLOR_BORDER)
    for widget in ("Treeview", "TCombobox", "TSpinbox", "TEntry"):
        style.configure(widget, lightcolor=COLOR_BORDER, darkcolor=COLOR_BORDER, bordercolor=COLOR_BORDER)


# --------------------------------------------------------------------------
# Red / API
# --------------------------------------------------------------------------
def auth_cookie(password, user=USER):
    """Cookie Authorization = base64(base64('usuario:' + md5(password)))."""
    digest = hashlib.md5(password.encode("utf-8")).hexdigest()
    inner = base64.b64encode(f"{user}:{digest}".encode()).decode()
    outer = base64.b64encode(inner.encode()).decode()
    return urllib.parse.quote(outer, safe="")


def tcp_open(ip, port=80):
    try:
        with socket.create_connection((ip, port), timeout=TCP_TIMEOUT):
            return True
    except OSError:
        return False


def http_request(ip, path, body=None, cookie=None):
    req = urllib.request.Request(f"http://{ip}{path}", data=body)
    if body is not None:
        req.add_header("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
        req.add_header("X-Requested-With", "XMLHttpRequest")
    if cookie:
        req.add_header("Cookie", f"Authorization={cookie}")
    req.add_header("Referer", f"http://{ip}/index.html")
    with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
        return resp.read().decode("utf-8", errors="replace")


def api_call(ip, action, cookie, body=None):
    return http_request(
        ip, f"/cgi-bin/web_cgi_main.cgi?{action}",
        body=action.encode() if body is None else body, cookie=cookie,
    )


def probe(ip, password):
    """Devuelve un dict con los datos del equipo o None si no es Engineerix."""
    if not tcp_open(ip, 80):
        return None
    try:
        if not password:
            raise ValueError("sin contrasena")  # modo solo deteccion
        raw = api_call(ip, "get_network_base_data", auth_cookie(password))
        data = json.loads(raw)
        if isinstance(data, dict) and "result" in data and "iPAddress" in data:
            dns = ""
            if data.get("primaryDNS") or data.get("secondaryDNS"):
                dns = f'{data.get("primaryDNS", "")} / {data.get("secondaryDNS", "")}'
            return {
                "ip": data.get("iPAddress") or ip,
                "mask": data.get("subnetMask", ""),
                "gw": data.get("defaultGateway", ""),
                "vendor": "Engineerix",
                "mode": "Static" if data.get("internetPort") == "staticIPAddress" else str(data.get("internetPort", "")),
                "dns": dns,
                "status": "OK",
                "_scan_ip": ip,
                "_raw": data,
            }
    except (urllib.error.URLError, OSError, ValueError):
        pass
    # Sin sesion valida: comprobar si es la pagina de login de estos equipos.
    try:
        page = http_request(ip, "/login.html")
        if "Administrator" in page:
            return {
                "ip": ip, "mask": "", "gw": "", "vendor": "Engineerix?", "mode": "",
                "dns": "",
                "status": ("Login fallido (contrasena distinta)" if password
                           else "Detectado (sin contrasena: solo IP y MAC)"),
                "_scan_ip": ip,
            }
    except (urllib.error.URLError, OSError):
        pass
    return None


def run_cmd(cmd, timeout=20):
    kwargs = {"creationflags": 0x08000000} if IS_WINDOWS else {}  # sin ventana de consola
    res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, **kwargs)
    return res.returncode == 0, (res.stdout + res.stderr).strip()


def load_arp():
    """Tabla ARP del sistema: {ip: MAC}. Vacia para redes enrutadas."""
    table = {}
    try:
        if IS_LINUX:
            with open("/proc/net/arp") as fh:
                next(fh)
                for line in fh:
                    parts = line.split()
                    if len(parts) >= 4 and parts[2] != "0x0" and parts[3] != "00:00:00:00:00:00":
                        table[parts[0]] = parts[3].upper()
            return table
        out = run_cmd(["arp", "-a"], timeout=10)[1]
        for ip, mac in re.findall(r"(\d+\.\d+\.\d+\.\d+)\D+?(" + MAC_RE + ")", out):
            octets = [o.zfill(2) for o in re.split(r"[-:]", mac)]
            table[ip] = ":".join(octets).upper()
    except Exception:
        pass
    return table


# --------------------------------------------------------------------------
# Adaptadores de red (sin psutil)
# --------------------------------------------------------------------------
def norm_mac(mac):
    return mac.upper().replace("-", ":")


def _as_list(data):
    return data if isinstance(data, list) else [data]


def parse_windows_adapters(ips_json, adapters_json):
    """Entradas (etiqueta, red, nombre, ip) y set de MAC propias, desde PowerShell."""
    by_name = {}
    for e in _as_list(json.loads(ips_json)) if ips_json.strip() else []:
        ip = e.get("IPAddress", "")
        if ip and not ip.startswith("127."):
            by_name.setdefault(e.get("InterfaceAlias", ""), []).append((ip, int(e.get("PrefixLength", 24))))
    items, macs = [], set()
    for a in _as_list(json.loads(adapters_json)) if adapters_json.strip() else []:
        name = a.get("Name", "")
        if not name:
            continue
        if a.get("MacAddress"):
            macs.add(norm_mac(a["MacAddress"]))
        suffix = "" if str(a.get("Status", "")).lower() == "up" else f" ({a.get('Status', '?')})"
        entries = by_name.get(name) or []
        if entries:
            for ip, prefix in entries:
                net = ipaddress.IPv4Network(f"{ip}/{prefix}", strict=False)
                items.append((f"{name} [{ip}]{suffix}", str(net), name, ip))
        else:
            items.append((f"{name} [sin IPv4]{suffix}", "", name, ""))
    return items, macs


def parse_linux_adapters(ip_json):
    items, macs = [], set()
    for ifc in json.loads(ip_json) if ip_json.strip() else []:
        name = ifc.get("ifname", "")
        if not name or ifc.get("link_type") != "ether":
            continue
        if ifc.get("address"):
            macs.add(norm_mac(ifc["address"]))
        suffix = "" if ifc.get("operstate", "").upper() in ("UP", "UNKNOWN") else f" ({ifc.get('operstate', '?')})"
        entries = [(ai["local"], ai["prefixlen"]) for ai in ifc.get("addr_info", []) if ai.get("family") == "inet"]
        if entries:
            for ip, prefix in entries:
                net = ipaddress.IPv4Network(f"{ip}/{prefix}", strict=False)
                items.append((f"{name} [{ip}]{suffix}", str(net), name, ip))
        else:
            items.append((f"{name} [sin IPv4]{suffix}", "", name, ""))
    return items, macs


def list_adapters():
    """([(etiqueta, red, nombre, ip)], {MAC propias}). Vacio si no se puede consultar."""
    try:
        if IS_WINDOWS:
            ps = lambda c: run_cmd(["powershell", "-NoProfile", "-NonInteractive", "-Command", c], timeout=25)[1]
            ips = ps("Get-NetIPAddress -AddressFamily IPv4 | Select-Object InterfaceAlias,IPAddress,PrefixLength"
                     " | ConvertTo-Json -Compress")
            ads = ps("Get-NetAdapter -Physical | Select-Object Name,MacAddress,Status | ConvertTo-Json -Compress")
            return parse_windows_adapters(ips, ads)
        if IS_LINUX:
            ok, out = run_cmd(["ip", "-j", "addr", "show"])
            return parse_linux_adapters(out) if ok else ([], set())
    except Exception:
        pass
    return [], set()


def parse_subnets(text):
    hosts = []
    for chunk in re.split(r"[,\s;]+", text.strip()):
        if not chunk:
            continue
        net = ipaddress.ip_network(chunk, strict=False)
        if net.version != 4:
            raise ValueError(f"Solo IPv4: {chunk}")
        hosts.extend(str(h) for h in net.hosts())
    return list(dict.fromkeys(hosts))  # sin duplicados, mismo orden


# --------------------------------------------------------------------------
# Deteccion de segmento (escucha pasiva ARP / DHCP, sin librerias externas)
# --------------------------------------------------------------------------
def is_engineerix(mac):
    return norm_mac(mac)[:8] in ENGINEERIX_OUIS


def _register(seen, mac, ip=None, note=""):
    entry = seen.setdefault(mac, {"ips": set(), "notes": set()})
    if ip:
        entry["ips"].add(ip)
    if note:
        entry["notes"].add(note)


def parse_frame(frame, seen, own=()):
    """Interpreta una trama Ethernet cruda (bytes): ARP o DHCP discover."""
    if len(frame) < 14:
        return
    ethertype = struct.unpack("!H", frame[12:14])[0]
    payload = frame[14:]
    if ethertype == 0x8100 and len(frame) >= 18:  # etiqueta VLAN
        ethertype = struct.unpack("!H", frame[16:18])[0]
        payload = frame[18:]
    if ethertype == 0x0806 and len(payload) >= 28:  # ARP
        mac = ":".join(f"{b:02X}" for b in payload[8:14])
        if mac in own or mac == "00:00:00:00:00:00":
            return
        ip, note = socket.inet_ntoa(payload[14:18]), "ARP"
        if ip == "0.0.0.0":  # ARP probe: la IP que el equipo esta a punto de usar
            ip, note = socket.inet_ntoa(payload[24:28]), "ARP probe (IP que intenta usar)"
        _register(seen, mac, ip, note)
    elif ethertype == 0x0800 and len(payload) >= 20:  # IPv4
        ihl = (payload[0] & 0x0F) * 4
        if payload[9] == 17 and len(payload) >= ihl + 8 + 34:  # UDP
            sport, dport = struct.unpack("!HH", payload[ihl:ihl + 4])
            bootp = payload[ihl + 8:]
            if sport == 68 and dport == 67 and bootp[0] == 1:  # cliente DHCP pidiendo direccion
                mac = ":".join(f"{b:02X}" for b in bootp[28:34])
                if mac not in own:
                    _register(seen, mac, None, "Pide DHCP (sin IP)")


def parse_pktmon_text(text, seen, own=()):
    """Interpreta la salida de 'pktmon etl2txt' (formato tipo tcpdump)."""
    l2 = re.compile(r"(" + MAC_RE + r")\s*>\s*(" + MAC_RE + ")")
    req = re.compile(r"who-has\s+(\d+\.\d+\.\d+\.\d+)\s+tell\s+(\d+\.\d+\.\d+\.\d+)")
    rep = re.compile(r"Reply\s+(\d+\.\d+\.\d+\.\d+)\s+is-at\s+(" + MAC_RE + ")")
    dhcp = re.compile(r"BOOTP/DHCP,\s*Request from\s+(" + MAC_RE + ")")
    src = None
    for line in text.splitlines():
        m = l2.search(line)
        if m:
            src = norm_mac(m.group(1))
        m = req.search(line)
        if m and src and src not in own:
            who, tell = m.groups()
            if tell == "0.0.0.0":
                _register(seen, src, who, "ARP probe (IP que intenta usar)")
            else:
                _register(seen, src, tell, "ARP")
            continue
        m = rep.search(line)
        if m:
            mac = norm_mac(m.group(2))
            if mac not in own:
                _register(seen, mac, m.group(1), "ARP")
            continue
        m = dhcp.search(line)
        if m and norm_mac(m.group(1)) not in own:
            _register(seen, norm_mac(m.group(1)), None, "Pide DHCP (sin IP)")


def sniff_linux(iface, secs, seen, own):
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
    try:
        s.bind((iface, 0))
        s.settimeout(0.5)
        end = time.time() + secs
        while time.time() < end:
            try:
                frame = s.recv(65535)
            except socket.timeout:
                continue
            parse_frame(frame, seen, own)
    finally:
        s.close()


def read_text_file(path):
    with open(path, "rb") as fh:
        raw = fh.read()
    if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return raw.decode("utf-16", errors="replace")
    return raw.decode("utf-8", errors="replace")


def sniff_windows(secs, seen, own):
    """Captura ARP/DHCP con pktmon (incluido en Windows). Devuelve la ruta del texto capturado."""
    tmp = tempfile.gettempdir()
    etl = os.path.join(tmp, "engineerix_cap.etl")
    txt = os.path.join(tmp, "engineerix_cap.txt")
    pk = lambda *a: run_cmd(["pktmon", *a], timeout=60)
    pk("stop")  # por si quedo una captura anterior
    pk("filter", "remove")
    try:
        for args in (("filter", "add", "EFARP", "-d", "ARP"),
                     ("filter", "add", "EFDHCP", "-t", "UDP", "-p", "67", "68")):
            ok, out = pk(*args)
            if not ok:
                raise RuntimeError(f"pktmon rechazo el filtro: {out}")
        ok, out = pk("start", "--capture", "--comp", "nics", "--pkt-size", "0", "-f", etl)
        if not ok:
            raise RuntimeError("pktmon no pudo iniciar la captura (¿administrador? ¿Windows 10 1809 o "
                               f"superior?):\n{out}")
        try:
            time.sleep(secs)
        finally:
            pk("stop")
        ok, out = pk("etl2txt", etl, "-o", txt)
        if not ok:
            raise RuntimeError(f"pktmon no pudo convertir la captura: {out}")
        parse_pktmon_text(read_text_file(txt), seen, own)
        return txt
    finally:
        pk("filter", "remove")
        try:
            os.remove(etl)
        except OSError:
            pass


def pick_temp_ip(net, taken):
    """Una IP libre cerca del final del rango para usarla como IP temporal del PC."""
    taken = set(taken)
    for i in range(2, 60):
        cand = net.broadcast_address - i
        if cand not in net or cand == net.network_address + 1:
            continue
        if str(cand) not in taken:
            return cand
    return None


# --------------------------------------------------------------------------
# Permisos y IP temporal en el adaptador del PC
# --------------------------------------------------------------------------
IFACE_RE = re.compile(r"^[\w .\-()#\[\]]+$")


def is_admin():
    try:
        if IS_WINDOWS:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        return os.geteuid() == 0
    except Exception:
        return False


def relaunch_as_admin():
    """Windows: vuelve a abrir este programa con permisos de administrador (pide confirmacion UAC)."""
    if not IS_WINDOWS:
        return False
    try:
        import ctypes
        frozen = getattr(sys, "frozen", False)  # True dentro de un .exe de PyInstaller
        args = sys.argv[1:] if frozen else [os.path.abspath(sys.argv[0])] + sys.argv[1:]
        rc = ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable,
                                                 subprocess.list2cmdline(args), None, 1)
        return rc > 32
    except Exception:
        return False


def temp_ip_command(action, name, ip, prefix):
    """Comando (str en Windows, lista en Linux) para agregar/quitar una IP del adaptador."""
    if not IFACE_RE.match(name):
        raise ValueError("Nombre de adaptador no valido")
    ip = str(ipaddress.IPv4Address(ip))
    prefix = int(prefix)
    if not 1 <= prefix <= 30:
        raise ValueError("Prefijo no valido")
    if IS_WINDOWS:
        mask = str(ipaddress.IPv4Network(f"0.0.0.0/{prefix}").netmask)
        if action == "add":
            return f'netsh interface ip add address name="{name}" addr={ip} mask={mask}'
        return f'netsh interface ip delete address name="{name}" addr={ip}'
    verb = "add" if action == "add" else "del"
    return ["ip", "addr", verb, f"{ip}/{prefix}", "dev", name]


# --------------------------------------------------------------------------
# Cambio de IP de un equipo
# --------------------------------------------------------------------------
def validate_new_config(ip, mask, gw, other_ips=()):
    """Devuelve un texto de error o None si la configuracion es coherente."""
    try:
        ip_o = ipaddress.IPv4Address(ip.strip())
    except ValueError:
        return "La IP no es valida."
    if ip_o.is_unspecified or ip_o.is_loopback or ip_o.is_multicast or ip_o.is_reserved:
        return "La IP no es utilizable (0.0.0.0, loopback, multicast o reservada)."
    try:
        net = ipaddress.IPv4Network(f"{ip_o}/{mask.strip()}", strict=False)
    except ValueError:
        return "La mascara no es valida (ej. 255.255.255.0)."
    if net.prefixlen < 31 and ip_o in (net.network_address, net.broadcast_address):
        return "La IP es la direccion de red o de broadcast de esa mascara."
    try:
        gw_o = ipaddress.IPv4Address(gw.strip())
    except ValueError:
        return "El gateway no es valido."
    if gw_o not in net:
        return "El gateway no esta dentro de la red de la nueva IP."
    if gw_o == ip_o:
        return "El gateway no puede ser igual a la IP del equipo."
    if str(ip_o) in set(other_ips):
        return "Otro equipo detectado ya usa esa IP."
    return None


def build_set_request(current, new):
    """PENDIENTE. Debe devolver (accion, cuerpo_bytes) para la peticion
    web_cgi_main.cgi?set_network_... Hace falta la pestana Payload de DevTools al
    pulsar Confirm en Network > Basic. current es el JSON de get_network_base_data."""
    raise NotImplementedError("Falta la peticion set_network de los equipos")


# --------------------------------------------------------------------------
# Interfaz
# --------------------------------------------------------------------------
class DetectWindow(tk.Toplevel):
    def __init__(self, app, seen, capture_file=None):
        super().__init__(app)
        self.app, self.seen = app, seen
        self.title("Segmento detectado")
        self.configure(bg=COLOR_CARD)
        self.geometry("780x400")
        cols = ("mac", "ips", "vendor", "note")
        self.tree = ttk.Treeview(self, columns=cols, show="headings", selectmode="browse")
        for key, title, width in (("mac", "MAC", 150), ("ips", "IP vista", 170),
                                  ("vendor", "Fabricante", 90), ("note", "Como se vio", 300)):
            self.tree.heading(key, text=title)
            self.tree.column(key, width=width, anchor="w")
        self.tree.pack(fill="both", expand=True, padx=6, pady=6)
        order = sorted(seen.items(), key=lambda kv: (not is_engineerix(kv[0]), kv[0]))
        for mac, e in order:
            self.tree.insert("", "end", iid=mac, values=(
                mac, ", ".join(sorted(e["ips"])),
                "Engineerix" if is_engineerix(mac) else "", "; ".join(sorted(e["notes"]))))
        if order:
            self.tree.selection_set(order[0][0])
        else:
            ttk.Label(self, foreground="gray", wraplength=740, text=(
                "No se vio trafico ARP ni DHCP. Reinicia el equipo o desconecta y vuelve a "
                "conectar su cable mientras se escucha, y repite la deteccion.")).pack(padx=6)
        if capture_file:
            ttk.Label(self, foreground="gray", wraplength=740, text=(
                f"En Windows se escucha en todas las tarjetas. Captura en bruto: {capture_file}")).pack(padx=6)
        bar = ttk.Frame(self, padding=6)
        bar.pack(fill="x")
        ttk.Label(bar, text="Mascara /").pack(side="left")
        self.prefix = tk.IntVar(value=24)
        ttk.Spinbox(bar, from_=8, to=30, textvariable=self.prefix, width=4).pack(side="left", padx=4)
        ttk.Button(bar, text="Usar el segmento del equipo seleccionado", command=self.use).pack(side="left", padx=10)
        ttk.Button(bar, text="Cerrar", command=self.destroy).pack(side="right")

    def use(self):
        sel = self.tree.selection()
        if not sel:
            return
        ips = sorted(self.seen[sel[0]]["ips"])
        if not ips:
            messagebox.showinfo("Sin IP", "Ese equipo solo pidio DHCP y no tiene IP. Hasta que "
                                          "reciba una (de un servidor DHCP) no se puede alcanzar por IP.",
                                parent=self)
            return
        taken = {ip for e in self.seen.values() for ip in e["ips"]}
        self.app.use_segment(ips[0], self.prefix.get(), taken)
        self.destroy()


class SendDialog(tk.Toplevel):
    def __init__(self, app, row, other_ips):
        super().__init__(app)
        self.app, self.row, self.other_ips = app, row, other_ips
        self.title(f"Cambiar red de {row['ip']}")
        self.configure(bg=COLOR_CARD)
        self.resizable(False, False)
        self.vars = {}
        for i, (key, label) in enumerate((("ip", "Nueva IP"), ("mask", "Mascara"), ("gw", "Gateway"))):
            ttk.Label(self, text=label).grid(row=i, column=0, sticky="w", padx=8, pady=4)
            self.vars[key] = tk.StringVar(value=row.get(key, ""))
            ttk.Entry(self, textvariable=self.vars[key], width=22).grid(row=i, column=1, padx=8, pady=4)
        btns = ttk.Frame(self, padding=8)
        btns.grid(row=3, column=0, columnspan=2)
        ttk.Button(btns, text="Aplicar", command=self.apply).pack(side="left", padx=4)
        ttk.Button(btns, text="Cancelar", command=self.destroy).pack(side="left", padx=4)

    def apply(self):
        ip, mask, gw = (self.vars[k].get() for k in ("ip", "mask", "gw"))
        err = validate_new_config(ip, mask, gw, self.other_ips)
        if err:
            messagebox.showerror("Configuracion no valida", err, parent=self)
            return
        if not messagebox.askyesno(
                "Confirmar", f"Se cambiara {self.row['ip']} a {ip} / {mask} / {gw}.\n"
                             "Si el valor es incorrecto el equipo puede quedar inaccesible.\n\n¿Continuar?",
                parent=self):
            return
        self.app.send_config(self.row, {"ip": ip.strip(), "mask": mask.strip(), "gw": gw.strip()})
        self.destroy()


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(f"Engineerix Finder - {AUTHOR}")
        self.geometry("1050x700")
        self.minsize(900, 600)
        setup_styles(self)
        self.rows = []
        self.q = queue.Queue()
        self.scanning = False
        self.detecting_until = 0.0
        self.temp_ips = []  # [(adaptador, ip, prefijo)]
        self.adapters, self.own_macs = list_adapters()
        self.logo_img = None
        self.sort_key, self.sort_rev = "ip", False
        self.protocol("WM_DELETE_WINDOW", self.on_close)

        self.status = tk.StringVar(value="Listo. Pulsa Refresh (la contraseña es opcional: sin ella solo se "
                                         "detectan IP y MAC) o usa Detectar segmento si no sabes el rango.")
        foot = tk.Frame(self, bg="#0A0A0A")
        foot.pack(side=tk.BOTTOM, fill=tk.X)
        tk.Label(foot, text=COPYRIGHT_TEXT, bg="#0A0A0A", fg=COLOR_MUTED, font=("Segoe UI", 8),
                 padx=10).pack(side=tk.RIGHT)
        tk.Label(foot, textvariable=self.status, bg="#0A0A0A", fg=COLOR_MUTED, anchor="w",
                 font=("Segoe UI", 9), padx=10, pady=5).pack(side=tk.LEFT, fill=tk.X, expand=True)

        main = tk.Frame(self, bg=COLOR_BG)
        main.pack(fill=tk.BOTH, expand=True, padx=15, pady=15)
        self.build_header(main)
        self.build_controls(main)
        self.build_table(main)
        self.build_bottom(main)
        self.after(100, self.poll)

    # ---- construccion de la interfaz ----
    @staticmethod
    def make_button(parent, text, command, primary=False, **kw):
        bg = COLOR_PRIMARY if primary else COLOR_FIELD
        hover = COLOR_PRIMARY_HOVER if primary else COLOR_BORDER
        opts = dict(bg=bg, fg=COLOR_TEXT, activebackground=hover, activeforeground=COLOR_TEXT,
                    disabledforeground="#666666", relief="flat", bd=0, cursor="hand2",
                    font=("Segoe UI", 9, "bold" if primary else "normal"), padx=10, pady=3)
        opts.update(kw)
        btn = tk.Button(parent, text=text, command=command, **opts)
        btn.bind("<Enter>", lambda _e: btn["state"] != "disabled" and btn.config(bg=hover))
        btn.bind("<Leave>", lambda _e: btn.config(bg=bg))
        return btn

    def build_header(self, parent):
        header = tk.Frame(parent, bg=COLOR_BG)
        header.pack(fill=tk.X, pady=(0, 10))
        for path in (resource_path("logo.png"), "logo.png"):  # opcional; sin Pillow
            try:
                img = tk.PhotoImage(file=path)
                factor = max(1, round(img.height() / 40))
                self.logo_img = img.subsample(factor, factor) if factor > 1 else img
                tk.Label(header, image=self.logo_img, bg=COLOR_BG).pack(side=tk.LEFT)
                return
            except Exception:
                continue
        tk.Label(header, text="Engineerix™", font=("Segoe UI", 16, "bold"),
                 fg=COLOR_PRIMARY, bg=COLOR_BG).pack(side=tk.LEFT)

    def build_controls(self, parent):
        panel = tk.Frame(parent, bg=COLOR_CARD, highlightbackground=COLOR_BORDER, highlightthickness=1)
        panel.pack(fill=tk.X, pady=(0, 10), ipadx=10, ipady=10)
        lab = lambda p, t, **k: tk.Label(p, text=t, font=("Segoe UI", 10), fg=COLOR_TEXT, bg=COLOR_CARD, **k)
        entry = lambda p, var, **k: tk.Entry(p, textvariable=var, font=("Segoe UI", 10), bg=COLOR_FIELD,
                                             fg=COLOR_TEXT, insertbackground="white", relief="flat", **k)

        # Fila 1: adaptador
        row1 = tk.Frame(panel, bg=COLOR_CARD)
        row1.pack(fill=tk.X, padx=10, pady=5)
        lab(row1, "Adaptador:").pack(side=tk.LEFT, padx=(0, 10))
        self.adapter_var = tk.StringVar()
        self.adapter_cb = ttk.Combobox(row1, textvariable=self.adapter_var, font=("Segoe UI", 10), width=50,
                                       state="readonly" if self.adapters else "normal",
                                       values=[a[0] for a in self.adapters])
        self.adapter_cb.pack(side=tk.LEFT, padx=(0, 10))
        self.make_button(row1, "Agregar subred", self.add_adapter_subnet, primary=True,
                         padx=10, pady=2).pack(side=tk.LEFT, padx=5)
        self.make_button(row1, "Actualizar", self.reload_adapters, padx=8, pady=2).pack(side=tk.LEFT)
        if not self.adapters:
            tk.Label(panel, text="(no pude listar los adaptadores: escribe el nombre exacto de tu tarjeta)",
                     font=("Segoe UI", 8, "italic"), fg=COLOR_MUTED, bg=COLOR_CARD).pack(anchor="w", padx=10)

        # Fila 2: subredes y deteccion de segmento
        row2 = tk.Frame(panel, bg=COLOR_CARD)
        row2.pack(fill=tk.X, padx=10, pady=5)
        lab(row2, "Subredes:").pack(side=tk.LEFT, padx=(0, 22))
        self.subnet_var = tk.StringVar(value="10.20.21.0/24")
        entry(row2, self.subnet_var, width=45).pack(side=tk.LEFT, padx=(0, 15), ipady=3)
        tk.Label(row2, text="seg:", font=("Segoe UI", 9), fg=COLOR_MUTED, bg=COLOR_CARD).pack(side=tk.LEFT)
        self.secs_var = tk.IntVar(value=DETECT_SECONDS)
        ttk.Spinbox(row2, from_=5, to=60, width=5, textvariable=self.secs_var,
                    font=("Segoe UI", 9)).pack(side=tk.LEFT, padx=5)
        self.detect_btn = self.make_button(row2, "Detectar segmento", self.start_detect)
        self.detect_btn.pack(side=tk.LEFT, padx=5)

        # Fila 3: contraseña
        row3 = tk.Frame(panel, bg=COLOR_CARD)
        row3.pack(fill=tk.X, padx=10, pady=5)
        lab(row3, "Contraseña (opcional):").pack(side=tk.LEFT, padx=(0, 10))
        self.pw_var = tk.StringVar()
        tk.Entry(row3, textvariable=self.pw_var, show="*", font=("Segoe UI", 10), bg=COLOR_FIELD, fg=COLOR_TEXT,
                 insertbackground="white", relief="flat", width=25).pack(side=tk.LEFT, padx=(0, 15), ipady=3)
        tk.Label(row3, text="separadas por coma, ej: 10.20.21.0/24, 10.20.30.0/24",
                 font=("Segoe UI", 8, "italic"), fg=COLOR_MUTED, bg=COLOR_CARD).pack(side=tk.LEFT, padx=(0, 15))
        self.make_button(row3, "Quitar IP temporal", self.remove_temp_ips).pack(side=tk.LEFT)

        # Aviso de permisos (solo si no hay administrador / root)
        if not is_admin():
            warn = tk.Frame(panel, bg=COLOR_CARD)
            warn.pack(fill=tk.X, padx=10, pady=(5, 0))
            if IS_WINDOWS:
                tk.Label(warn, text="Sin permisos de administrador: detectar segmento y la IP temporal los "
                                    "necesitan.", font=("Segoe UI", 9), fg=COLOR_WARN,
                         bg=COLOR_CARD).pack(side=tk.LEFT, padx=(0, 10))
                self.make_button(warn, "Reabrir como administrador", self.restart_admin,
                                 padx=8, pady=2).pack(side=tk.LEFT)
            else:
                tk.Label(warn, text="Sin root: para detectar segmento y agregar IP temporal ejecuta  "
                                    "sudo python3 engineerix_finder.py", font=("Segoe UI", 9), fg=COLOR_WARN,
                         bg=COLOR_CARD).pack(side=tk.LEFT)

    def build_table(self, parent):
        frame = tk.Frame(parent, bg=COLOR_CARD, highlightbackground=COLOR_BORDER, highlightthickness=1)
        frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        self.tree = ttk.Treeview(frame, columns=[c[0] for c in COLUMNS], show="headings", selectmode="browse")
        for key, title, width in COLUMNS:
            self.tree.heading(key, text=title, command=lambda k=key: self.sort_by(k))
            self.tree.column(key, width=width, anchor="w")
        scroll = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll.set)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=2, pady=2)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree.bind("<<TreeviewSelect>>", lambda _e: self.update_send_state())

    def build_bottom(self, parent):
        bottom = tk.Frame(parent, bg=COLOR_CARD, highlightbackground=COLOR_BORDER, highlightthickness=1)
        bottom.pack(fill=tk.X, pady=(0, 5), ipadx=10, ipady=8)
        frow = tk.Frame(bottom, bg=COLOR_CARD)
        frow.pack(fill=tk.X, padx=10, pady=(0, 8))
        tk.Label(frow, text="Filtro", font=("Segoe UI", 10, "bold"), fg=COLOR_PRIMARY,
                 bg=COLOR_CARD).pack(side=tk.LEFT, padx=(0, 15))
        tk.Label(frow, text="Texto:", font=("Segoe UI", 9), fg=COLOR_TEXT,
                 bg=COLOR_CARD).pack(side=tk.LEFT, padx=(0, 5))
        self.filter_var = tk.StringVar()
        tk.Entry(frow, textvariable=self.filter_var, font=("Segoe UI", 9), bg=COLOR_FIELD, fg=COLOR_TEXT,
                 insertbackground="white", relief="flat", width=25).pack(side=tk.LEFT, padx=(0, 20), ipady=2)
        self.filter_var.trace_add("write", lambda *_: self.render())
        self.only_fail = tk.BooleanVar()
        tk.Checkbutton(frow, text="Solo con login fallido", variable=self.only_fail, command=self.render,
                       bg=COLOR_CARD, fg=COLOR_TEXT, selectcolor=COLOR_FIELD, activebackground=COLOR_CARD,
                       activeforeground=COLOR_TEXT, font=("Segoe UI", 9)).pack(side=tk.LEFT)

        arow = tk.Frame(bottom, bg=COLOR_CARD)
        arow.pack(fill=tk.X, padx=10)
        self.send_btn = self.make_button(arow, "Send", self.open_send, font=("Segoe UI", 10), width=18, pady=4)
        self.send_btn.config(state="disabled")
        self.send_btn.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=(0, 5))
        self.refresh_btn = self.make_button(arow, "Refresh", self.start_scan, primary=True,
                                            font=("Segoe UI", 10, "bold"), width=18, pady=4)
        self.refresh_btn.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=5)
        self.make_button(arow, "Export", self.export_csv, font=("Segoe UI", 10), width=18,
                         pady=4).pack(side=tk.LEFT, expand=True, fill=tk.X, padx=(5, 0))

    # ---- permisos / adaptador ----
    def restart_admin(self):
        self.remove_temp_ips(quiet=True)
        if relaunch_as_admin():
            self.destroy()
        else:
            messagebox.showerror("No se pudo", "No se pudo reabrir como administrador (¿cancelaste el aviso?).")

    def reload_adapters(self):
        self.adapters, self.own_macs = list_adapters()
        self.adapter_cb.config(values=[a[0] for a in self.adapters],
                               state="readonly" if self.adapters else "normal")
        self.status.set(f"{len(self.adapters)} adaptador(es) encontrados.")

    def selected_adapter(self):
        sel = self.adapter_var.get().strip()
        for label, _net, name, _ip in self.adapters:
            if label == sel:
                return name
        return sel  # nombre escrito a mano

    def add_adapter_subnet(self):
        sel = self.adapter_var.get()
        for label, net, _name, _ip in self.adapters:
            if label == sel:
                if not net:
                    self.status.set("Ese adaptador no tiene IPv4. Usa Detectar segmento.")
                    return
                current = [s for s in re.split(r"[,\s;]+", self.subnet_var.get()) if s]
                if net not in current:
                    current.append(net)
                self.subnet_var.set(", ".join(current))
                return

    # ---- deteccion de segmento ----
    def start_detect(self):
        if not (IS_WINDOWS or IS_LINUX):
            messagebox.showerror("No disponible", "Detectar segmento solo esta disponible en Windows y Linux.")
            return
        name = self.selected_adapter()
        if IS_LINUX and not name:
            messagebox.showwarning("Falta el adaptador", "Elige el adaptador conectado al switch.")
            return
        if self.detecting_until:
            return
        if not is_admin():
            if IS_WINDOWS:
                if messagebox.askyesno("Se necesita administrador",
                                       "Escuchar la red requiere permisos de administrador.\n"
                                       "¿Reabrir el programa como administrador ahora?"):
                    self.restart_admin()
            else:
                messagebox.showwarning("Se necesita root",
                                       "Ejecuta:  sudo python3 engineerix_finder.py")
            return
        try:
            secs = max(5, min(60, int(self.secs_var.get())))
        except (tk.TclError, ValueError):
            secs = DETECT_SECONDS
        self.detecting_until = time.time() + secs
        self.detect_btn.config(state="disabled")
        threading.Thread(target=self.detect_worker, args=(name, secs), daemon=True).start()

    def detect_worker(self, name, secs):
        seen, capture_file = {}, None
        try:
            if IS_WINDOWS:
                capture_file = sniff_windows(secs, seen, self.own_macs)
            else:
                sniff_linux(name, secs, seen, self.own_macs)
        except Exception as exc:
            self.q.put(("detect_error", str(exc)))
            return
        self.q.put(("detect_done", (seen, capture_file)))

    def use_segment(self, ip, prefix, taken):
        net = ipaddress.ip_network(f"{ip}/{prefix}", strict=False)
        current = [s for s in re.split(r"[,\s;]+", self.subnet_var.get()) if s]
        if str(net) not in current:
            current.append(str(net))
        self.subnet_var.set(", ".join(current))
        name = self.selected_adapter()
        mine = [ipaddress.ip_address(a_ip) for (_l, _n, n, a_ip) in self.adapters if n == name and a_ip]
        if any(m in net for m in mine):
            self.status.set(f"Tu adaptador ya esta en {net}. Pulsa Refresh para escanear.")
            return
        if not name:
            messagebox.showwarning("Falta el adaptador", "Elige tu adaptador para agregarle la IP temporal.")
            return
        temp = pick_temp_ip(net, taken)
        if temp is None:
            messagebox.showerror("Sin IP libre", f"No encontre una IP libre en {net} para tu PC.")
            return
        add_cmd = temp_ip_command("add", name, temp, net.prefixlen)
        shown = add_cmd if isinstance(add_cmd, str) else "sudo " + " ".join(add_cmd)
        if not messagebox.askyesno(
                "IP temporal",
                f"Tu adaptador '{name}' no esta en {net}.\n\n"
                f"¿Agregarle la IP temporal {temp}/{net.prefixlen}? (se quita con el boton "
                f"'Quitar IP temporal' o al cerrar el programa; tu IP actual no se toca).\n\n"
                f"Comando equivalente:\n{shown}"):
            return
        ok, out = run_cmd(add_cmd)
        if not ok:
            messagebox.showerror("No se pudo agregar la IP", out or "Error desconocido")
            return
        self.temp_ips.append((name, str(temp), net.prefixlen))
        self.status.set(f"IP temporal {temp}/{net.prefixlen} agregada a {name}.")
        if self.pw_var.get():
            self.after(2000, self.start_scan)

    def remove_temp_ips(self, quiet=False):
        failed = []
        for name, ip, prefix in list(self.temp_ips):
            try:
                ok, out = run_cmd(temp_ip_command("del", name, ip, prefix))
            except Exception as exc:
                ok, out = False, str(exc)
            if ok:
                self.temp_ips.remove((name, ip, prefix))
            else:
                failed.append(f"{ip} en {name}: {out}")
        if failed and not quiet:
            messagebox.showerror("No se pudo quitar", "\n".join(failed))
        elif not quiet:
            self.status.set("IP temporal quitada.")

    def on_close(self):
        self.remove_temp_ips(quiet=True)
        self.destroy()

    # ---- escaneo ----
    def start_scan(self):
        if self.scanning:
            return
        try:
            hosts = parse_subnets(self.subnet_var.get())
        except ValueError as exc:
            messagebox.showerror("Subredes inválidas", str(exc))
            return
        if not hosts:
            messagebox.showwarning("Sin direcciones", "No hay IPs que escanear.")
            return
        if len(hosts) > MAX_HOSTS:
            messagebox.showerror("Rango muy grande", f"{len(hosts)} IPs; el máximo es {MAX_HOSTS}.")
            return
        self.rows.clear()
        self.render()
        self.scanning = True
        self.refresh_btn.config(state="disabled")
        threading.Thread(target=self.scan_worker, args=(hosts, self.pw_var.get()), daemon=True).start()

    def scan_worker(self, hosts, password):
        total, done = len(hosts), 0
        found = []
        with ThreadPoolExecutor(max_workers=WORKERS) as pool:
            for result in pool.map(lambda h: probe(h, password), hosts):
                done += 1
                if result:
                    found.append(result)
                    self.q.put(("row", result))
                if done % 10 == 0 or done == total:
                    self.q.put(("progress", f"Escaneando {done}/{total}  |  encontrados: {len(found)}"))
        arp = load_arp()
        self.q.put(("arp", arp))
        self.q.put(("done", f"Terminado. {len(found)} equipo(s) en {total} direcciones."))

    def poll(self):
        try:
            while True:
                kind, payload = self.q.get_nowait()
                if kind == "row":
                    self.rows.append(payload)
                    self.render()
                elif kind == "progress":
                    self.status.set(payload)
                elif kind == "arp":
                    for r in self.rows:
                        r["mac"] = payload.get(r["_scan_ip"], payload.get(r["ip"], ""))
                    self.render()
                elif kind == "done":
                    self.status.set(payload)
                    self.scanning = False
                    self.refresh_btn.config(state="normal")
                elif kind == "detect_done":
                    seen, capture_file = payload
                    self.detecting_until = 0.0
                    self.detect_btn.config(state="normal")
                    self.status.set(f"Deteccion terminada: {len(seen)} equipo(s) vistos.")
                    DetectWindow(self, seen, capture_file)
                elif kind == "detect_error":
                    self.detecting_until = 0.0
                    self.detect_btn.config(state="normal")
                    self.status.set("La deteccion fallo.")
                    messagebox.showerror("Error al escuchar la red", payload)
        except queue.Empty:
            pass
        if self.detecting_until:
            left = max(0, int(self.detecting_until - time.time()))
            self.status.set(f"Escuchando la red... {left} s (reinicia o reconecta el equipo ahora)")
        self.after(100, self.poll)

    # ---- tabla ----
    def sort_by(self, key):
        self.sort_rev = (not self.sort_rev) if key == self.sort_key else False
        self.sort_key = key
        self.render()

    def visible_rows(self):
        text = self.filter_var.get().strip().lower()
        out = []
        for r in self.rows:
            if self.only_fail.get() and r["status"] == "OK":
                continue
            if text and text not in " ".join(str(r.get(c[0], "")) for c in COLUMNS).lower():
                continue
            out.append(r)

        def keyf(r):
            v = str(r.get(self.sort_key, ""))
            if self.sort_key in ("ip", "mask", "gw"):
                try:
                    return (0, int(ipaddress.IPv4Address(v)))
                except ValueError:
                    return (1, 0)
            return (0, v.lower())

        return sorted(out, key=keyf, reverse=self.sort_rev)

    def render(self):
        self.tree.delete(*self.tree.get_children())
        for r in self.visible_rows():
            self.tree.insert("", "end", iid=r["_scan_ip"], values=[r.get(c[0], "") for c in COLUMNS])
        self.update_send_state()

    def selected_row(self):
        sel = self.tree.selection()
        if not sel:
            return None
        return next((r for r in self.rows if r["_scan_ip"] == sel[0]), None)

    def update_send_state(self):
        row = self.selected_row()
        ok = SET_READY and row is not None and row.get("status") == "OK"
        self.send_btn.config(state="normal" if ok else "disabled")

    # ---- cambio de IP ----
    def open_send(self):
        row = self.selected_row()
        if not row:
            return
        others = [r["ip"] for r in self.rows if r is not row]
        SendDialog(self, row, others)

    def send_config(self, row, new):
        if not self.pw_var.get():
            messagebox.showwarning("Falta la contraseña", "Para cambiar la IP escribe la contraseña del usuario admin.")
            return
        try:
            action, body = build_set_request(row.get("_raw", {}), new)
            reply = api_call(row["_scan_ip"], action, auth_cookie(self.pw_var.get()), body=body)
        except NotImplementedError as exc:
            messagebox.showinfo("Pendiente", str(exc))
            return
        except (urllib.error.URLError, OSError) as exc:
            messagebox.showerror("Error al enviar", str(exc))
            return
        self.status.set(f"Respuesta del equipo: {reply[:150]}")
        messagebox.showinfo("Enviado", f"Respuesta del equipo:\n{reply[:500]}\n\n"
                                       "Si cambiaste de segmento, usa Detectar segmento o escanea el nuevo rango.")

    def export_csv(self):
        rows = self.visible_rows()
        if not rows:
            messagebox.showinfo("Export", "No hay datos para exportar.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV", "*.csv")])
        if not path:
            return
        with open(path, "w", newline="", encoding="utf-8-sig") as fh:
            w = csv.writer(fh)
            w.writerow([c[1] for c in COLUMNS])
            for r in rows:
                w.writerow([r.get(c[0], "") for c in COLUMNS])
        self.status.set(f"Exportado: {path}")


if __name__ == "__main__":
    main()
