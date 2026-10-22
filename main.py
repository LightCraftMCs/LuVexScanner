# -*- coding: utf-8 -*-
"""
LuVex Server Scanner - Android (Kivy) version of LuVex.py

Everything above the "UI (Kivy)" marker is plain Python (sockets only).
It uses no mcstatus, so the APK build stays simple and reliable.
"""
import base64
import hashlib
import io
import json
import math
import os
import random
import re
import socket
import struct
import textwrap
import threading
import time
import uuid
from datetime import datetime
from pathlib import Path

try:
    import dns.resolver as _dns_resolver
except Exception:
    _dns_resolver = None

# ------------------------------------------------------------------
#  SETTINGS
# ------------------------------------------------------------------
APP_NAME = "Luvex Server Scanner"
DEFAULT_IP = "Play.DonutSMP.net:25565"
FOOTER_TEXT = "LuVex"

# Text/buttons too small or too big? 0.8 smaller, 1.0 normal, 1.3 bigger.
UI_SCALE = 1.0

# ------------------------------------------------------------------
#  THEME (green)
# ------------------------------------------------------------------
BG = "#040d08"
CARD = "#0b1b13"
CARD_BORDER = "#1c4630"
INPUT_BG = "#0e2418"
ACCENT = "#22c55e"
ACCENT_DARK = "#15803d"
ACCENT_PRESS = "#166534"
TEAL = "#0f766e"
TEAL_PRESS = "#115e59"
LIME = "#a3e635"
GREEN = "#4ade80"
YELLOW = "#fbbf24"
RED = "#f87171"
TEXT = "#ecfdf5"
MUTED = "#86a897"
DISABLED = "#10261a"
DISABLED_TEXT = "#4f7461"
CODE = "#d9f99d"


# ------------------------------------------------------------------
#  SMALL HELPERS
# ------------------------------------------------------------------
def hex_to_rgb(color):
    color = color.lstrip("#")
    return tuple(int(color[i:i + 2], 16) for i in (0, 2, 4))


def lerp_color(c1, c2, t):
    r1, g1, b1 = hex_to_rgb(c1)
    r2, g2, b2 = hex_to_rgb(c2)
    r = int(r1 + (r2 - r1) * t)
    g = int(g1 + (g2 - g1) * t)
    b = int(b1 + (b2 - b1) * t)
    return f"#{r:02x}{g:02x}{b:02x}"


def shorten(text, limit=20):
    text = str(text)
    if len(text) <= limit:
        return text
    return text[:limit - 3] + "..."


def strip_codes(text):
    return re.sub("\u00a7.", "", text or "")


# ------------------------------------------------------------------
#  MINECRAFT PROTOCOL
# ------------------------------------------------------------------
def write_varint(value):
    out = b""
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out += bytes([byte | 0x80])
        else:
            out += bytes([byte])
            return out


def read_varint_bytes(data, offset):
    number = 0
    for i in range(5):
        byte = data[offset + i]
        number |= (byte & 0x7F) << (7 * i)
        if not byte & 0x80:
            return number, offset + i + 1
    raise ValueError("VarInt is too big")


def pack_string(text):
    raw = text.encode("utf-8")
    return write_varint(len(raw)) + raw


def make_packet(packet_id, payload):
    data = write_varint(packet_id) + payload
    return write_varint(len(data)) + data


def recv_varint(sock):
    length = 0
    for i in range(5):
        byte = sock.recv(1)
        if not byte:
            raise ConnectionError("Server closed the connection.")
        length |= (byte[0] & 0x7F) << (7 * i)
        if not byte[0] & 0x80:
            return length
    raise ValueError("VarInt is too big")


def recv_exact(sock, length):
    data = b""
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            break
        data += chunk
    return data


def read_packet(sock):
    length = recv_varint(sock)
    if length <= 0 or length > 8_000_000:
        raise ValueError("Server sent an invalid reply.")
    return recv_exact(sock, length)


def offline_uuid(name):
    digest = bytearray(hashlib.md5(("OfflinePlayer:" + name).encode("utf-8")).digest())
    digest[6] = (digest[6] & 0x0F) | 0x30
    digest[8] = (digest[8] & 0x3F) | 0x80
    return uuid.UUID(bytes=bytes(digest))


def build_login_start(name, protocol):
    payload = pack_string(name)
    player_uuid = offline_uuid(name).bytes
    if protocol >= 764:        # 1.20.2+
        payload += player_uuid
    elif protocol >= 761:      # 1.19.3 - 1.20.1
        payload += b"\x01" + player_uuid
    elif protocol == 760:      # 1.19.1 - 1.19.2
        payload += b"\x00\x01" + player_uuid
    elif protocol == 759:      # 1.19
        payload += b"\x00"
    return make_packet(0x00, payload)


def flatten_chat(node):
    if isinstance(node, str):
        return node
    if isinstance(node, list):
        return "".join(flatten_chat(x) for x in node)
    if isinstance(node, dict):
        out = node.get("text", "") or node.get("translate", "")
        for extra in node.get("extra", []) or []:
            out += flatten_chat(extra)
        return out
    return str(node)


# ---- MOTD as copyable color code (&a&lText\nLine two) ----
MC_COLORS = {
    "black": "0", "dark_blue": "1", "dark_green": "2", "dark_aqua": "3",
    "dark_red": "4", "dark_purple": "5", "gold": "6", "gray": "7",
    "dark_gray": "8", "blue": "9", "green": "a", "aqua": "b",
    "red": "c", "light_purple": "d", "yellow": "e", "white": "f",
}
MC_FORMATS = {
    "obfuscated": "k", "bold": "l", "strikethrough": "m",
    "underlined": "n", "italic": "o",
}


def _style_prefix(style):
    prefix = ""
    color = style.get("color")
    if color in MC_COLORS:
        prefix += "\u00a7" + MC_COLORS[color]
    elif isinstance(color, str) and re.fullmatch(r"#[0-9a-fA-F]{6}", color):
        prefix += "\u00a7" + color
    for name, code in MC_FORMATS.items():
        if style.get(name) in (True, "true"):
            prefix += "\u00a7" + code
    return prefix


def components_to_code(node):
    out = []
    last = [""]

    def emit(text, style):
        prefix = _style_prefix(style)
        if prefix != last[0]:
            if last[0]:
                out.append("\u00a7r")
            out.append(prefix)
            last[0] = prefix
        out.append(text)

    def walk(n, inherit):
        if isinstance(n, str):
            emit(n, inherit)
        elif isinstance(n, list):
            for item in n:
                walk(item, inherit)
        elif isinstance(n, dict):
            style = dict(inherit)
            for key in ("color",) + tuple(MC_FORMATS):
                if key in n:
                    style[key] = n[key]
            text = n.get("text", "") or ""
            if text:
                emit(text, style)
            for extra in n.get("extra", []) or []:
                walk(extra, style)

    walk(node, {})
    return "".join(out)


def get_motd_code(description):
    try:
        code = components_to_code(description)
    except Exception:
        code = description if isinstance(description, str) else json.dumps(description, ensure_ascii=False)
    return code.replace("\u00a7", "&").replace("\n", "\\n")


# ---- cracked / premium check (online-mode detection) ----
def parse_disconnect(payload):
    try:
        length, offset = read_varint_bytes(payload, 0)
        text = payload[offset:offset + length].decode("utf-8", "replace")
        try:
            text = flatten_chat(json.loads(text))
        except Exception:
            pass
        return shorten(strip_codes(text).replace("\n", " ").strip() or "no reason", 110)
    except Exception:
        return "unreadable reason"


def classify_login_packet(data):
    """Decide premium / cracked from the first packet the server sends."""
    packet_id, offset = read_varint_bytes(data, 0)

    if packet_id == 0x01:
        return "premium", "Online-mode: only real Minecraft accounts can join."
    if packet_id in (0x02, 0x03):
        return "cracked", "Offline-mode: any username can join."
    if packet_id == 0x00:
        reason = parse_disconnect(data[offset:])
        return "unknown", f"Server rejected the test login: {reason}"
    if packet_id == 0x04:
        return "unknown", "Login needs proxy forwarding (server sits behind a proxy)."
    return "unknown", f"Unexpected reply (packet {packet_id})."


def check_online_mode(connect_host, connect_port, handshake_host, protocol, timeout=5):
    name = f"LuvexChk{random.randint(10, 99)}"
    try:
        with socket.create_connection((connect_host, connect_port), timeout=timeout) as sock:
            sock.settimeout(timeout)

            handshake = make_packet(
                0x00,
                write_varint(protocol)
                + pack_string(handshake_host)
                + struct.pack(">H", connect_port)
                + write_varint(2)
            )
            sock.sendall(handshake + build_login_start(name, protocol))

            length = recv_varint(sock)
            if length <= 0 or length > 1_000_000:
                return "unknown", "Server sent an invalid reply."

            data = recv_exact(sock, length)
            return classify_login_packet(data)

    except socket.timeout:
        return "unknown", "The server did not answer the test login in time."
    except Exception as exc:
        return "unknown", f"Check failed: {exc}"


# ---- address handling (SRV records when no port is typed) ----
def split_address(address):
    address = address.strip()
    host, port = address, None
    if address.startswith("["):
        m = re.match(r"^\[(.+)\](?::(\d+))?$", address)
        if m:
            host = m.group(1)
            port = int(m.group(2)) if m.group(2) else None
    elif address.count(":") == 1:
        h, p = address.split(":")
        if p.isdigit():
            host, port = h, int(p)
    return host, port


def srv_lookup(host):
    if _dns_resolver is None:
        return None
    try:
        resolver = _dns_resolver.Resolver(configure=False)
        resolver.nameservers = ["8.8.8.8", "1.1.1.1"]
        resolver.lifetime = 3
        answers = resolver.resolve("_minecraft._tcp." + host, "SRV")
        rec = sorted(answers, key=lambda r: (r.priority, -r.weight))[0]
        return str(rec.target).rstrip("."), int(rec.port)
    except Exception:
        return None


def resolve_address(address):
    host, port = split_address(address)
    if port is None:
        srv = srv_lookup(host)
        if srv:
            return srv
        return host, 25565
    return host, port


# ---- server status (Server List Ping) ----
def get_status(host, port, handshake_host, timeout=5):
    started = time.time()
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        handshake = make_packet(
            0x00,
            write_varint(767)
            + pack_string(handshake_host)
            + struct.pack(">H", port)
            + write_varint(1)
        )
        sock.sendall(handshake + make_packet(0x00, b""))

        data = read_packet(sock)
        packet_id, offset = read_varint_bytes(data, 0)
        if packet_id != 0x00:
            raise ConnectionError("Unexpected status reply.")
        length, offset = read_varint_bytes(data, offset)
        info = json.loads(data[offset:offset + length].decode("utf-8", "replace"))
        latency = (time.time() - started) * 1000

        try:
            t1 = time.time()
            sock.sendall(make_packet(0x01, struct.pack(">q", 12345)))
            read_packet(sock)
            latency = (time.time() - t1) * 1000
        except Exception:
            pass

    return info, latency


# ---- optional extra info through Query (only if enable-query=true) ----
def get_query(host, port, timeout=3):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        addr = (host, port)
        session = 0x01020304
        sock.sendto(b"\xfe\xfd\x09" + struct.pack(">i", session), addr)
        reply = sock.recvfrom(2048)[0]
        token = int(reply[5:].split(b"\x00")[0])

        sock.sendto(
            b"\xfe\xfd\x00" + struct.pack(">i", session)
            + struct.pack(">i", token) + b"\x00\x00\x00\x00",
            addr
        )
        reply = sock.recvfrom(16384)[0]
        data = reply[16:]

        parts = data.split(b"\x00\x01player_\x00\x00", 1)
        kv = parts[0].split(b"\x00")
        info = {}
        for k, v in zip(kv[0::2], kv[1::2]):
            info[k.decode("utf-8", "replace")] = v.decode("utf-8", "replace")

        names = []
        if len(parts) == 2:
            names = [n.decode("utf-8", "replace") for n in parts[1].split(b"\x00") if n]

        plugins = info.get("plugins", "")
        if ":" in plugins:
            brand = plugins.split(":", 1)[0].split(" on ")[0].strip()
        elif plugins:
            brand = plugins.strip()
        else:
            brand = "vanilla"

        return {
            "software": brand,
            "software_version": info.get("version", ""),
            "map": info.get("map", ""),
            "players": names,
        }
    except Exception:
        return None
    finally:
        sock.close()


def scan_server(address, do_check):
    """Full scan. Returns the result dict (same keys as the Pydroid version)."""
    checked_at = datetime.now().isoformat(timespec="seconds")
    try:
        host, port = resolve_address(address)
        handshake_host = split_address(address)[0]
        info, latency = get_status(host, port, handshake_host)
    except Exception as exc:
        return {
            "application": APP_NAME,
            "checked_at": checked_at,
            "address": address,
            "online": False,
            "error": str(exc) or exc.__class__.__name__,
        }

    description = info.get("description", "")
    players = info.get("players") or {}
    version = info.get("version") or {}
    sample = []
    try:
        sample = [p.get("name", "") for p in (players.get("sample") or []) if p.get("name")]
    except Exception:
        pass

    result = {
        "application": APP_NAME,
        "checked_at": checked_at,
        "address": address,
        "resolved": f"{host}:{port}",
        "online": True,
        "version": strip_codes(str(version.get("name", "?"))),
        "protocol": version.get("protocol", 0),
        "players_online": players.get("online", 0),
        "players_max": players.get("max", 0),
        "players_sample": sample,
        "description": strip_codes(flatten_chat(description)).strip(),
        "motd_code": get_motd_code(description),
        "latency_ms": round(latency, 2),
        "access_mode": "skipped",
        "access_detail": "Cracked check is turned off.",
        "_icon": info.get("favicon"),
    }

    query = get_query(host, port)
    if query:
        result["query"] = query

    if do_check:
        protocol = result["protocol"]
        if not isinstance(protocol, int) or protocol <= 0:
            protocol = 767
        mode, detail = check_online_mode(host, port, handshake_host, protocol)
        result["access_mode"] = mode
        result["access_detail"] = detail

    return result


def build_info(result):
    if not result["online"]:
        return [("ADDRESS", result["address"]), ("ERROR", result["error"])]

    query = result.get("query") or {}
    names = query.get("players") or result.get("players_sample") or []

    items = [
        ("ADDRESS", result["resolved"]),
        ("VERSION", f"{result['version']} (protocol {result['protocol']})"),
    ]
    if query.get("software"):
        software = f"{query['software']} {query.get('software_version', '')}".strip()
        items.append(("SOFTWARE", software))
    if query.get("map"):
        items.append(("MAP", query["map"]))

    items += [
        ("ACCESS MODE", access_text(result)),
        ("PING", f"{result['latency_ms']} ms"),
        ("PLAYERS", f"{result['players_online']} / {result['players_max']}"),
        ("PLAYER LIST", ", ".join(names) if names else "Not shared by the server."),
        ("MOTD CODE", result["motd_code"] or "(empty)"),
        ("CHECKED AT", result["checked_at"].replace("T", "  ")),
    ]
    return items


def access_text(result):
    mode = result.get("access_mode", "skipped")
    names = {
        "premium": "PREMIUM (online-mode)",
        "cracked": "CRACKED (offline-mode)",
        "unknown": "UNKNOWN",
        "skipped": "SKIPPED",
    }
    return f"{names.get(mode, mode.upper())} - {result.get('access_detail', '')}".strip(" -")


def save_json_report(filename, text, fallback_dir):
    """Save into the Downloads folder. Returns a readable location."""
    data = text.encode("utf-8")

    # Android 10+ (MediaStore - works without special permissions)
    try:
        from jnius import autoclass
        build_version = autoclass("android.os.Build$VERSION")
        if build_version.SDK_INT >= 29:
            python_activity = autoclass("org.kivy.android.PythonActivity")
            content_values = autoclass("android.content.ContentValues")
            downloads_collection = autoclass("android.provider.MediaStore$Downloads")
            environment = autoclass("android.os.Environment")

            resolver = python_activity.mActivity.getContentResolver()
            values = content_values()
            values.put("_display_name", filename)
            values.put("mime_type", "application/json")
            values.put("relative_path", environment.DIRECTORY_DOWNLOADS)
            uri = resolver.insert(downloads_collection.EXTERNAL_CONTENT_URI, values)
            stream = resolver.openOutputStream(uri)
            stream.write(bytearray(data))
            stream.flush()
            stream.close()
            return "Downloads/" + filename
    except Exception:
        pass

    # Pydroid / older Android / desktop
    candidates = [
        Path.home() / "Downloads",
        Path("/storage/emulated/0/Download"),
        Path("/sdcard/Download"),
    ]
    for folder in candidates:
        try:
            folder.mkdir(parents=True, exist_ok=True)
            path = folder / filename
            path.write_bytes(data)
            return str(path)
        except Exception:
            continue

    folder = Path(fallback_dir)
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / filename
    path.write_bytes(data)
    return str(path)


# ==================================================================
#  UI (Kivy)
# ==================================================================
from kivy.app import App  # noqa: E402
from kivy.clock import Clock  # noqa: E402
from kivy.core.clipboard import Clipboard  # noqa: E402
from kivy.core.image import Image as CoreImage  # noqa: E402
from kivy.core.text import Label as CoreLabel  # noqa: E402
from kivy.core.window import Window  # noqa: E402
from kivy.graphics import Color, Ellipse, Line, Rectangle, RoundedRectangle  # noqa: E402
from kivy.metrics import dp, sp  # noqa: E402
from kivy.uix.behaviors import ButtonBehavior  # noqa: E402
from kivy.uix.boxlayout import BoxLayout  # noqa: E402
from kivy.uix.button import Button  # noqa: E402
from kivy.uix.checkbox import CheckBox  # noqa: E402
from kivy.uix.floatlayout import FloatLayout  # noqa: E402
from kivy.uix.gridlayout import GridLayout  # noqa: E402
from kivy.uix.image import Image  # noqa: E402
from kivy.uix.label import Label  # noqa: E402
from kivy.uix.popup import Popup  # noqa: E402
from kivy.uix.scrollview import ScrollView  # noqa: E402
from kivy.uix.textinput import TextInput  # noqa: E402
from kivy.uix.widget import Widget  # noqa: E402
from kivy.utils import escape_markup, get_color_from_hex  # noqa: E402

try:
    import arabic_reshaper
    from bidi.algorithm import get_display
except Exception:
    arabic_reshaper = None
    get_display = None

Window.clearcolor = get_color_from_hex(BG)
Window.softinput_mode = "below_target"


def rgba(color):
    return tuple(get_color_from_hex(color))


def px(n):
    return dp(max(1, n * UI_SCALE))


def fs(n):
    return sp(max(6, n * UI_SCALE))


# ------------------------------------------------------------------
#  PERSIAN TEXT SUPPORT (shaping + right-to-left + font)
# ------------------------------------------------------------------
def find_persian_font():
    here = os.path.dirname(os.path.abspath(__file__))
    try:
        for name in sorted(os.listdir(here)):
            if name.lower().endswith(".ttf"):
                return os.path.join(here, name)      # your own font file wins
    except Exception:
        pass
    for path in (
        "/system/fonts/NotoNaskhArabic-Regular.ttf",
        "/system/fonts/NotoNaskhArabicUI-Regular.ttf",
        "/system/fonts/NotoSansArabic-Regular.ttf",
        "/system/fonts/NotoSansArabicUI-Regular.ttf",
        "/system/fonts/DroidNaskh-Regular.ttf",
        "/system/fonts/NotoKufiArabic-Regular.ttf",
    ):
        if os.path.exists(path):
            return path
    return None


FA_FONT = find_persian_font()


def fa(text, width=28):
    """Prepare Persian text: wrap -> join letters -> right-to-left order."""
    lines = []
    for paragraph in text.split("\n"):
        for line in textwrap.wrap(paragraph, width) or [""]:
            line = line.replace("\u200c", "")
            if arabic_reshaper is not None and get_display is not None:
                try:
                    line = get_display(arabic_reshaper.reshape(line), base_dir="R")
                except Exception:
                    pass
            lines.append(line)
    return "\n".join(lines)


# ------------------------------------------------------------------
#  CUSTOM WIDGETS
# ------------------------------------------------------------------
class AutoLabel(Label):
    """Label that wraps to its width and grows in height to fit the text."""

    def __init__(self, **kw):
        kw.setdefault("size_hint_y", None)
        kw.setdefault("halign", "left")
        kw.setdefault("valign", "top")
        super().__init__(**kw)
        self.bind(width=self._wrap, texture_size=self._fit)

    def _wrap(self, *_):
        self.text_size = (self.width, None)

    def _fit(self, *_):
        self.height = self.texture_size[1]


class RoundBox(BoxLayout):
    """Rounded card with border and an optional green accent line."""

    def __init__(self, fill=CARD, border=CARD_BORDER, radius=16, accent=None, **kw):
        super().__init__(**kw)
        self.radius_px = px(radius)
        with self.canvas.before:
            self._fill_c = Color(*rgba(fill))
            self._fill_r = RoundedRectangle(pos=self.pos, size=self.size, radius=[self.radius_px])
            self._border_c = Color(*rgba(border))
            self._border_l = Line(rounded_rectangle=(0, 0, 10, 10, 2), width=dp(1.5))
            self._acc_c = Color(*(rgba(accent) if accent else (0, 0, 0, 0)))
            self._acc_l = Line(points=[0, 0, 0, 0], width=dp(2.5), cap="round")
        self.bind(pos=self._redraw, size=self._redraw)
        self._redraw()

    def _redraw(self, *_):
        x, y = self.pos
        w, h = self.size
        self._fill_r.pos = self.pos
        self._fill_r.size = self.size
        self._border_l.rounded_rectangle = (
            x + 1, y + 1, max(4, w - 2), max(4, h - 2), self.radius_px
        )
        self._acc_l.points = [
            x + px(13), y + px(14),
            x + px(13), y + max(px(15), h - px(14))
        ]

    def set_border(self, color):
        self._border_c.rgba = rgba(color)

    def set_accent(self, color):
        self._acc_c.rgba = rgba(color)


class Card(RoundBox):
    def __init__(self, title, value="--", value_color=TEXT, **kw):
        super().__init__(
            orientation="vertical", accent=CARD_BORDER,
            padding=[px(24), px(9), px(12), px(9)], spacing=px(1),
            size_hint_y=None, **kw
        )
        self.title = AutoLabel(text=title, color=rgba(MUTED), font_size=fs(9), bold=True)
        self.value = AutoLabel(text=value, color=rgba(value_color), font_size=fs(15), bold=True)
        self.sub = AutoLabel(text="", color=rgba(MUTED), font_size=fs(9))
        self.add_widget(self.title)
        self.add_widget(self.value)
        self.add_widget(self.sub)
        self.bind(minimum_height=self.setter("height"))

    def set(self, value, sub="", color=TEXT):
        self.value.text = value
        self.value.color = rgba(color)
        self.sub.text = sub
        self.set_accent(color if color != TEXT else CARD_BORDER)


class StatBar(Widget):
    def __init__(self, **kw):
        super().__init__(size_hint_y=None, height=px(10), **kw)
        self.ratio = 0.0
        self.color = ACCENT
        self.bind(pos=self.draw, size=self.draw)

    def draw(self, *_):
        self.canvas.clear()
        with self.canvas:
            Color(*rgba(INPUT_BG))
            RoundedRectangle(pos=self.pos, size=self.size, radius=[px(4)])
            fill_w = self.width * self.ratio
            if fill_w > px(8):
                Color(*rgba(self.color))
                RoundedRectangle(pos=self.pos, size=(fill_w, self.height), radius=[px(4)])

    def set(self, ratio, color=ACCENT):
        self.ratio = max(0.0, min(1.0, ratio))
        self.color = color
        self.draw()


class GlowButton(ButtonBehavior, Label):
    def __init__(self, text, command, color=ACCENT_DARK, outline=ACCENT,
                 press=ACCENT_PRESS, height=48, text_size_pt=12, **kw):
        super().__init__(
            text=text, size_hint_y=None, height=px(height), bold=True,
            font_size=fs(text_size_pt), color=rgba(TEXT),
            disabled_color=rgba(DISABLED_TEXT), halign="center", valign="middle",
            **kw
        )
        self.command = command
        self.face = color
        self.outline = outline
        self.press = press
        self.bind(pos=self.draw, size=self.draw, state=self.draw, disabled=self.draw)
        self.draw()

    def draw(self, *_):
        self.canvas.before.clear()
        x, y = self.pos
        w, h = self.size
        radius = px(15)
        down = self.state == "down"
        if self.disabled:
            fill, border, shadow = DISABLED, CARD_BORDER, BG
        else:
            fill = self.press if down else self.face
            border = self.outline
            shadow = lerp_color(fill, "#000000", 0.55)
        dy = px(2) if down else 0
        with self.canvas.before:
            Color(*rgba(shadow))
            RoundedRectangle(pos=(x, y), size=(w, max(4, h - px(3))), radius=[radius])
            Color(*rgba(fill))
            RoundedRectangle(pos=(x, y + px(4) - dy), size=(w, max(4, h - px(5))), radius=[radius])
            Color(*rgba(border))
            Line(rounded_rectangle=(x + 1, y + px(4) - dy, max(4, w - 2), max(4, h - px(5)), radius),
                 width=dp(1.5))

    def set_enabled(self, value):
        self.disabled = not value

    def on_release(self):
        if not self.disabled:
            self.command()


class TapLabel(ButtonBehavior, Label):
    pass


def text_texture(text, size, bold=True):
    lbl = CoreLabel(text=text, font_size=size, bold=bold)
    lbl.refresh()
    return lbl.texture


def blit(texture, cx, cy, color):
    Color(*color)
    Rectangle(texture=texture, pos=(cx - texture.width / 2, cy - texture.height / 2),
              size=texture.size)


class Header(Widget):
    """Night sky + pixel grass + glowing title + fireflies."""

    def __init__(self, **kw):
        super().__init__(size_hint_y=None, height=px(110), **kw)
        self.landscape = False
        self.flies = []
        self.bind(pos=self.draw, size=self.draw)
        Clock.schedule_interval(self.animate, 0.1)

    def set_landscape(self, value):
        self.landscape = value
        self.height = px(70) if value else px(110)

    def draw(self, *_):
        w, h = self.size
        if w < 10 or h < 10:
            return
        x0, y0 = self.pos
        self.canvas.clear()
        self.flies = []
        rng = random.Random(11)
        cell = px(8)
        land = self.landscape

        with self.canvas:
            # sky gradient
            step = px(2)
            for i in range(int(h // step) + 1):
                t = min(1.0, ((i * step) / h) ** 0.8)
                Color(*rgba(lerp_color("#14532d", BG, t)))
                Rectangle(pos=(x0, y0 + h - (i + 1) * step), size=(w, step))

            # stars
            for _ in range(46):
                sx = x0 + rng.random() * w
                sy = y0 + h - rng.random() * (h * 0.65)
                size = dp(rng.choice([1, 1, 2]))
                Color(*rgba(rng.choice(["#bef264", "#86efac", "#ffffff"])))
                Ellipse(pos=(sx, sy), size=(size, size))

            # pixel grass strip
            rows = 1 if land else 2
            greens = ["#22c55e", "#16a34a", "#15803d", "#4ade80", "#166534"]
            dirts = ["#6b4423", "#5a3a1c", "#7a5230", "#4d3119"]
            for row in range(rows):
                palette = greens if row == 0 else dirts
                for col in range(int(w // cell) + 1):
                    Color(*rgba(rng.choice(palette)))
                    Rectangle(pos=(x0 + col * cell, y0 + (rows - 1 - row) * cell),
                              size=(cell, cell))

            # glowing title
            if land:
                title_f, title_size, sub_f, sub_size = 0.34, 20, 0.66, 8
            else:
                title_f, title_size, sub_f, sub_size = 0.36, 30, 0.65, 10
            cx = x0 + w / 2
            title_y = y0 + h * (1 - title_f)
            sub_y = y0 + h * (1 - sub_f)
            title_tex = text_texture("LuVex", fs(title_size))
            glow = dp(2)
            for dx, dy in ((-1, 0), (1, 0), (0, -1), (0, 1), (-1, -1), (1, 1), (-1, 1), (1, -1)):
                blit(title_tex, cx + dx * glow, title_y + dy * glow, rgba("#14532d"))
            blit(title_tex, cx + dp(3), title_y - dp(3), rgba("#16a34a"))
            blit(title_tex, cx, title_y, rgba(TEXT))
            blit(text_texture("S E R V E R    S C A N N E R", fs(sub_size)),
                 cx, sub_y, rgba("#bef264"))

            # fireflies
            low = 3 * cell
            for _ in range(14):
                fx = rng.random() * w
                fy = low + rng.random() * max(1, h - low)
                color = Color(*rgba("#bef264"))
                dot = Ellipse(pos=(x0 + fx, y0 + fy), size=(dp(3), dp(3)))
                self.flies.append([
                    color, dot, fx, fy,
                    (rng.random() - 0.5) * 0.8,
                    (rng.random() - 0.5) * 0.4,
                    rng.random() * 6.28,
                ])

    def animate(self, *_):
        w, h = self.size
        if w < 10 or not self.flies:
            return
        x0, y0 = self.pos
        low = 2.5 * px(8)
        for fly in self.flies:
            fly[2] += fly[4]
            fly[3] += fly[5]
            fly[6] += 0.15
            if fly[2] < 0:
                fly[2] = w
            elif fly[2] > w:
                fly[2] = 0
            fly[3] = max(low, min(h * 0.95, fly[3]))
            fly[1].pos = (x0 + fly[2], y0 + fly[3])
            glow = (math.sin(fly[6]) + 1) / 2
            fly[0].rgba = rgba(lerp_color("#14532d", "#d9f99d", glow))


def parts_to_markup(parts):
    out = []
    for text, tag in parts:
        t = escape_markup(text)
        if tag == "h":
            if out:
                out.append("\n")
            out.append(f"[b][size={int(fs(10))}][color={LIME}]{t}[/color][/size][/b]")
        elif tag == "v":
            out.append(f"[size={int(fs(12))}][color={TEXT}]{t}[/color][/size]")
        elif tag == "m":
            out.append(f"[size={int(fs(11))}][color={MUTED}]{t}[/color][/size]")
        elif tag == "code":
            out.append(
                f"[font=data/fonts/RobotoMono-Regular.ttf][size={int(fs(11))}]"
                f"[color={CODE}]{t}[/color][/size][/font]"
            )
        else:
            out.append(t)
    return "".join(out)


def show_message(title, message):
    box = BoxLayout(orientation="vertical", padding=px(12), spacing=px(10))
    lbl = Label(text=message, color=rgba(TEXT), halign="left", valign="middle",
                font_size=fs(12))
    lbl.bind(size=lambda w, _s: setattr(w, "text_size", (w.width, None)))
    popup = Popup(
        title=title, content=box, size_hint=(0.88, None), height=px(280),
        background="", background_color=rgba(CARD),
        separator_color=rgba(ACCENT), title_color=rgba(LIME)
    )
    box.add_widget(lbl)
    box.add_widget(GlowButton("OK", popup.dismiss, height=46))
    popup.open()


# ------------------------------------------------------------------
#  SCANNER SCREEN
# ------------------------------------------------------------------
def is_landscape():
    return Window.width > Window.height * 1.1


class ScannerScreen(BoxLayout):
    def __init__(self, **kw):
        super().__init__(orientation="vertical", **kw)
        self.scanning = False
        self.last_result = None
        self.toast_event = None
        self.landscape = None
        self.icon_widget = None

        self.header = Header()
        self.add_widget(self.header)

        self.body = BoxLayout(padding=[px(14), px(12), px(14), 0])
        self.add_widget(self.body)

        self.footer = Label(
            text=FOOTER_TEXT, size_hint_y=None, height=px(26),
            color=rgba(DISABLED_TEXT), font_size=fs(9)
        )
        self.add_widget(self.footer)

        self.left = BoxLayout(orientation="vertical", size_hint_y=None, spacing=px(8))
        self.left.bind(minimum_height=self.left.setter("height"))
        self.right = BoxLayout(orientation="vertical", size_hint_y=None, spacing=px(8))
        self.right.bind(minimum_height=self.right.setter("height"))

        self.build_left()
        self.build_right()
        self.reset_cards()

        Window.bind(size=self.on_window_size)
        self.apply_layout(is_landscape())

    # ---------- build panels ----------
    def build_left(self):
        self.left.add_widget(AutoLabel(
            text="Server IP: Play.example.com:25565",
            color=rgba(MUTED), font_size=fs(10), bold=True
        ))

        self.entry_card = RoundBox(
            fill=INPUT_BG, border=CARD_BORDER, radius=14,
            size_hint_y=None, height=px(54), padding=px(4)
        )
        self.ip_entry = TextInput(
            text=DEFAULT_IP, hint_text="play.example.com:25565",
            multiline=False, write_tab=False, font_size=fs(14),
            foreground_color=rgba(TEXT), hint_text_color=rgba(DISABLED_TEXT),
            cursor_color=(1, 1, 1, 1), selection_color=(0.13, 0.77, 0.37, 0.4),
            background_normal="", background_active="", background_color=(0, 0, 0, 0),
            padding=[px(10), px(14), px(10), px(10)]
        )
        self.ip_entry.bind(
            on_text_validate=lambda *_: self.start_scan(),
            focus=lambda _i, v: self.entry_card.set_border(ACCENT if v else CARD_BORDER)
        )
        self.entry_card.add_widget(self.ip_entry)
        self.left.add_widget(self.entry_card)

        buttons = BoxLayout(size_hint_y=None, height=px(54), spacing=px(10))
        self.scan_btn = GlowButton("SCAN SERVER", self.start_scan, height=52, size_hint_x=3)
        self.save_btn = GlowButton(
            "SAVE REPORT", self.save_report, color=TEAL, outline=GREEN,
            press=TEAL_PRESS, height=52, text_size_pt=11, size_hint_x=2
        )
        self.save_btn.set_enabled(False)
        buttons.add_widget(self.scan_btn)
        buttons.add_widget(self.save_btn)
        self.left.add_widget(buttons)

        cards = GridLayout(cols=2, spacing=px(8), size_hint_y=None)
        cards.bind(minimum_height=cards.setter("height"))
        self.status_card = Card("STATUS", "READY", MUTED)
        self.ping_card = Card("PING")
        self.version_card = Card("VERSION")
        self.players_card = Card("PLAYERS")
        self.players_bar = StatBar()
        self.players_card.add_widget(self.players_bar)
        for card in (self.status_card, self.ping_card, self.version_card, self.players_card):
            cards.add_widget(card)
        self.left.add_widget(cards)

    def build_right(self):
        self.access_card = Card("ACCESS MODE  (CRACKED OR PREMIUM)", "--")
        self.right.add_widget(self.access_card)

        options = RoundBox(
            orientation="vertical", size_hint_y=None, radius=14,
            padding=[px(12), px(8), px(10), px(6)], spacing=px(2)
        )
        options.bind(minimum_height=options.setter("height"))
        options.add_widget(AutoLabel(text="SERVER INFO", color=rgba(GREEN),
                                     font_size=fs(10), bold=True))
        row = BoxLayout(size_hint_y=None, height=px(40))
        self.check_box = CheckBox(
            active=True, size_hint=(None, None), size=(px(40), px(40)),
            color=rgba(ACCENT)
        )
        tap = TapLabel(
            text="Check cracked / premium", color=rgba(TEXT), font_size=fs(11),
            bold=True, halign="left", valign="middle"
        )
        tap.bind(size=lambda w, _s: setattr(w, "text_size", (w.width, None)))
        tap.bind(on_release=lambda *_: setattr(self.check_box, "active", not self.check_box.active))
        row.add_widget(self.check_box)
        row.add_widget(tap)
        options.add_widget(row)
        self.right.add_widget(options)

        copy_row = BoxLayout(size_hint_y=None, height=px(46), spacing=px(6))
        self.copy_info_btn = GlowButton(
            "COPY INFO", self.copy_info, color=TEAL, outline=GREEN,
            press=TEAL_PRESS, height=42, text_size_pt=9
        )
        self.copy_motd_btn = GlowButton("COPY MOTD", self.copy_motd, height=42, text_size_pt=9)
        self.copy_players_btn = GlowButton(
            "COPY PLAYERS", self.copy_players, color=TEAL, outline=GREEN,
            press=TEAL_PRESS, height=42, text_size_pt=9
        )
        for btn in (self.copy_info_btn, self.copy_motd_btn, self.copy_players_btn):
            btn.set_enabled(False)
            copy_row.add_widget(btn)
        self.right.add_widget(copy_row)

        self.info_card = RoundBox(
            orientation="vertical", size_hint_y=None, radius=16,
            padding=px(12), spacing=px(6)
        )
        self.info_card.bind(minimum_height=self.info_card.setter("height"))
        self.info_label = AutoLabel(markup=True, color=rgba(TEXT), font_size=fs(11))
        self.info_card.add_widget(self.info_label)
        self.right.add_widget(self.info_card)

    # ---------- portrait / landscape ----------
    def on_window_size(self, *_):
        self.apply_layout(is_landscape())

    def apply_layout(self, landscape):
        if self.landscape == landscape:
            return
        self.landscape = landscape
        for widget in (self.left, self.right):
            if widget.parent is not None:
                widget.parent.remove_widget(widget)
        self.body.clear_widgets()
        self.header.set_landscape(landscape)

        if landscape:
            self.body.orientation = "horizontal"
            self.body.spacing = px(16)
            left_scroll = ScrollView(size_hint_x=0.4, do_scroll_x=False, bar_width=px(3))
            right_scroll = ScrollView(size_hint_x=0.6, do_scroll_x=False, bar_width=px(3))
            left_scroll.add_widget(self.left)
            right_scroll.add_widget(self.right)
            self.body.add_widget(left_scroll)
            self.body.add_widget(right_scroll)
        else:
            self.body.orientation = "vertical"
            self.body.spacing = 0
            column = BoxLayout(
                orientation="vertical", size_hint_y=None, spacing=px(10),
                padding=[0, 0, 0, px(16)]
            )
            column.bind(minimum_height=column.setter("height"))
            column.add_widget(self.left)
            column.add_widget(self.right)
            scroll = ScrollView(do_scroll_x=False, bar_width=px(3))
            scroll.add_widget(column)
            self.body.add_widget(scroll)

    # ---------- small helpers ----------
    def toast(self, message, color=LIME):
        self.footer.text = message
        self.footer.color = rgba(color)
        if self.toast_event is not None:
            self.toast_event.cancel()
        self.toast_event = Clock.schedule_once(self._clear_toast, 1.8)

    def _clear_toast(self, *_):
        self.footer.text = FOOTER_TEXT
        self.footer.color = rgba(DISABLED_TEXT)

    def copy_to_clipboard(self, text, label):
        try:
            Clipboard.copy(text)
            self.toast(f"Copied: {label}")
        except Exception as exc:
            self.toast(f"Copy failed: {exc}", RED)

    def write_info(self, parts, icon=None):
        if self.icon_widget is not None and self.icon_widget.parent is not None:
            self.icon_widget.parent.remove_widget(self.icon_widget)
        self.icon_widget = None
        if icon is not None:
            self.icon_widget = Image(
                texture=icon, size_hint=(None, None), size=(px(64), px(64)),
                fit_mode="contain"
            )
            self.info_card.add_widget(self.icon_widget, index=len(self.info_card.children))
        self.info_label.text = parts_to_markup(parts)

    # ---------- copy buttons ----------
    def copy_info(self):
        result = self.last_result
        if not result:
            self.toast("Scan a server first.", YELLOW)
            return
        lines = [APP_NAME]
        for title, value in build_info(result):
            lines.append(f"{title}: {value}")
        self.copy_to_clipboard("\n".join(lines), "server info")

    def copy_motd(self):
        result = self.last_result
        if not result or not result.get("online"):
            self.toast("Scan an online server first.", YELLOW)
            return
        self.copy_to_clipboard(result["motd_code"], "MOTD code")

    def copy_players(self):
        result = self.last_result
        if not result or not result.get("online"):
            self.toast("Scan an online server first.", YELLOW)
            return
        query = result.get("query") or {}
        names = query.get("players") or result.get("players_sample") or []
        if not names:
            self.toast("The server does not share a player list.", YELLOW)
            return
        self.copy_to_clipboard("\n".join(names), "player list")

    # ---------- scanning ----------
    def start_scan(self, *_):
        address = self.ip_entry.text.strip()
        if not address:
            show_message("Luvex", "Enter a Minecraft server IP.")
            return
        if self.scanning:
            return

        self.scanning = True
        self.scan_btn.set_enabled(False)
        self.save_btn.set_enabled(False)
        self.copy_info_btn.set_enabled(False)
        self.copy_motd_btn.set_enabled(False)
        self.copy_players_btn.set_enabled(False)
        self.reset_cards()
        self.animate_scanning(0)

        threading.Thread(
            target=self.perform_scan,
            args=(address, self.check_box.active),
            daemon=True
        ).start()

    def animate_scanning(self, step):
        if not self.scanning:
            return
        color = LIME if step % 2 else ACCENT
        self.status_card.set("SCANNING" + "." * (step % 4), "Please wait", color)
        Clock.schedule_once(lambda dt: self.animate_scanning(step + 1), 0.35)

    def reset_cards(self):
        self.status_card.set("READY", "Waiting for scan", MUTED)
        self.version_card.set("--", "", TEXT)
        self.ping_card.set("--", "", TEXT)
        self.players_card.set("--", "", TEXT)
        self.players_bar.set(0)
        self.access_card.set("--", "Run a scan to see if the server is cracked or premium.", MUTED)
        self.write_info([("Enter a server IP and press SCAN SERVER.", "m")])

    def perform_scan(self, address, do_check):
        try:
            result = scan_server(address, do_check)
        except Exception as exc:
            result = {
                "application": APP_NAME,
                "checked_at": datetime.now().isoformat(timespec="seconds"),
                "address": address,
                "online": False,
                "error": str(exc) or exc.__class__.__name__,
            }
        Clock.schedule_once(lambda dt: self.display_result(result))

    def show_access(self, result):
        mode = result.get("access_mode")
        detail = result.get("access_detail", "")
        if mode == "premium":
            self.access_card.set("PREMIUM", detail, GREEN)
        elif mode == "cracked":
            self.access_card.set("CRACKED", detail, YELLOW)
        elif mode == "skipped":
            self.access_card.set("SKIPPED", detail, MUTED)
        else:
            self.access_card.set("UNKNOWN", detail, MUTED)

    def display_result(self, result):
        self.scanning = False
        self.last_result = result
        self.scan_btn.set_enabled(True)
        self.save_btn.set_enabled(True)
        self.copy_info_btn.set_enabled(True)

        if not result["online"]:
            self.status_card.set("OFFLINE", shorten(result["address"], 18), RED)
            self.version_card.set("--", "", TEXT)
            self.ping_card.set("--", "", TEXT)
            self.players_card.set("--", "", TEXT)
            self.players_bar.set(0)
            self.access_card.set("--", "Server is offline.", MUTED)
            self.copy_motd_btn.set_enabled(False)
            self.copy_players_btn.set_enabled(False)
            self.write_info([
                ("COULD NOT REACH THE SERVER\n", "h"),
                (f"{result['error']}\n", "v"),
                ("\nCHECK\n", "h"),
                ("The IP and port, your internet connection, and that the "
                 "server accepts Java status queries.", "m"),
            ])
            return

        self.copy_motd_btn.set_enabled(True)
        self.copy_players_btn.set_enabled(bool(
            (result.get("query") or {}).get("players") or result.get("players_sample")
        ))

        self.status_card.set("ONLINE", shorten(result["address"], 18), GREEN)

        ping = result["latency_ms"]
        ping_color = GREEN if ping < 80 else YELLOW if ping < 200 else RED
        self.ping_card.set(f"{ping} ms", "Latency", ping_color)

        self.version_card.set(
            shorten(result["version"], 14), f"Protocol {result['protocol']}", TEXT
        )

        online = result["players_online"]
        maximum = result["players_max"]
        ratio = online / maximum if maximum else 0
        bar_color = GREEN if ratio < 0.7 else YELLOW if ratio < 0.9 else RED
        self.players_card.set(f"{online} / {maximum}", "Players online", bar_color)
        self.players_bar.set(ratio, bar_color)

        self.show_access(result)
        self.show_info(result)

    def show_info(self, result):
        icon = None
        raw_icon = result.get("_icon")
        if raw_icon:
            try:
                data = raw_icon.split(",", 1)[1] if "," in raw_icon else raw_icon
                icon = CoreImage(io.BytesIO(base64.b64decode(data)), ext="png").texture
                icon.mag_filter = "nearest"
            except Exception:
                icon = None

        parts = []
        for title, value in build_info(result):
            parts.append((f"{title}\n", "h"))
            if title == "MOTD CODE":
                parts.append((f"{value}\n", "code"))
            elif title in ("PLAYER LIST", "CHECKED AT"):
                parts.append((f"{value}\n", "m"))
            else:
                parts.append((f"{value}\n", "v"))
        self.write_info(parts, icon)

    def save_report(self):
        result = self.last_result
        if not result:
            show_message("Luvex", "Scan a server first.")
            return
        try:
            filename = "luvex_report_" + datetime.now().strftime("%Y%m%d_%H%M%S") + ".json"
            clean = {k: v for k, v in result.items() if not k.startswith("_")}
            text = json.dumps(clean, indent=2, ensure_ascii=False)
            where = save_json_report(filename, text, App.get_running_app().user_data_dir)
            show_message("Report saved", f"Report saved to:\n{where}")
        except Exception as exc:
            show_message("Save failed", str(exc))


# ------------------------------------------------------------------
#  SPLASH / HOME / INFO PAGES + ROOT
# ------------------------------------------------------------------
INFO_FA_1 = (
    "سلام دوست عزیز! به برنامه LuVexMineCraftServerScanner خوش اومدی. "
    "اینجا می‌تونی سرورهای ماینکرفت رو اسکن کنی و اطلاعات عمومی‌شون رو ببینی. "
    "یادت نره پورت سرور رو هم وارد کنی."
)
INFO_FA_SAMPLE = "نمونه آی‌پی:"
INFO_SAMPLE = "DonutSMP.net:25565\nPlay.TrexMine.Com:25565"
INFO_EN_1 = (
    "Hello, friend! Welcome to LuVexMineCraftServerScanner. "
    "You can scan Minecraft servers here and view their public information. "
    "Remember to include the server port."
)
INFO_EN_SAMPLE = "Example: DonutSMP.net:25565 or Play.TrexMine.Com:25565"
INFO_FA_NOTE = (
    "نکته: لیست بازیکن‌ها و جزئیات MOTD فقط وقتی نمایش داده می‌شن که سرور "
    "اون‌ها رو به اشتراک بذاره. از دکمه‌های کپی توی صفحه‌ی اسکن برای کپی "
    "کد MOTD یا اسم بازیکن‌ها استفاده کن."
)
INFO_EN_NOTE = (
    "Note: Player lists and MOTD details are only available when the "
    "server shares them. Use the copy buttons on the scan screen to copy "
    "the MOTD code or available player names."
)


class Root(FloatLayout):
    def __init__(self, **kw):
        super().__init__(**kw)
        self.screen = "splash"

        self.scanner = ScannerScreen()
        self.add_widget(self.scanner)

        self.page_layer = BoxLayout(orientation="vertical")
        with self.page_layer.canvas.before:
            Color(*rgba(BG))
            self._page_bg = Rectangle(pos=self.page_layer.pos, size=self.page_layer.size)
        self.page_layer.bind(
            pos=lambda *_: setattr(self._page_bg, "pos", self.page_layer.pos),
            size=lambda *_: setattr(self._page_bg, "size", self.page_layer.size),
        )
        self.add_widget(self.page_layer)

        self.back_button = Button(
            text="\u2039 Home", size_hint=(None, None), size=(px(84), px(36)),
            pos_hint={"x": 0.02, "top": 0.99}, background_normal="", background_down="",
            background_color=rgba(ACCENT_DARK), color=rgba(TEXT), bold=True,
            font_size=fs(10)
        )
        self.back_button.bind(on_release=lambda *_: self.back_to_home())

        self.show_splash()

    def clear_page(self):
        self.page_layer.clear_widgets()

    def show_splash(self):
        self.screen = "splash"
        self.clear_page()
        page = FloatLayout()
        page.add_widget(Label(
            text="LuVex", color=rgba(GREEN), font_size=fs(34), bold=True,
            pos_hint={"center_x": 0.5, "center_y": 0.60}
        ))
        page.add_widget(Label(
            text="MINECRAFT SERVER SCANNER", color=rgba(LIME), font_size=fs(10),
            bold=True, pos_hint={"center_x": 0.5, "center_y": 0.52}
        ))
        page.add_widget(Label(
            text="Loading...", color=rgba(MUTED), font_size=fs(11),
            pos_hint={"center_x": 0.5, "center_y": 0.42}
        ))
        self.page_layer.add_widget(page)
        Clock.schedule_once(self._after_splash, 6)

    def _after_splash(self, *_):
        if self.screen == "splash":
            self.show_home()

    def show_home(self):
        self.screen = "home"
        self.clear_page()
        home = BoxLayout(orientation="vertical", padding=[px(35), px(60), px(35), px(18)],
                         spacing=px(14))
        home.add_widget(Widget(size_hint_y=0.3))
        home.add_widget(Label(
            text="LuVex", color=rgba(TEXT), font_size=fs(32), bold=True,
            size_hint_y=None, height=px(60)
        ))
        home.add_widget(Label(
            text="MINECRAFT SERVER SCANNER", color=rgba(LIME), font_size=fs(10),
            bold=True, size_hint_y=None, height=px(30)
        ))
        home.add_widget(Widget(size_hint_y=None, height=px(24)))
        home.add_widget(GlowButton("Start Scan", self.show_scanner, height=58, text_size_pt=15))
        home.add_widget(GlowButton("Info", self.show_info_page, height=58, text_size_pt=15))
        home.add_widget(Widget())
        home.add_widget(Label(
            text="Green-powered server scanner", color=rgba(DISABLED_TEXT),
            font_size=fs(9), size_hint_y=None, height=px(24)
        ))
        self.page_layer.add_widget(home)

    def show_info_page(self):
        self.screen = "info"
        self.clear_page()
        page = BoxLayout(orientation="vertical", padding=px(14), spacing=px(10))

        top = BoxLayout(size_hint_y=None, height=px(46))
        top.add_widget(GlowButton("\u2039 Back", self.show_home, height=44,
                                  text_size_pt=12, size_hint_x=None, width=px(110)))
        top.add_widget(Widget())
        page.add_widget(top)

        page.add_widget(Label(
            text="LuVex Server Scanner", color=rgba(GREEN), font_size=fs(19),
            bold=True, size_hint_y=None, height=px(44)
        ))

        card = RoundBox(orientation="vertical", size_hint_y=None, padding=px(16),
                        spacing=px(14), radius=16)
        card.bind(minimum_height=card.setter("height"))

        def persian(text, size=13):
            kw = dict(text=fa(text), halign="right", color=rgba(TEXT), font_size=fs(size))
            if FA_FONT:
                kw["font_name"] = FA_FONT
            card.add_widget(AutoLabel(**kw))

        def english(text, color=TEXT, size=12, bold=False):
            card.add_widget(AutoLabel(text=text, color=rgba(color), font_size=fs(size), bold=bold))

        persian(INFO_FA_1)
        persian(INFO_FA_SAMPLE)
        english(INFO_SAMPLE, color=LIME, bold=True)
        english(INFO_EN_1)
        english(INFO_EN_SAMPLE, color=MUTED, size=11)
        persian(INFO_FA_NOTE, size=12)
        english(INFO_EN_NOTE, color=MUTED, size=11)

        scroll = ScrollView(do_scroll_x=False, bar_width=px(3))
        scroll.add_widget(card)
        page.add_widget(scroll)
        self.page_layer.add_widget(page)

    def show_scanner(self):
        self.screen = "scanner"
        if self.page_layer.parent is not None:
            self.remove_widget(self.page_layer)
        if self.back_button.parent is None:
            self.add_widget(self.back_button)

    def back_to_home(self):
        if self.back_button.parent is not None:
            self.remove_widget(self.back_button)
        if self.page_layer.parent is None:
            self.add_widget(self.page_layer)
        self.show_home()

    def handle_back(self):
        """Android back button. Returns True when handled."""
        if self.screen == "scanner":
            self.back_to_home()
            return True
        if self.screen == "info":
            self.show_home()
            return True
        return False


class LuvexApp(App):
    title = APP_NAME

    def build(self):
        self.main = Root()
        Window.bind(on_keyboard=self.on_key)
        return self.main

    def on_key(self, _window, key, *_args):
        if key == 27:
            return self.main.handle_back()
        return False


if __name__ == "__main__":
    LuvexApp().run()
