#!/usr/bin/env python3
"""Count IPv4/IPv6 traffic for a UDP server port, grouped by remote IP."""

from __future__ import annotations

import argparse
import signal
import socket
import sqlite3
import struct
import sys
import time
from collections import defaultdict
from pathlib import Path
from threading import Event


DEFAULT_DB = Path("/var/lib/hy2mon/stats.db")
ETH_P_ALL = 0x0003
ETH_P_IP = 0x0800
ETH_P_IPV6 = 0x86DD
VLAN_TYPES = {0x8100, 0x88A8, 0x9100}
PACKET_OUTGOING = 4


def parse_packet(
    frame: bytes, packet_type: int, monitored_port: int
) -> tuple[str, str, int] | None:
    """Return (remote_ip, rx_or_tx, IP-layer bytes), or None."""
    if len(frame) < 14:
        return None

    ether_type = struct.unpack_from("!H", frame, 12)[0]
    offset = 14
    while ether_type in VLAN_TYPES:
        if len(frame) < offset + 4:
            return None
        ether_type = struct.unpack_from("!H", frame, offset + 2)[0]
        offset += 4

    if ether_type == ETH_P_IP:
        parsed = _parse_ipv4(frame, offset)
    elif ether_type == ETH_P_IPV6:
        parsed = _parse_ipv6(frame, offset)
    else:
        return None

    if parsed is None:
        return None
    src_ip, dst_ip, src_port, dst_port, ip_bytes = parsed

    if packet_type == PACKET_OUTGOING:
        if src_port != monitored_port:
            return None
        return dst_ip, "tx", ip_bytes

    if dst_port != monitored_port:
        return None
    return src_ip, "rx", ip_bytes


def _parse_ipv4(frame: bytes, offset: int):
    if len(frame) < offset + 20 or frame[offset] >> 4 != 4:
        return None
    header_length = (frame[offset] & 0x0F) * 4
    if header_length < 20 or len(frame) < offset + header_length + 8:
        return None
    total_length = struct.unpack_from("!H", frame, offset + 2)[0]
    fragment = struct.unpack_from("!H", frame, offset + 6)[0]
    if frame[offset + 9] != socket.IPPROTO_UDP or fragment & 0x1FFF:
        return None

    udp_offset = offset + header_length
    src_port, dst_port = struct.unpack_from("!HH", frame, udp_offset)
    src_ip = socket.inet_ntop(socket.AF_INET, frame[offset + 12 : offset + 16])
    dst_ip = socket.inet_ntop(socket.AF_INET, frame[offset + 16 : offset + 20])
    if total_length < header_length + 8:
        return None
    return src_ip, dst_ip, src_port, dst_port, total_length


def _parse_ipv6(frame: bytes, offset: int):
    if len(frame) < offset + 40 or frame[offset] >> 4 != 6:
        return None
    payload_length = struct.unpack_from("!H", frame, offset + 4)[0]
    next_header = frame[offset + 6]
    cursor = offset + 40

    while next_header != socket.IPPROTO_UDP:
        if next_header in (0, 43, 60):  # Hop-by-hop, routing, destination
            if len(frame) < cursor + 2:
                return None
            next_header, length = frame[cursor], (frame[cursor + 1] + 1) * 8
        elif next_header == 44:  # Fragment header
            if len(frame) < cursor + 8:
                return None
            fragment = struct.unpack_from("!H", frame, cursor + 2)[0]
            if fragment & 0xFFF8:
                return None
            next_header, length = frame[cursor], 8
        elif next_header == 51:  # Authentication header
            if len(frame) < cursor + 2:
                return None
            next_header, length = frame[cursor], (frame[cursor + 1] + 2) * 4
        else:
            return None
        cursor += length
        if len(frame) < cursor:
            return None

    if len(frame) < cursor + 8:
        return None
    src_port, dst_port = struct.unpack_from("!HH", frame, cursor)
    src_ip = socket.inet_ntop(socket.AF_INET6, frame[offset + 8 : offset + 24])
    dst_ip = socket.inet_ntop(socket.AF_INET6, frame[offset + 24 : offset + 40])
    return src_ip, dst_ip, src_port, dst_port, 40 + payload_length


def open_database(path: str | Path) -> sqlite3.Connection:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path, timeout=5)
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("PRAGMA synchronous=NORMAL")
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS traffic (
            ip TEXT PRIMARY KEY,
            rx_bytes INTEGER NOT NULL DEFAULT 0,
            tx_bytes INTEGER NOT NULL DEFAULT 0,
            rx_packets INTEGER NOT NULL DEFAULT 0,
            tx_packets INTEGER NOT NULL DEFAULT 0,
            last_seen REAL NOT NULL
        )
        """
    )
    connection.execute(
        "CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)"
    )
    connection.execute(
        "INSERT OR IGNORE INTO metadata(key, value) VALUES ('started_at', ?)",
        (str(time.time()),),
    )
    connection.commit()
    return connection


def flush_pending(connection: sqlite3.Connection, pending: dict) -> None:
    if not pending:
        return
    with connection:
        connection.executemany(
            """
            INSERT INTO traffic(ip, rx_bytes, tx_bytes, rx_packets, tx_packets, last_seen)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(ip) DO UPDATE SET
                rx_bytes = rx_bytes + excluded.rx_bytes,
                tx_bytes = tx_bytes + excluded.tx_bytes,
                rx_packets = rx_packets + excluded.rx_packets,
                tx_packets = tx_packets + excluded.tx_packets,
                last_seen = MAX(last_seen, excluded.last_seen)
            """,
            ((ip, *values) for ip, values in pending.items()),
        )


def read_snapshot(path: str | Path):
    connection = sqlite3.connect(f"file:{Path(path)}?mode=ro", uri=True, timeout=2)
    try:
        rows = connection.execute(
            """
            SELECT ip, rx_bytes, tx_bytes, rx_packets, tx_packets, last_seen
            FROM traffic
            ORDER BY rx_bytes + tx_bytes DESC, ip
            """
        ).fetchall()
        item = connection.execute(
            "SELECT value FROM metadata WHERE key = 'started_at'"
        ).fetchone()
        return rows, float(item[0]) if item else None
    finally:
        connection.close()


def find_default_interface() -> str:
    try:
        with open("/proc/net/route", encoding="ascii") as route_file:
            next(route_file, None)
            for line in route_file:
                fields = line.split()
                if len(fields) >= 4 and fields[1] == "00000000":
                    if int(fields[3], 16) & 1:
                        return fields[0]
    except OSError:
        pass
    raise RuntimeError("无法自动识别公网网卡，请通过 --interface 指定，例如 eth0")


def run_collector(interface: str, port: int, db_path: Path, flush_interval: float):
    if not hasattr(socket, "AF_PACKET"):
        raise RuntimeError("collect 只能在 Linux 上运行")
    if interface == "auto":
        interface = find_default_interface()

    connection = open_database(db_path)
    packet_socket = socket.socket(
        socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL)
    )
    packet_socket.bind((interface, 0))
    packet_socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 * 1024 * 1024)
    packet_socket.settimeout(1)

    stopping = Event()
    for signal_number in (signal.SIGINT, signal.SIGTERM):
        signal.signal(signal_number, lambda _signum, _frame: stopping.set())

    pending = defaultdict(lambda: [0, 0, 0, 0, 0.0])
    last_flush = time.monotonic()
    print(f"Monitoring UDP :{port} on {interface}; database: {db_path}", flush=True)

    try:
        while not stopping.is_set():
            try:
                frame, address = packet_socket.recvfrom(262_144)
            except socket.timeout:
                frame = None
            if frame is not None:
                result = parse_packet(frame, address[2], port)
                if result:
                    ip, direction, byte_count = result
                    values = pending[ip]
                    index = 0 if direction == "rx" else 1
                    values[index] += byte_count
                    values[index + 2] += 1
                    values[4] = time.time()
            if time.monotonic() - last_flush >= flush_interval:
                flush_pending(connection, pending)
                pending.clear()
                last_flush = time.monotonic()
    finally:
        flush_pending(connection, pending)
        packet_socket.close()
        connection.close()


def format_bytes(value: int) -> str:
    amount = float(value)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if amount < 1024 or unit == "TiB":
            return f"{amount:.0f} {unit}" if unit == "B" else f"{amount:.2f} {unit}"
        amount /= 1024
    raise AssertionError("unreachable")


def render_snapshot(rows, started_at: float | None) -> str:
    now = time.time()
    elapsed = max(0, int(now - started_at)) if started_at else 0
    hours, remainder = divmod(elapsed, 3600)
    minutes, seconds = divmod(remainder, 60)
    lines = [f"HY2 traffic monitor | running {hours:02d}:{minutes:02d}:{seconds:02d}", ""]
    lines.append(
        f"{'REMOTE IP':<39} {'RX':>11} {'TX':>11} {'TOTAL':>11} "
        f"{'RX PKTS':>10} {'TX PKTS':>10} {'LAST SEEN':>19}"
    )
    lines.append("-" * 119)
    total_rx = total_tx = total_rx_packets = total_tx_packets = 0
    for ip, rx, tx, rx_packets, tx_packets, last_seen in rows:
        total_rx += rx
        total_tx += tx
        total_rx_packets += rx_packets
        total_tx_packets += tx_packets
        seen = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(last_seen))
        lines.append(
            f"{ip:<39} {format_bytes(rx):>11} {format_bytes(tx):>11} "
            f"{format_bytes(rx + tx):>11} {rx_packets:>10} {tx_packets:>10} {seen:>19}"
        )
    lines.append("-" * 119)
    lines.append(
        f"{'TOTAL':<39} {format_bytes(total_rx):>11} {format_bytes(total_tx):>11} "
        f"{format_bytes(total_rx + total_tx):>11} "
        f"{total_rx_packets:>10} {total_tx_packets:>10}"
    )
    return "\n".join(lines)


def show_once(db_path: Path) -> None:
    rows, started_at = read_snapshot(db_path)
    print(render_snapshot(rows, started_at))


def run_tui(db_path: Path, refresh: float) -> None:
    try:
        while True:
            rows, started_at = read_snapshot(db_path)
            print("\033[2J\033[H" + render_snapshot(rows, started_at), flush=True)
            time.sleep(refresh)
    except KeyboardInterrupt:
        pass


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    collect = commands.add_parser("collect", help="开始抓包并累计数据")
    collect.add_argument("--interface", default="auto", help="网卡名，默认自动识别")
    collect.add_argument("--port", type=int, default=40000)
    collect.add_argument("--db", type=Path, default=DEFAULT_DB)
    collect.add_argument("--flush-interval", type=float, default=2.0)

    show = commands.add_parser("show", help="输出一次当前统计")
    show.add_argument("--db", type=Path, default=DEFAULT_DB)

    tui = commands.add_parser("tui", help="动态刷新统计表格")
    tui.add_argument("--db", type=Path, default=DEFAULT_DB)
    tui.add_argument("--refresh", type=float, default=1.0)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        if args.command == "collect":
            run_collector(args.interface, args.port, args.db, args.flush_interval)
        elif args.command == "show":
            show_once(args.db)
        else:
            run_tui(args.db, args.refresh)
        return 0
    except (OSError, RuntimeError, sqlite3.Error) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
