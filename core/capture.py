import asyncio
import json
import os
import sys
import subprocess
from typing import AsyncGenerator, Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from config import DEFAULT_INTERFACE, CAPTURE_FILTER


def get_interfaces() -> list:
    try:
        result = subprocess.run(["tshark", "-D"],
            capture_output=True, text=True, timeout=5)
        interfaces = []
        for line in result.stdout.strip().split("\n"):
            if line.strip():
                parts = line.strip().split(" ", 1)
                if len(parts) == 2:
                    interfaces.append({"index": parts[0].rstrip("."), "name": parts[1]})
        return interfaces
    except Exception:
        return []


def check_tshark() -> bool:
    try:
        subprocess.run(["tshark", "--version"],
            capture_output=True, text=True, timeout=5)
        return True
    except FileNotFoundError:
        return False


async def capture_live(
    interface: str = DEFAULT_INTERFACE,
    bpf_filter: str = CAPTURE_FILTER,
) -> AsyncGenerator[dict, None]:
    cmd = [
        "tshark", "-i", interface,
        "-T", "ek", "-l", "-n",
    ]
    if bpf_filter:
        cmd += ["-f", bpf_filter]

    process = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    try:
        while True:
            try:
                raw = await asyncio.wait_for(
                    process.stdout.readline(), timeout=5.0
                )
            except asyncio.TimeoutError:
                await asyncio.sleep(0.1)
                continue

            if not raw:
                break

            line = raw.decode("utf-8", errors="replace").strip()
            if not line or '"layers"' not in line:
                continue

            try:
                obj    = json.loads(line)
                layers = obj.get("layers", {})
                if not layers:
                    continue
                pkt = _parse(layers)
                if pkt.get("src_ip"):
                    yield pkt
            except json.JSONDecodeError:
                continue

    except asyncio.CancelledError:
        pass
    finally:
        try:
            process.terminate()
            await process.wait()
        except Exception:
            pass


async def capture_from_pcap(pcap_file: str) -> AsyncGenerator[dict, None]:
    cmd = ["tshark", "-r", pcap_file, "-T", "ek"]
    process = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        async for raw in process.stdout:
            line = raw.decode("utf-8", errors="replace").strip()
            if not line or '"layers"' not in line:
                continue
            try:
                obj = json.loads(line)
                layers = obj.get("layers", {})
                if layers:
                    pkt = _parse(layers)
                    if pkt.get("src_ip"):
                        yield pkt
            except json.JSONDecodeError:
                continue
    finally:
        try:
            process.terminate()
        except Exception:
            pass


def _parse(layers: dict) -> dict:
    """
    EK format: each protocol is a nested dict inside layers.
    layers["ip"]["ip_ip_src"] = "10.0.2.15"
    layers["tcp"]["tcp_tcp_srcport"] = "12345"
    layers["frame"]["frame_frame_len"] = "98"
    """
    ip    = layers.get("ip",    {})
    tcp   = layers.get("tcp",   {})
    udp   = layers.get("udp",   {})
    dns   = layers.get("dns",   {})
    http  = layers.get("http",  {})
    arp   = layers.get("arp",   {})
    icmp  = layers.get("icmp",  {})
    frame = layers.get("frame", {})

    def g(d, *keys):
        """Try multiple key names, return first match."""
        for k in keys:
            v = d.get(k)
            if v is not None:
                if isinstance(v, list):
                    v = v[0] if v else None
                if v is not None:
                    return v
        return None

    src_ip = g(ip, "ip_ip_src")
    dst_ip = g(ip, "ip_ip_dst")
    proto  = g(ip, "ip_ip_proto")

    tcp_src = g(tcp, "tcp_tcp_srcport")
    tcp_dst = g(tcp, "tcp_tcp_dstport")
    udp_src = g(udp, "udp_udp_srcport")
    udp_dst = g(udp, "udp_udp_dstport")

    syn = g(tcp, "tcp_tcp_flags_syn")
    ack = g(tcp, "tcp_tcp_flags_ack")
    rst = g(tcp, "tcp_tcp_flags_reset")

    dns_query   = g(dns,  "dns_dns_qry_name")
    http_method = g(http, "http_http_request_method")
    http_host   = g(http, "http_http_host")
    arp_opcode  = g(arp,  "arp_arp_opcode")
    icmp_type   = g(icmp, "icmp_icmp_type")

    frame_len = g(frame, "frame_frame_len")
    timestamp = g(frame, "frame_frame_time_epoch")

    return {
        "timestamp":   timestamp,
        "length":      _int(frame_len),
        "src_ip":      src_ip,
        "dst_ip":      dst_ip,
        "protocol":    _proto(proto),
        "src_port":    _int(tcp_src or udp_src),
        "dst_port":    _int(tcp_dst or udp_dst),
        "tcp_flags":   g(tcp, "tcp_tcp_flags"),
        "syn":         syn is True  or syn == "1"  or syn == True,
        "ack":         ack is True  or ack == "1"  or ack == True,
        "rst":         rst is True  or rst == "1"  or rst == True,
        "dns_query":   dns_query,
        "http_method": http_method,
        "http_host":   http_host,
        "arp_opcode":  arp_opcode,
        "icmp_type":   icmp_type,
    }


def _int(val) -> Optional[int]:
    try:
        return int(val)
    except (TypeError, ValueError):
        return None


def _proto(num) -> str:
    mapping = {"1": "ICMP", "6": "TCP", "17": "UDP",
               "47": "GRE", "50": "ESP"}
    return mapping.get(str(num), f"PROTO_{num}") if num else "UNKNOWN"
