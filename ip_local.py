#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Cloudflare IP 优选（单文件，纯标准库）
在手机 Termux 运行：python ip.py
关键：只保留 Cloudflare 官方 IP 段内的地址（过滤数据源里的污染 IP）
"""
import concurrent.futures as cf
import ipaddress
import re
import socket
import ssl
import sys
import time
import urllib.request

# ── 配置 ──
SOURCES = [
    "https://zip.cm.edu.kg/all.txt",
    "https://countrymerge.pages.dev/all.txt",
]
CF_RANGES_URL = "https://www.cloudflare.com/ips-v4"
# 兜底内置段（官方 ips-v4 拉不到时用）
CF_RANGES_FALLBACK = """173.245.48.0/20
103.21.244.0/22
103.22.200.0/22
103.31.4.0/22
141.101.64.0/18
108.162.192.0/18
190.93.240.0/20
188.114.96.0/20
197.234.240.0/22
198.41.128.0/17
162.158.0.0/15
104.16.0.0/13
104.24.0.0/14
172.64.0.0/13
131.0.72.0/22"""

TCP_TIMEOUT = 2.0
TCP_WORKERS = 300
TCP_TOP = 200
SPEED_WORKERS = 10
SPEED_SECONDS = 3.5
MIN_BYTES = 65536
MIN_MBPS = 1.0
TOP_N = 15

UA = "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 Chrome/120 Mobile Safari/537.36"

CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE


def log(msg):
    print(msg, flush=True)


# ── CF 段表 ──
def load_cf_ranges():
    text = ""
    try:
        req = urllib.request.Request(CF_RANGES_URL, headers={"User-Agent": UA})
        with urllib.request.urlopen(req, timeout=15) as r:
            text = r.read().decode("utf-8", "ignore")
        log(f"  已拉取 CF 官方段表（{len(text.splitlines())} 段）")
    except Exception as e:
        log(f"  ⚠ CF 段表拉取失败（{e}），用内置段表")
        text = CF_RANGES_FALLBACK
    nets = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            nets.append(ipaddress.ip_network(line, strict=False))
        except Exception:
            pass
    return nets


def is_cf(ip, nets):
    try:
        a = ipaddress.ip_address(ip)
        return any(a in n for n in nets)
    except Exception:
        return False


# ── 1. 拉取并过滤候选 ──
def fetch_source(url, retries=2):
    for i in range(retries + 1):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA})
            with urllib.request.urlopen(req, timeout=20) as r:
                return r.read().decode("utf-8", "ignore")
        except Exception as e:
            if i == retries:
                log(f"  ✗ {url} 失败: {e}")
            else:
                time.sleep(2)
    return ""


def parse_nodes(text):
    out = []
    for line in text.splitlines():
        line = line.strip()
        m = re.match(r"^(\d+\.\d+\.\d+\.\d+):(\d+)#(\S+)", line)
        if m:
            out.append((m.group(1), int(m.group(2)), m.group(3)))
    return out


def collect():
    log("=" * 60)
    log("步骤 1/5：拉取候选 IP + CF 段表校验")
    log("=" * 60)
    nets = load_cf_ranges()

    seen = set()
    nodes = []
    non_cf = 0
    for url in SOURCES:
        log(f"  请求 {url} ...")
        text = fetch_source(url)
        if not text:
            continue
        got = parse_nodes(text)
        kept = 0
        for ip, port, cc in got:
            key = f"{ip}:{port}"
            if key in seen:
                continue
            seen.add(key)
            if not is_cf(ip, nets):
                non_cf += 1
                continue
            nodes.append((ip, port, cc))
            kept += 1
        log(f"    解析 {len(got)} 个，其中真 CF {kept} 个")
    log(f"  合并去重后：{len(nodes)} 个真 CF 节点（已剔除 {non_cf} 个非 CF）")
    return nodes


# ── 2. TCP 测延迟 ──
def tcp_ping(item):
    ip, port, cc = item
    times = []
    for _ in range(2):
        try:
            t0 = time.time()
            s = socket.create_connection((ip, port), timeout=TCP_TIMEOUT)
            s.close()
            times.append((time.time() - t0) * 1000)
        except Exception:
            return None
    if not times:
        return None
    return (ip, port, cc, sum(times) / len(times))


def tcp_filter(nodes):
    log("")
    log("=" * 60)
    log("步骤 2/5：TCP 延迟测试")
    log("=" * 60)
    results = []
    done = 0
    total = len(nodes)
    with cf.ThreadPoolExecutor(max_workers=TCP_WORKERS) as ex:
        futs = {ex.submit(tcp_ping, n): n for n in nodes}
        for f in cf.as_completed(futs):
            done += 1
            r = f.result()
            if r:
                results.append(r)
            if done % 1000 == 0 or done == total:
                log(f"  进度 {done}/{total}，通过 {len(results)}")
    results.sort(key=lambda x: x[3])
    keep = min(TCP_TOP, len(results))
    log(f"  TCP 通过 {len(results)} 个，取延迟最低的 {keep} 个进测速")
    return results[:keep]


# ── 3. TLS 握手验证 ──
def tls_check(item):
    ip, port, cc, ping = item
    try:
        sock = socket.create_connection((ip, port), timeout=4)
        ss = CTX.wrap_socket(sock, server_hostname="speed.cloudflare.com")
        ss.close()
        return item
    except Exception:
        return None


def tls_filter(items):
    log("")
    log("=" * 60)
    log("步骤 3/5：TLS 握手验证")
    log("=" * 60)
    ok = []
    with cf.ThreadPoolExecutor(max_workers=40) as ex:
        for r in ex.map(tls_check, items):
            if r:
                ok.append(r)
    log(f"  TLS 通过 {len(ok)}/{len(items)} 个")
    return ok


# ── 4. 测速 ──
def speed_test(item):
    ip, port, cc, ping = item
    try:
        sock = socket.create_connection((ip, port), timeout=5)
        ss = CTX.wrap_socket(sock, server_hostname="speed.cloudflare.com")
        ss.settimeout(SPEED_SECONDS + 3)
        req = (
            "GET /__down?bytes=10000000 HTTP/1.1\r\n"
            "Host: speed.cloudflare.com\r\n"
            f"User-Agent: {UA}\r\n"
            "Accept: */*\r\n"
            "Connection: close\r\n\r\n"
        )
        ss.sendall(req.encode())

        buf = b""
        header_done = False
        t_start = None
        total_bytes = 0
        deadline = time.time() + SPEED_SECONDS

        while time.time() < deadline:
            try:
                chunk = ss.recv(65536)
            except socket.timeout:
                break
            if not chunk:
                break
            if not header_done:
                buf += chunk
                idx = buf.find(b"\r\n\r\n")
                if idx < 0:
                    if len(buf) > 65536:
                        break
                    continue
                header_done = True
                total_bytes = len(buf) - idx - 4
                t_start = time.time()
                head = buf[:idx].decode("latin1", "ignore")
                if " 200 " not in head.split("\r\n")[0]:
                    ss.close()
                    return None
            else:
                total_bytes += len(chunk)

        try:
            ss.close()
        except Exception:
            pass

        if not t_start or total_bytes < MIN_BYTES:
            return None
        dur = time.time() - t_start
        if dur <= 0.2:
            return None
        mbps = (total_bytes * 8) / (dur * 1000 * 1000)
        return (ip, port, cc, ping, round(mbps, 2))
    except Exception:
        return None


def speed_filter(items):
    log("")
    log("=" * 60)
    log(f"步骤 4/5：HTTPS 下载测速（每个 {SPEED_SECONDS} 秒）")
    log("=" * 60)
    results = []
    done = 0
    total = len(items)
    with cf.ThreadPoolExecutor(max_workers=SPEED_WORKERS) as ex:
        futs = {ex.submit(speed_test, it): it for it in items}
        for f in cf.as_completed(futs):
            done += 1
            r = f.result()
            if r:
                results.append(r)
            if done % 20 == 0 or done == total:
                log(f"  进度 {done}/{total}，有效 {len(results)}")
    results.sort(key=lambda x: -x[4])
    return results


# ── 5. 输出 ──
def main():
    t0 = time.time()
    print(f"CF IP 优选脚本 v3（含段表校验）\n")

    nodes = collect()
    if not nodes:
        log("没有真 CF 节点，检查网络/数据源")
        sys.exit(1)

    tcp_ok = tcp_filter(nodes)
    if not tcp_ok:
        log("TCP 全部失败")
        sys.exit(1)

    tls_ok = tls_filter(tcp_ok)
    if not tls_ok:
        log("TLS 全部失败")
        sys.exit(1)

    speeds = speed_filter(tls_ok)

    log("")
    log("=" * 60)
    log("步骤 5/5：最终结果")
    log("=" * 60)

    good = [r for r in speeds if r[4] >= MIN_MBPS]
    if not good:
        log(f"⚠ 无节点达到 {MIN_MBPS} Mbps，列出实测值：")
        good = speeds[:TOP_N]
    else:
        good = good[:TOP_N]

    if not good:
        log("无可用节点")
        sys.exit(1)

    lines = []
    for i, (ip, port, cc, ping, mbps) in enumerate(good, 1):
        line = f"{ip}:{port}#{cc} [{int(round(mbps))}M]"
        lines.append(line)
        log(f"{i:2d}. {line}   延迟 {ping:.0f}ms")

    log("")
    log("=" * 60)
    log("复制下面这段")
    log("=" * 60)
    for line in lines:
        print(line)

    try:
        with open("ip.txt", "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
        log(f"\n已保存 ip.txt（{len(lines)} 个节点）")
    except Exception as e:
        log(f"\n保存失败: {e}")

    log(f"\n总耗时 {time.time() - t0:.1f} 秒")


if __name__ == "__main__":
    main()
