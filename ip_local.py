#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Cloudflare IP 简易优选（单文件，仅用 Python 标准库）
在手机 Termux 里跑：python ip.py
输出：当前网络下最优的 CF 节点（IP:端口#国家 [速度M]）
"""
import concurrent.futures as cf
import json
import re
import socket
import ssl
import sys
import time
import urllib.request
from collections import defaultdict

# ── 配置 ──
SOURCES = [
    "https://zip.cm.edu.kg/all.txt",
    "https://countrymerge.pages.dev/all.txt",
]
TCP_TIMEOUT = 2.0
TCP_WORKERS = 200
TCP_TOP = 60           # 进测速的候选数
SPEED_WORKERS = 6
SPEED_SECONDS = 4.0    # 每个节点测速时长
MIN_MBPS = 1.0         # 低于此速度不算合格
TOP_N = 15

UA = "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 Chrome/120 Mobile Safari/537.36"

# 复用 SSL context
CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE


def log(msg):
    print(msg, flush=True)


# ── 1. 拉取候选 IP ──
def fetch_source(url, retries=2):
    for i in range(retries + 1):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA})
            with urllib.request.urlopen(req, timeout=15) as r:
                return r.read().decode("utf-8", "ignore")
        except Exception as e:
            if i == retries:
                log(f"  ✗ {url} 失败: {e}")
            else:
                time.sleep(2)
    return ""


def parse_nodes(text):
    """解析 IP:端口#国家 格式"""
    out = []
    for line in text.splitlines():
        line = line.strip()
        m = re.match(r"^(\d+\.\d+\.\d+\.\d+):(\d+)#(\S+)", line)
        if m:
            out.append((m.group(1), int(m.group(2)), m.group(3)))
    return out


def collect():
    log("=" * 60)
    log("步骤 1/3：拉取候选 IP")
    log("=" * 60)
    seen = set()
    nodes = []
    for url in SOURCES:
        log(f"  请求 {url} ...")
        text = fetch_source(url)
        if not text:
            continue
        got = parse_nodes(text)
        log(f"    解析出 {len(got)} 个节点")
        for ip, port, cc in got:
            key = f"{ip}:{port}"
            if key in seen:
                continue
            seen.add(key)
            nodes.append((ip, port, cc))
    log(f"  合并去重后：{len(nodes)} 个节点")
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
    log("步骤 2/3：TCP 延迟测试")
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
            if done % 500 == 0 or done == total:
                log(f"  进度 {done}/{total}，通过 {len(results)}")
    results.sort(key=lambda x: x[3])
    log(f"  TCP 通过 {len(results)} 个，取延迟最低的 {min(TCP_TOP, len(results))} 个进测速")
    return results[:TCP_TOP]


# ── 3. HTTPS 下载测速 ──
def speed_test(item):
    """经该 IP 下载 Cloudflare 测速文件，返回 Mbps"""
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
        body_start = 0
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
                body_start = idx + 4
                total_bytes = len(buf) - body_start
                t_start = time.time()
                # 检查状态码
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

        if not t_start or total_bytes < 262144:  # 至少 256KB
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
    log(f"步骤 3/3：HTTPS 下载测速（每个测 {SPEED_SECONDS} 秒）")
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
            log(f"  进度 {done}/{total}，有效 {len(results)}")
    results.sort(key=lambda x: -x[4])
    return results


# ── 4. 输出 ──
def main():
    t0 = time.time()
    nodes = collect()
    if not nodes:
        log("没有拿到任何节点，检查网络后重试")
        sys.exit(1)

    tcp_ok = tcp_filter(nodes)
    if not tcp_ok:
        log("TCP 全部失败，检查网络")
        sys.exit(1)

    speeds = speed_filter(tcp_ok)

    log("")
    log("=" * 60)
    log("最终结果")
    log("=" * 60)

    good = [r for r in speeds if r[4] >= MIN_MBPS]
    if not good:
        log(f"⚠ 没有节点达到 {MIN_MBPS} Mbps，下面是实测值：")
        good = speeds[:TOP_N]
    else:
        good = good[:TOP_N]

    if not good:
        log("没有任何可用节点")
        sys.exit(1)

    lines = []
    for i, (ip, port, cc, ping, mbps) in enumerate(good, 1):
        line = f"{ip}:{port}#{cc} [{int(round(mbps))}M]"
        lines.append(line)
        log(f"{i:2d}. {line}   延迟 {ping:.0f}ms")

    log("")
    log("=" * 60)
    log("复制下面这段（可直接粘到 EdgeTunnel / Clash）")
    log("=" * 60)
    for line in lines:
        print(line)

    # 同时存文件
    try:
        with open("ip.txt", "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
        log(f"\n已保存到当前目录 ip.txt（共 {len(lines)} 个节点）")
    except Exception as e:
        log(f"\n保存失败: {e}")

    log(f"\n总耗时 {time.time() - t0:.1f} 秒")


if __name__ == "__main__":
    main()
