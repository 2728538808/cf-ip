#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Cloudflare IP 优选 v4（纯标准库）
策略：CF 官方段随机采样 + 数据源合并，全部经段表校验
在手机 Termux 运行：python ip.py
"""
import concurrent.futures as cf
import ipaddress
import random
import re
import socket
import ssl
import sys
import time
import urllib.request

# ── 配置 ──
SOURCES = [
    "https://countrymerge.pages.dev/all.txt",
    "https://zip.cm.edu.kg/all.txt",
]
CF_RANGES_URL = "https://www.cloudflare.com/ips-v4"
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

# 随机采样点数（每个采样点再测，避免全段盲扫）
SAMPLE_COUNT = 3000
# 数据源 + 采样合并后的 TCP 测试上限
TCP_TEST_MAX = 3500
TCP_TIMEOUT = 1.5
TCP_WORKERS = 400
TCP_TOP = 250
SPEED_WORKERS = 12
SPEED_SECONDS = 3.0
MIN_BYTES = 65536
MIN_MBPS = 1.0
TOP_N = 15

UA = "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 Chrome/120 Mobile Safari/537.36"

CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE


def log(msg):
    print(msg, flush=True)


def load_cf_ranges():
    text = ""
    try:
        req = urllib.request.Request(CF_RANGES_URL, headers={"User-Agent": UA})
        with urllib.request.urlopen(req, timeout=15) as r:
            text = r.read().decode("utf-8", "ignore")
        log(f"  已拉取 CF 官方段表（{len([l for l in text.splitlines() if l.strip()])} 段）")
    except Exception as e:
        log(f"  ⚠ 段表拉取失败（{e}），用内置")
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


def fetch_source(url, retries=1):
    for i in range(retries + 1):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA})
            with urllib.request.urlopen(req, timeout=20) as r:
                return r.read().decode("utf-8", "ignore")
        except Exception as e:
            if i == retries:
                log(f"  ✗ {url}：{e}")
            else:
                time.sleep(1)
    return ""


def parse_nodes(text):
    out = []
    for line in text.splitlines():
        line = line.strip()
        m = re.match(r"^(\d+\.\d+\.\d+\.\d+):(\d+)#(\S+)", line)
        if m:
            out.append((m.group(1), int(m.group(2)), m.group(3)))
        else:
            m2 = re.match(r"^(\d+\.\d+\.\d+\.\d+)$", line)
            if m2:
                out.append((m2.group(1), 443, "??"))
    return out


def random_sample(nets, count):
    """从 CF 官方段随机采样 IP"""
    big = [n for n in nets if n.num_addresses > 256]
    if not big:
        big = nets
    out = []
    for _ in range(count):
        net = random.choice(big)
        # 随机偏移
        offset = random.randrange(1, net.num_addresses - 1)
        out.append(str(net.network_address + offset))
    return out


def collect():
    log("=" * 60)
    log("步骤 1/5：收集候选（段表校验 + 随机采样）")
    log("=" * 60)
    nets = load_cf_ranges()

    seen = set()
    nodes = []

    # ① 数据源
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
            if is_cf(ip, nets):
                nodes.append((ip, port, cc))
                kept += 1
        log(f"    解析 {len(got)} 个，真 CF {kept} 个")

    src_count = len(nodes)

    # ② 官方段随机采样补充
    log(f"  从 CF 官方段随机采样 {SAMPLE_COUNT} 个 IP ...")
    sample_ips = random_sample(nets, SAMPLE_COUNT)
    added = 0
    for ip in sample_ips:
        key = f"{ip}:443"
        if key in seen:
            continue
        seen.add(key)
        nodes.append((ip, 443, "??"))
        added += 1
    log(f"    采样新增 {added} 个")

    log(f"  候选合计：{src_count}（数据源）+ {added}（采样）= {len(nodes)} 个")

    # 控制 TCP 测试量
    if len(nodes) > TCP_TEST_MAX:
        # 优先保留数据源的，再随机补采样
        random.shuffle(nodes)
        nodes = nodes[:TCP_TEST_MAX]
        log(f"  限制到 {TCP_TEST_MAX} 个进 TCP 测试")
    return nodes


def tcp_ping(item):
    ip, port, cc = item
    try:
        t0 = time.time()
        s = socket.create_connection((ip, port), timeout=TCP_TIMEOUT)
        s.close()
        lat = (time.time() - t0) * 1000
        if lat > 800:
            return None
        return (ip, port, cc, lat)
    except Exception:
        return None


def tcp_filter(nodes):
    log("")
    log("=" * 60)
    log(f"步骤 2/5：TCP 延迟测试（{len(nodes)} 个）")
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
    keep = min(TCP_TOP, len(results))
    log(f"  TCP 通过 {len(results)} 个，取最快 {keep} 个进测速")
    return results[:keep]


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
    with cf.ThreadPoolExecutor(max_workers=50) as ex:
        for r in ex.map(tls_check, items):
            if r:
                ok.append(r)
    log(f"  TLS 通过 {len(ok)}/{len(items)} 个")
    return ok


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
        colo = ""
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
                m = re.search(r"(?i)cf-ray:\s*[0-9a-f]+-([A-Za-z]{3})", head)
                if m:
                    colo = m.group(1).upper()
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
        return (ip, port, colo or cc, ping, round(mbps, 2))
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
            if done % 25 == 0 or done == total:
                log(f"  进度 {done}/{total}，有效 {len(results)}")
    results.sort(key=lambda x: -x[4])
    return results


def main():
    t0 = time.time()
    print("CF IP 优选 v4（段表校验 + 随机采样）\n")

    nodes = collect()
    if not nodes:
        log("无候选节点")
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
        log(f"⚠ 无节点达到 {MIN_MBPS} Mbps")
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
        log(f"\n已保存 ip.txt（{len(lines)} 个）")
    except Exception as e:
        log(f"\n保存失败: {e}")

    log(f"\n总耗时 {time.time() - t0:.1f} 秒")


if __name__ == "__main__":
    main()
