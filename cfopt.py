#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Cloudflare IP 优选（备用机同款逻辑 + 改进，纯标准库）
用法：python3 cfopt.py
输出：IP:端口#地区 [速度M]  （同时存 ip.txt）

流程（与备用机 cfnb 一致）：
  ① 拉数据源 + CF 官方段校验（剔除假 IP）
  ② TCP 延迟测试（并发，成功率 100%）
  ③ 机房探测 + 机房轮转取样（避免单一机房垄断）
  ④ 可用性二次检测（HTTPS 握手，等价 cfnb 的 HTTP 检测但更准）
  ⑤ 带宽测速（多线程，按速度排序）
  ⑥ 机房限速识别（同一机房速度低则降权）
"""
import concurrent.futures as cf
import ipaddress
import re
import socket
import ssl
import sys
import time
import urllib.request
from collections import defaultdict

# ══════════════ 配置（对应备用机 config.json）══════════════
SOURCES = [
    "https://zip.cm.edu.kg/all.txt",
    "https://countrymerge.pages.dev/all.txt",
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

GLOBAL_TOP_N = 15          # 最终保留节点数
TCP_PROBES = 2             # 每节点 TCP 测试次数
MIN_SUCCESS_RATE = 1.0     # TCP 成功率要求
TCP_TIMEOUT = 2.0
TCP_WORKERS = 300
BANDWIDTH_CANDIDATES = 200 # 进测速的候选数
BANDWIDTH_WORKERS = 10
BANDWIDTH_SIZE_MB = 2      # 测速下载大小
BANDWIDTH_TIMEOUT = 15
MIN_MBPS = 1.0             # 合格阈值
BLOCK_COUNTRIES = ["CN"]   # 排除的国家
PRE_FILTER_PORTS = [443, 8443, 2053, 2083, 2087, 2096]
# 机房轮转：每机房最多占多少名额
COLO_EXPLORE = 2           # 限速机房保留的探索名额
THROTTLE_MIN_MBPS = 1.0

UA = "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 Chrome/120 Mobile Safari/537.36"

CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE


def log(msg=""):
    print(msg, flush=True)


# ══════════════ ① 数据收集 + CF 段校验 ══════════════
def load_cf_ranges():
    text = ""
    try:
        req = urllib.request.Request(CF_RANGES_URL, headers={"User-Agent": UA})
        with urllib.request.urlopen(req, timeout=15) as r:
            text = r.read().decode("utf-8", "ignore")
        log(f"  CF 段表：已拉取（{len([l for l in text.splitlines() if l.strip()])} 段）")
    except Exception as e:
        log(f"  CF 段表拉取失败（{e}），用内置 15 段")
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


def fetch_source(url, retries=2):
    for i in range(retries + 1):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA})
            with urllib.request.urlopen(req, timeout=20) as r:
                return r.read().decode("utf-8", "ignore")
        except Exception as e:
            if i == retries:
                log(f"  ✗ {url}：{e}")
            else:
                time.sleep(2)
    return ""


def parse_nodes(text):
    out = []
    for line in text.splitlines():
        line = line.strip()
        # IP:端口#国家
        m = re.match(r"^(\d+\.\d+\.\d+\.\d+):(\d+)#(\S+)", line)
        if m:
            out.append((m.group(1), int(m.group(2)), m.group(3)))
            continue
        # 纯 IP
        m2 = re.match(r"^(\d+\.\d+\.\d+\.\d+)$", line)
        if m2:
            out.append((m2.group(1), 443, "??"))
    return out


def collect():
    log("=" * 64)
    log("① 收集候选节点")
    log("=" * 64)
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
            if port not in PRE_FILTER_PORTS:
                continue
            nodes.append((ip, port, cc))
            kept += 1
        log(f"    解析 {len(got)}，有效 {kept}")

    # 采样补充（数据源可能失效时兜底）
    if len(nodes) < 500:
        sample_n = 2000 - len(nodes)
        log(f"  候选偏少，从 CF 官方段补充采样 {sample_n} 个 ...")
        import random
        big = [n for n in nets if n.num_addresses > 4096]
        for _ in range(sample_n):
            net = random.choice(big)
            ip = str(net.network_address + random.randrange(1, net.num_addresses - 1))
            key = f"{ip}:443"
            if key in seen:
                continue
            seen.add(key)
            nodes.append((ip, 443, "??"))

    log(f"  候选合计：{len(nodes)} 个（剔除非 CF {non_cf} 个）")
    return nodes


# ══════════════ ② TCP 延迟测试 ══════════════
def tcp_test(item):
    ip, port, cc = item
    ok = 0
    lats = []
    for _ in range(TCP_PROBES):
        try:
            t0 = time.time()
            s = socket.create_connection((ip, port), timeout=TCP_TIMEOUT)
            s.close()
            lats.append((time.time() - t0) * 1000)
            ok += 1
        except Exception:
            pass
    if TCP_PROBES == 0:
        return None
    rate = ok / TCP_PROBES
    if rate < MIN_SUCCESS_RATE or not lats:
        return None
    return (ip, port, cc, sum(lats) / len(lats), rate)


def tcp_phase(nodes):
    log("")
    log("=" * 64)
    log(f"② TCP 延迟测试（{len(nodes)} 个，每节点 {TCP_PROBES} 次）")
    log("=" * 64)
    results = []
    done = 0
    total = len(nodes)
    with cf.ThreadPoolExecutor(max_workers=TCP_WORKERS) as ex:
        futs = {ex.submit(tcp_test, n): n for n in nodes}
        for f in cf.as_completed(futs):
            done += 1
            r = f.result()
            if r:
                results.append(r)
            if done % 1000 == 0 or done == total:
                log(f"  进度 {done}/{total}，通过 {len(results)}")
    results.sort(key=lambda x: x[3])
    log(f"  TCP 通过 {len(results)} 个")
    return results


# ══════════════ ③ 机房探测 + 轮转取样 ══════════════
def colo_probe(item, timeout=3.0):
    ip, port, cc, lat, rate = item
    try:
        sock = socket.create_connection((ip, port), timeout=timeout)
        ss = CTX.wrap_socket(sock, server_hostname="cloudflare.com")
        ss.settimeout(timeout)
        ss.sendall(b"GET /cdn-cgi/trace HTTP/1.1\r\nHost: cloudflare.com\r\nConnection: close\r\n\r\n")
        buf = b""
        while len(buf) < 4096:
            chunk = ss.recv(1024)
            if not chunk:
                break
            buf += chunk
            m = re.search(rb"colo=([A-Z]{3})", buf)
            if m:
                ss.close()
                return (item, m.group(1).decode())
        ss.close()
    except Exception:
        pass
    return (item, None)


def pick_by_colo(items, colo_map, limit, throttled):
    buckets = defaultdict(list)
    for it in items:
        c = colo_map.get(it[0]) or "UNK"
        buckets[c].append(it)
    lists = []
    for c, xs in buckets.items():
        cap = COLO_EXPLORE if c in throttled else len(xs)
        lists.append({"c": c, "xs": xs, "i": 0, "cap": cap})
    lists.sort(key=lambda l: -len(l["xs"]))
    out = []
    while len(out) < limit and any(l["i"] < len(l["xs"]) and l["i"] < l["cap"] for l in lists):
        for l in lists:
            if len(out) >= limit:
                break
            if l["i"] < len(l["xs"]) and l["i"] < l["cap"]:
                out.append(l["xs"][l["i"]])
                l["i"] += 1
    stat = {l["c"]: len(l["xs"]) for l in lists}
    return out, stat


def colo_phase(tcp_ok):
    log("")
    log("=" * 64)
    log("③ 机房探测 + 轮转取样")
    log("=" * 64)
    probe_list = tcp_ok[:max(BANDWIDTH_CANDIDATES * 2, 400)]
    log(f"  探测 {len(probe_list)} 个节点的入口机房 ...")
    colo_map = {}
    with cf.ThreadPoolExecutor(max_workers=40) as ex:
        for item, colo in ex.map(colo_probe, probe_list):
            if colo:
                colo_map[item[0]] = colo
    known = len(colo_map)
    log(f"  拿到 {known}/{len(probe_list)} 个机房信息")

    stat = defaultdict(int)
    for v in colo_map.values():
        stat[v] += 1
    if stat:
        log("  机房分布：" + " ".join(f"{c}:{n}" for c, n in sorted(stat.items(), key=lambda x: -x[1])))

    picked, allstat = pick_by_colo(probe_list, colo_map, BANDWIDTH_CANDIDATES, set())
    log(f"  轮转后 {len(picked)} 个进测速（各机房均分名额）")
    return picked, colo_map


# ══════════════ ④ 可用性检测（HTTPS 握手）══════════════
def avail_check(item, timeout=4.0):
    ip, port, cc, lat, rate = item
    try:
        sock = socket.create_connection((ip, port), timeout=timeout)
        ss = CTX.wrap_socket(sock, server_hostname="www.cloudflare.com")
        ss.settimeout(timeout)
        ss.sendall(b"GET /cdn-cgi/trace HTTP/1.1\r\nHost: www.cloudflare.com\r\nConnection: close\r\n\r\n")
        buf = b""
        while len(buf) < 4096:
            chunk = ss.recv(1024)
            if not chunk:
                break
            buf += chunk
        ss.close()
        text = buf.decode("latin1", "ignore")
        m = re.match(r"HTTP/1\.\d (\d+)", text)
        status = int(m.group(1)) if m else 0
        if status not in (200, 400, 403):
            return None
        if "colo=" not in text:
            return None
        return item
    except Exception:
        return None


def avail_phase(items):
    log("")
    log("=" * 64)
    log(f"④ 可用性检测（HTTPS 握手，{len(items)} 个）")
    log("=" * 64)
    ok = []
    with cf.ThreadPoolExecutor(max_workers=50) as ex:
        for r in ex.map(avail_check, items):
            if r:
                ok.append(r)
    log(f"  通过 {len(ok)}/{len(items)}")
    return ok


# ══════════════ ⑤ 带宽测速 ══════════════
def speed_test(item):
    ip, port, cc, lat, rate = item
    try:
        sock = socket.create_connection((ip, port), timeout=5)
        ss = CTX.wrap_socket(sock, server_hostname="speed.cloudflare.com")
        ss.settimeout(BANDWIDTH_TIMEOUT)
        nbytes = BANDWIDTH_SIZE_MB * 1024 * 1024
        req = (
            f"GET /__down?bytes={nbytes} HTTP/1.1\r\n"
            "Host: speed.cloudflare.com\r\n"
            f"User-Agent: {UA}\r\n"
            "Accept: */*\r\n"
            "Connection: close\r\n\r\n"
        )
        ss.sendall(req.encode())

        buf = b""
        header_done = False
        t_start = None
        total = 0
        colo = ""
        deadline = time.time() + BANDWIDTH_TIMEOUT

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
                total = len(buf) - idx - 4
                t_start = time.time()
                head = buf[:idx].decode("latin1", "ignore")
                if " 200 " not in head.split("\r\n")[0]:
                    ss.close()
                    return None
                m = re.search(r"(?i)cf-ray:\s*[0-9a-f]+-([A-Za-z]{3})", head)
                if m:
                    colo = m.group(1).upper()
            else:
                total += len(chunk)

        try:
            ss.close()
        except Exception:
            pass

        if not t_start or total < 65536:
            return None
        dur = time.time() - t_start
        if dur <= 0.2:
            return None
        mbps = (total * 8) / (dur * 1000 * 1000)
        return (ip, port, colo or cc, lat, round(mbps, 2))
    except Exception:
        return None


def speed_phase(items):
    log("")
    log("=" * 64)
    log(f"⑤ 带宽测速（{len(items)} 个，{BANDWIDTH_SIZE_MB}MB / {BANDWIDTH_TIMEOUT}s，并发 {BANDWIDTH_WORKERS}）")
    log("=" * 64)
    results = []
    done = 0
    total = len(items)
    with cf.ThreadPoolExecutor(max_workers=BANDWIDTH_WORKERS) as ex:
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


# ══════════════ ⑥ 机房限速识别 + 输出 ══════════════
def finalize(speeds):
    log("")
    log("=" * 64)
    log("⑥ 机房限速识别 + 最终排序")
    log("=" * 64)

    # 按机房统计
    per = defaultdict(list)
    for ip, port, colo, lat, mbps in speeds:
        per[colo].append(mbps)
    throttled = set()
    for c, sp in per.items():
        med = sorted(sp)[len(sp) // 2]
        if med < THROTTLE_MIN_MBPS:
            throttled.add(c)
        log(f"  机房 {c}: {len(sp)} 个节点，中位速度 {med:.1f} Mbps" + ("  ⚠限速" if med < THROTTLE_MIN_MBPS else ""))

    # 限速机房降权（速度打 0.5 折再排序）
    def score(r):
        mbps = r[4] * (0.5 if r[2] in throttled else 1.0)
        return -mbps

    good = [r for r in speeds if r[4] >= MIN_MBPS]
    if not good:
        log(f"  ⚠ 无节点达到 {MIN_MBPS} Mbps，列出实测值")
        good = speeds[:GLOBAL_TOP_N]
    good.sort(key=score)
    good = good[:GLOBAL_TOP_N]

    if not good:
        return []

    log("")
    log("=" * 64)
    log("最终优选结果")
    log("=" * 64)
    lines = []
    for i, (ip, port, colo, lat, mbps) in enumerate(good, 1):
        line = f"{ip}:{port}#{colo} [{int(round(mbps))}M]"
        lines.append(line)
        flag = " ⚠限速机房" if colo in throttled else ""
        log(f"{i:2d}. {line:<32} 延迟 {lat:.0f}ms{flag}")
    return lines


def main():
    t0 = time.time()
    log("CF IP 优选（备用机同款逻辑）")
    log("")

    nodes = collect()
    if not nodes:
        log("无候选节点")
        sys.exit(1)

    tcp_ok = tcp_phase(nodes)
    if not tcp_ok:
        log("TCP 全部失败")
        sys.exit(1)

    picked, colo_map = colo_phase(tcp_ok)
    if not picked:
        log("无轮转结果")
        sys.exit(1)

    avail = avail_phase(picked)
    if not avail:
        log("可用性检测全失败")
        sys.exit(1)

    speeds = speed_phase(avail)
    if not speeds:
        log("测速无有效结果")
        sys.exit(1)

    lines = finalize(speeds)
    if not lines:
        sys.exit(1)

    log("")
    log("=" * 64)
    log("复制下面这段（粘到 EdgeTunnel / Clash）")
    log("=" * 64)
    for line in lines:
        print(line)

    try:
        with open("ip.txt", "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
        log(f"\n已保存 ip.txt（{len(lines)} 个节点）")
    except Exception as e:
        log(f"\n保存失败：{e}")

    log(f"总耗时 {time.time() - t0:.1f} 秒")


if __name__ == "__main__":
    main()
