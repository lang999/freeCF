#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""cn_proxy_hunter.py — 大陆出口代理自动发现/验证

背景:
  免费大陆出口代理寿命通常只有几小时~几天, 手动维护没意义。
  本脚本一键完成: 抓公开源 → 测活 → 验证"真大陆出口"→ 输出可用列表。

判定"真大陆出口"的三关 (缺一不可):
  1) 控制组: 223.5.5.5:443 / www.baidu.com:443 必须通   (代理在干活)
  2) 反证组: www.google.com:443 / 8.8.8.8:443 必须不通 (出口确实在大陆, 没走海外中转)
  3) 触达组: 至少能连上一个 CF IP:443                  (对我们有用)

用法:
  python3 cn_proxy_hunter.py                    # 全流程, 输出代理列表
  python3 cn_proxy_hunter.py --out cn_proxies.json
  python3 cn_proxy_hunter.py --test-only 1.2.3.4:1080   # 只验证指定代理
  python3 cn_proxy_hunter.py --ci               # CI 模式: 把可用出口写进 $GITHUB_ENV

CI 模式行为 (供 GitHub Actions 使用):
  - 找到可用大陆出口 → 写 CN_PROXY=socks5://a,http://b,... (最多 5 个, 供 main_v3 轮换)
  - 一个都没找到     → 写 CN_FILTER=off (显式关闭过滤层, 避免无谓等待)
  - 任何异常都不让 job 失败 (永远 exit 0)
"""

import argparse
import json
import os
import re
import socket
import struct
import sys
import time
import urllib.request
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124.0"}

SOURCES = [
    "https://www.89ip.cn/tqdl.html?api=1&num=500",
    "https://www.89ip.cn/tqdl.html?api=1&num=500&page=2",
    "http://www.ip3366.net/free/?stype=1&page=1",
    "http://www.ip3366.net/free/?stype=3&page=1",
    "https://www.kuaidaili.com/free/inha/1/",
    "https://www.kuaidaili.com/free/intr/1/",
    "https://api.proxyscrape.com/v4/free-proxy-list/get?request=display_proxies&protocol=socks5&country=cn&proxy_format=ipport&format=text",
    "https://api.proxyscrape.com/v4/free-proxy-list/get?request=display_proxies&protocol=http&country=cn&proxy_format=ipport&format=text",
    "https://www.proxy-list.download/api/v1/get?type=socks5&country=CN",
    "https://www.proxy-list.download/api/v1/get?type=http&country=CN",
]

CTRL_REACH = [("223.5.5.5", 443), ("www.baidu.com", 443)]
CTRL_FAIL = [("www.google.com", 443), ("8.8.8.8", 443)]
CF_TARGETS = [("104.17.108.76", 443), ("104.18.33.250", 443), ("162.159.192.1", 443)]

TIMEOUT = 5.0
VERIFY_TIMEOUT = 8.0


def fetch_sources():
    pools = {}
    for url in SOURCES:
        for attempt in range(2):
            try:
                html = urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=25).read().decode("utf-8", "replace")
                found = set(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}:\d{2,5}\b", html))
                if not found:  # 表格分列
                    ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", html)
                    ports = re.findall(r">\s*(\d{2,5})\s*<", html)
                    for ip in ips[:200]:
                        for pt in ports[:4]:
                            found.add(ip + ":" + pt)
                host = url.split("/")[2]
                pools[host] = pools.get(host, set()) | found
                print("    %-46s %d" % (url[:46], len(found)))
                break
            except Exception as e:
                if attempt:
                    print("    %-46s FAIL %s" % (url[:46], str(e)[:40]))
    allp = set()
    for v in pools.values():
        allp |= v
    return allp


def _socks5(addr, host, port, timeout):
    h, _, p = addr.rpartition(":")
    s = socket.create_connection((h, int(p)), timeout=timeout)
    s.settimeout(timeout)
    s.sendall(b"\x05\x01\x00")
    r = s.recv(2)
    if len(r) < 2 or r[0] != 5 or r[1] == 0xFF:
        s.close(); return None
    hb = host.encode()
    s.sendall(b"\x05\x01\x00\x03" + bytes([len(hb)]) + hb + struct.pack("!H", port))
    if s.recv(10)[1] != 0:
        s.close(); return None
    return s


def _http(addr, host, port, timeout):
    h, _, p = addr.rpartition(":")
    s = socket.create_connection((h, int(p)), timeout=timeout)
    s.settimeout(timeout)
    s.sendall(("CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\n\r\n" % (host, port, host, port)).encode())
    resp = s.recv(200)
    if b" 200 " in resp.split(b"\r\n", 1)[0] or resp.startswith(b"HTTP/1.0 200"):
        return s
    s.close(); return None


def connect(addr, host, port, timeout=TIMEOUT, proto=None):
    fns = [("socks5", _socks5), ("http", _http)]
    if proto:
        fns = [f for f in fns if f[0] == proto]
    for name, fn in fns:
        try:
            s = fn(addr, host, port, timeout)
            if s:
                return s, name
        except Exception:
            pass
    return None, None


def liveness(addr):
    t0 = time.time()
    for host, port in [("223.5.5.5", 443), ("www.baidu.com", 80)]:
        s, proto = connect(addr, host, port)
        if s:
            s.close()
            return addr, True, proto, round((time.time() - t0) * 1000)
    return addr, False, None, 0


def verify(addr, proto):
    """三关验证 + 出口归属"""
    reach = 0
    for h, p in CTRL_REACH:
        s, _ = connect(addr, h, p, VERIFY_TIMEOUT, proto)
        if s:
            s.close(); reach += 1
    if reach == 0:
        return None
    leak = 0
    for h, p in CTRL_FAIL:
        s, _ = connect(addr, h, p, VERIFY_TIMEOUT, proto)
        if s:
            s.close(); leak += 1
    cf = 0
    for h, p in CF_TARGETS:
        s, _ = connect(addr, h, p, VERIFY_TIMEOUT, proto)
        if s:
            s.close(); cf += 1
    egress = {}
    try:
        s, _ = connect(addr, "ip-api.com", 80, VERIFY_TIMEOUT, proto)
        if s:
            s.sendall(b"GET /json/?fields=status,country,countryCode,isp,as,query HTTP/1.1\r\nHost: ip-api.com\r\nUser-Agent: c\r\nConnection: close\r\n\r\n")
            buf = b""
            while len(buf) < 8192:
                d = s.recv(2048)
                if not d:
                    break
                buf += d
            s.close()
            egress = json.loads(buf.split(b"\r\n\r\n", 1)[-1].decode("utf-8", "replace"))
    except Exception:
        pass
    return {"addr": addr, "proto": proto, "ctrl_reach": reach, "ctrl_leak": leak,
            "cf_reach": cf, "egress_ip": egress.get("query", ""),
            "country": egress.get("country", ""), "isp": egress.get("isp", ""),
            "is_cn": reach >= 1 and leak == 0}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="cn_proxies.json")
    ap.add_argument("--workers", type=int, default=96)
    ap.add_argument("--test-only", help="只验证指定 ip:port (逗号分隔)")
    ap.add_argument("--full", action="store_true", help="输出全部可用(含海外出口)")
    ap.add_argument("--ci", action="store_true", help="CI 模式: 把可用出口写进 $GITHUB_ENV, 永不失败")
    ap.add_argument("--max-exits", type=int, default=5, help="CI 模式下最多写入几个出口供轮换")
    args = ap.parse_args()



    if args.test_only:
        cands = [x.strip() for x in args.test_only.split(",") if x.strip()]
        print("[*] 只验证 %d 个指定代理" % len(cands))
        with ThreadPoolExecutor(max_workers=8) as ex:
            rows = [r for r in ex.map(lambda a: verify(a, None), cands) if r]
        for r in rows:
            print(json.dumps(r, ensure_ascii=False))
        return

    print("[*] 第 1 步: 抓取公开代理源")
    pool = fetch_sources()
    print("[+] 去重候选: %d 个" % len(pool))
    if not pool:
        print("[x] 没抓到任何候选, 退出")
        if args.ci:
            print("[!] CI: 写 CN_FILTER=off")
            p = os.environ.get("GITHUB_ENV")
            if p:
                with open(p, "a", encoding="utf-8") as f:
                    f.write("CN_FILTER=off\n")
        sys.exit(1)

    print("[*] 第 2 步: 测活 (并发 %d, 超时 %.0fs)" % (args.workers, TIMEOUT))
    pool = sorted(pool)
    alive, t0 = [], time.time()
    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        for i, (addr, ok, proto, ms) in enumerate(ex.map(liveness, pool), 1):
            if ok:
                alive.append((addr, proto, ms))
            if i % 200 == 0:
                print("    进度 %d/%d, 疑似可用 %d" % (i, len(pool), len(alive)), flush=True)
    print("[+] 测活: %d 个疑似可用 (%.1f%%, %.0fs)" % (
        len(alive), 100.0 * len(alive) / max(1, len(pool)), time.time() - t0))
    if not alive:
        print("[x] 无可用代理")
        if args.ci:
            print("[!] CI: 写 CN_FILTER=off")
            p = os.environ.get("GITHUB_ENV")
            if p:
                with open(p, "a", encoding="utf-8") as f:
                    f.write("CN_FILTER=off\n")
        sys.exit(2)

    print("[*] 第 3 步: 三关验证 (控制组/反证组/CF 触达)")
    results = []
    with ThreadPoolExecutor(max_workers=24) as ex:
        futs = [ex.submit(verify, a, p) for a, p, _ in alive]
        for i, f in enumerate(futs, 1):
            r = f.result()
            if r:
                results.append(r)
            if i % 20 == 0:
                print("    验证 %d/%d" % (i, len(alive)), flush=True)

    ok = [r for r in results if r["is_cn"] and r["cf_reach"] > 0]
    print("\n===== 结果 =====")
    print("候选 %d → 疑似可用 %d → 真大陆出口(且能连 CF) %d" % (len(pool), len(alive), len(ok)))
    print("出口地区分布:", dict(Counter(r["country"] or "?" for r in results).most_common(8)))
    print("\n★ 可用大陆出口:")
    for r in ok:
        print("  %-22s %-7s CF %d/%d  %s %s" % (
            r["addr"], r["proto"], r["cf_reach"], len(CF_TARGETS), r["country"], r["isp"][:30]))
    if not ok:
        print("  (无 — 免费源此刻没有可用的大陆出口代理)")

    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "scanned": len(pool), "alive": len(alive),
        "cn_exits": ok if not args.full else [r for r in results if r["is_cn"]],
        "all_alive": results if args.full else [],
    }
    outdir = os.path.dirname(os.path.abspath(args.out))
    os.makedirs(outdir, exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
    print("\n[+] 已写出 %s" % args.out)
    if ok:
        print("[+] 可直接用于 main_v3.py:")
        print("    CN_PROXY=%s://%s python3 main_v3.py" % (ok[0]["proto"], ok[0]["addr"]))

    # ── CI 模式: 把可用出口写进 $GITHUB_ENV, 供后续步骤的 main_v3.py 使用 ──
    if args.ci:
        if ok:
            proxies = ",".join("%s://%s" % (r["proto"], r["addr"]) for r in ok[:args.max_exits])
            line = "CN_PROXY=" + proxies + "\n"
            print("[+] CI: 写入 %d 个出口供轮换" % min(len(ok), args.max_exits))
        else:
            line = "CN_FILTER=off\n"
            print("[!] CI: 未找到可用大陆出口 → 写 CN_FILTER=off (跳过过滤层)")
        env_path = os.environ.get("GITHUB_ENV")
        if env_path:
            with open(env_path, "a", encoding="utf-8") as f:
                f.write(line)
            print("[+] CI: 已写入 $GITHUB_ENV")
        else:
            print("[!] CI: 未找到 $GITHUB_ENV (本地运行?), 请手动 export:")
            print("    " + line.strip())


if __name__ == "__main__":
    if "--ci" in sys.argv:
        # CI 模式: 任何失败都不让 job 挂掉 (拿不到代理 = 过滤层自动关闭, 不影响主流程)
        try:
            main()
        except SystemExit:
            pass
        except BaseException as e:
            print("[!] CI 模式异常 (已吞掉, 不影响 job): %r" % (e,))
    else:
        main()
