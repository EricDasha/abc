#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Steam Toolbox 每日验证码自动更新

原理:
  steam-toolbox 读取 <Steam>/config/info/Verification_code.txt, 内容为两行:
      第一行: 当日验证码 (例如 VDS6VA)
      第二行: KYE1:<64位十六进制签名>
  签名是机器绑定的 HMAC-SHA256:
      key = HMAC-SHA256(b"KYE-vc-bind-v1::SteamToolbox", MachineGuid)
      sig = HMAC-SHA256(key, b"KYE1|" + 验证码).hex()
  验证码每天变化, 但签名可以由本机随时重算, 因此无需再下载 CAPTCHA<日期>.exe.

用法:
  python steam_captcha_auto.py               # 抓取当日验证码并写入
  python steam_captcha_auto.py --check       # 只检查, 不写文件
  python steam_captcha_auto.py --dry-run     # 显示将要写入的内容
  python steam_captcha_auto.py --code ABC123 # 使用指定验证码
  python steam_captcha_auto.py --install-task    # 安装计划任务(每3小时+登录时)
  python steam_captcha_auto.py --remove-task     # 删除计划任务
"""

import argparse
import hashlib
import hmac
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.request
import ssl
import winreg

SALT = b"KYE-vc-bind-v1::SteamToolbox"
TASK_NAME = "SteamToolbox-AutoCaptcha"
LOG_DIR = os.path.join(os.environ.get("LOCALAPPDATA", os.path.expanduser("~")), "SteamToolboxAuto")
LOG_FILE = os.path.join(LOG_DIR, "auto.log")

SOURCES = [
    "https://raw.githubusercontent.com/BIAO-001/SteamToolbox/main/toolbox3.txt",
    "https://cdn.jsdelivr.net/gh/BIAO-001/SteamToolbox@main/toolbox3.txt",
    "https://gitee.com/biaogeNB/SteamToolbox/raw/master/toolbox2.txt",
]

CAPTCHA_RE = re.compile(r"CAPTCHA\s*[:：]\s*([A-Za-z0-9]{3,16})")
CODE_RE = re.compile(r"^[A-Za-z0-9]{3,16}$")


# ---------------------------------------------------------------- 日志

def log(msg, quiet=False):
    line = "%s  %s" % (time.strftime("%Y-%m-%d %H:%M:%S"), msg)
    if not quiet:
        try:
            print(msg)
        except Exception:
            pass
    try:
        os.makedirs(LOG_DIR, exist_ok=True)
        if os.path.exists(LOG_FILE) and os.path.getsize(LOG_FILE) > 200 * 1024:
            with open(LOG_FILE, "r", encoding="utf-8", errors="replace") as f:
                tail = f.readlines()[-500:]
            with open(LOG_FILE, "w", encoding="utf-8") as f:
                f.writelines(tail)
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass


# ---------------------------------------------------------------- 机器绑定

def machine_guid():
    """读取 HKLM\\SOFTWARE\\Microsoft\\Cryptography\\MachineGuid"""
    try:
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Cryptography",
            0,
            winreg.KEY_READ | winreg.KEY_WOW64_64KEY,
        )
        try:
            return winreg.QueryValueEx(key, "MachineGuid")[0].strip()
        finally:
            winreg.CloseKey(key)
    except OSError as e:
        raise RuntimeError("无法读取 MachineGuid: %s" % e)


def sign_code(code, guid=None):
    """按 steam-toolbox 的算法生成 KYE1 签名 (64 位小写十六进制)"""
    guid = guid or machine_guid()
    key = hmac.new(SALT, guid.encode("utf-8"), hashlib.sha256).digest()
    return hmac.new(key, b"KYE1|" + code.encode("utf-8"), hashlib.sha256).hexdigest()


# ---------------------------------------------------------------- 路径定位

def steam_info_dir():
    """返回 <Steam>/config/info, 定位失败返回 None"""
    candidates = []
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Valve\Steam")
        try:
            steam = winreg.QueryValueEx(key, "SteamPath")[0]
            candidates.append(os.path.join(os.path.normpath(steam), "config", "info"))
        finally:
            winreg.CloseKey(key)
    except OSError:
        pass

    # 常见安装位置兜底
    for root in ("E:\\steam", "D:\\steam", "C:\\Program Files (x86)\\Steam",
                 "C:\\Program Files\\Steam"):
        candidates.append(os.path.join(root, "config", "info"))

    for d in candidates:
        if d and os.path.isdir(os.path.dirname(d)):
            return d
    return None


# ---------------------------------------------------------------- 远程抓取

def http_get(url, timeout=15, insecure=False):
    ctx = ssl.create_default_context()
    if insecure:
        # 仅在显式 --insecure 时关闭校验(部分机器吊销链离线)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    return urllib.request.urlopen(req, timeout=timeout, context=ctx).read().decode(
        "utf-8", "replace")


def fetch_captcha(insecure=False):
    """依次尝试各源, 返回 (code, source_url)"""
    errors = []
    for url in SOURCES:
        try:
            text = http_get(url, insecure=insecure)
            m = CAPTCHA_RE.search(text)
            if m and CODE_RE.match(m.group(1)):
                return m.group(1), url
            errors.append("%s: 未找到 CAPTCHA 字段" % url)
        except Exception as e:
            errors.append("%s: %s" % (url, e))
    raise RuntimeError("所有验证码源均失败:\n  " + "\n  ".join(errors))


# ---------------------------------------------------------------- 读写验证码文件

def read_local(path):
    try:
        with open(path, "rb") as f:
            raw = f.read()
        text = raw.decode("utf-8", "replace")
        lines = text.splitlines()
        code = lines[0].strip() if lines else ""
        sig = ""
        if len(lines) > 1:
            m = re.match(r"^KYE1[:：]\s*([0-9a-fA-F]{64})$", lines[1].strip())
            if m:
                sig = m.group(1).lower()
        return code, sig, raw
    except FileNotFoundError:
        return "", "", b""


def write_local(path, code, sig, backup=True):
    content = "%s\nKYE1:%s\n" % (code, sig)
    if backup and os.path.exists(path):
        try:
            shutil.copy2(path, path + ".bak")
        except Exception as e:
            log("备份失败(忽略): %s" % e)
    tmp = path + ".tmp"
    with open(tmp, "wb") as f:
        f.write(content.encode("utf-8"))
    os.replace(tmp, path)


def verify_local(path):
    code, sig, _ = read_local(path)
    if not code or not sig:
        return False, "本地文件缺失或格式不正确"
    expect = sign_code(code)
    if expect == sig:
        return True, "签名有效 (机器匹配)"
    return False, "签名无效 (文件被篡改或来自其他机器)"


# ---------------------------------------------------------------- 计划任务

def pythonw():
    exe = sys.executable or "python"
    cand = exe.replace("python.exe", "pythonw.exe").replace("python3.exe", "pythonw.exe")
    return cand if os.path.exists(cand) else exe


def install_task(script_path):
    tr = '"%s" "%s" --quiet' % (pythonw(), script_path)
    cmds = [
        ["schtasks", "/Create", "/TN", TASK_NAME, "/TR", tr,
         "/SC", "HOURLY", "/MO", "3", "/F"],
        ["schtasks", "/Create", "/TN", TASK_NAME + "-Logon", "/TR", tr,
         "/SC", "ONLOGON", "/F"],
    ]
    rc = 0
    for c in cmds:
        r = subprocess.run(c, capture_output=True, text=True)
        if r.returncode != 0:
            rc = r.returncode
            log("任务创建失败: %s\n%s%s" % (" ".join(c), r.stdout, r.stderr))
        else:
            log("已创建计划任务: %s" % c[3])
    return rc


def remove_task():
    rc = 0
    for name in (TASK_NAME, TASK_NAME + "-Logon"):
        r = subprocess.run(["schtasks", "/Delete", "/TN", name, "/F"],
                           capture_output=True, text=True)
        if r.returncode != 0:
            rc = r.returncode
    return rc


# ---------------------------------------------------------------- 主流程

def main():
    ap = argparse.ArgumentParser(description="Steam Toolbox 每日验证码自动更新")
    ap.add_argument("--check", action="store_true", help="只检查, 不写文件")
    ap.add_argument("--dry-run", action="store_true", help="显示结果, 不写文件")
    ap.add_argument("--code", help="手动指定验证码(不联网)")
    ap.add_argument("--insecure", action="store_true", help="跳过 HTTPS 证书校验(吊销链离线时用)")
    ap.add_argument("--info-dir", help="Verification_code.txt 所在目录")
    ap.add_argument("--quiet", action="store_true", help="不输出到控制台")
    ap.add_argument("--install-task", action="store_true", help="安装计划任务")
    ap.add_argument("--remove-task", action="store_true", help="删除计划任务")
    args = ap.parse_args()

    if args.install_task:
        return install_task(os.path.abspath(__file__))
    if args.remove_task:
        return remove_task()

    info_dir = args.info_dir or steam_info_dir()
    if not info_dir:
        log("错误: 找不到 Steam 的 config/info 目录, 请用 --info-dir 指定", args.quiet)
        return 2
    path = os.path.join(info_dir, "Verification_code.txt")

    local_code, local_sig, _ = read_local(path)
    log("本机 MachineGuid : %s" % machine_guid(), args.quiet)
    log("验证码文件      : %s" % path, args.quiet)
    log("本地验证码      : %s" % (local_code or "(无)"), args.quiet)

    if args.code:
        code, source = args.code, "(手动指定)"
    else:
        try:
            code, source = fetch_captcha(insecure=args.insecure)
        except Exception as e:
            log("抓取失败: %s" % e, args.quiet)
            if local_code:
                log("保留现有本地验证码继续使用", args.quiet)
                return 0
            return 1
    log("远程验证码      : %s  <- %s" % (code, source), args.quiet)

    sig = sign_code(code)
    log("生成签名        : KYE1:%s" % sig, args.quiet)

    if local_code == code and local_sig == sig:
        log("已是最新, 无需修改", args.quiet)
        return 0

    if args.check or args.dry_run:
        log("将写入:\n%s\nKYE1:%s" % (code, sig), args.quiet)
        return 0

    try:
        write_local(path, code, sig)
    except Exception as e:
        log("写入失败: %s" % e, args.quiet)
        return 1

    ok, msg = verify_local(path)
    log("写入完成, 校验: %s" % msg, args.quiet)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
