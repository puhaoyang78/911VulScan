"""统一构建下载策略：国内源直连；下载失败时仅一次官方源＋任务代理。"""

import json
from pathlib import Path
import re
import shlex
import time

from utilities.docker_build.images import build_inputs, log_download
from utilities.docker_build.proxy import build_proxy_arguments, parse_docker_proxy

# 只在 RUN 的进程中设置，不写 ENV、pip/npm/go 全局配置，也不修改依赖清单。
# apt/apk 保留原协议、发行版、组件、签名与包版本；每次 RUN 先恢复原始源，再按模式换站点。
_SETUP = r'''
export PIP_DEFAULT_TIMEOUT=15 PIP_RETRIES=1 PIP_DISABLE_PIP_VERSION_CHECK=1;
export NPM_CONFIG_FETCH_RETRIES=1 NPM_CONFIG_FETCH_TIMEOUT=15000;
if [ "$VULSCAN_DOWNLOAD_SOURCE" = official ]; then
 export PIP_INDEX_URL=https://pypi.org/simple NPM_CONFIG_REGISTRY=https://registry.npmjs.org GOPROXY=https://proxy.golang.org;
else
 export PIP_INDEX_URL=https://pypi.tuna.tsinghua.edu.cn/simple NPM_CONFIG_REGISTRY=https://registry.npmmirror.com GOPROXY=https://goproxy.cn;
 unset HTTP_PROXY HTTPS_PROXY ALL_PROXY http_proxy https_proxy all_proxy;
fi;
export PIP_EXTRA_INDEX_URL=;
if command -v apt-get >/dev/null 2>&1 && [ -w /etc/apt ] && [ -w /var/lib ]; then
 mkdir -p /var/lib/vulscan-build-sources;
 for f in /etc/apt/sources.list /etc/apt/sources.list.d/*.list /etc/apt/sources.list.d/*.sources; do
  [ -f "$f" ] || continue;
  b=/var/lib/vulscan-build-sources/$(basename "$f");
  [ -f "$b" ] || cp "$f" "$b";
  cp "$b" "$f";
  if [ "$VULSCAN_DOWNLOAD_SOURCE" != official ]; then
   sed -i -e 's|\(https\?://\)deb.debian.org/debian|\1mirrors.tuna.tsinghua.edu.cn/debian|g' -e 's|\(https\?://\)security.debian.org/debian-security|\1mirrors.tuna.tsinghua.edu.cn/debian-security|g' -e 's|\(https\?://\)archive.ubuntu.com/ubuntu|\1mirrors.aliyun.com/ubuntu|g' -e 's|\(https\?://\)security.ubuntu.com/ubuntu|\1mirrors.aliyun.com/ubuntu|g' -e 's|\(https\?://\)ports.ubuntu.com/ubuntu-ports|\1mirrors.aliyun.com/ubuntu-ports|g' "$f";
  fi;
 done;
 printf '%s\n' 'Acquire::Retries "1";' 'Acquire::http::Timeout "15";' 'Acquire::https::Timeout "15";' 'APT::Update::Error-Mode "any";' > /etc/apt/apt.conf.d/99vulscan-download;
fi;
if [ -f /etc/apk/repositories ] && [ -w /etc/apk/repositories ] && [ -w /var/lib ]; then
 mkdir -p /var/lib/vulscan-build-sources;
 b=/var/lib/vulscan-build-sources/apk-repositories;
 [ -f "$b" ] || cp /etc/apk/repositories "$b";
 cp "$b" /etc/apk/repositories;
 if [ "$VULSCAN_DOWNLOAD_SOURCE" != official ]; then
  sed -i 's|\(https\?://\)dl-cdn.alpinelinux.org/alpine|\1mirrors.aliyun.com/alpine|g' /etc/apk/repositories;
 fi;
fi;
'''
# One physical line keeps existing continuations and BuildKit flags intact.
_PREFIX = ' '.join(line.strip() for line in _SETUP.strip().splitlines()) + ' '
_MARKER = 'ARG VULSCAN_DOWNLOAD_SOURCE=domestic'
_PROXY_NAMES = ('HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'http_proxy', 'https_proxy', 'all_proxy', 'NO_PROXY', 'no_proxy')
_DOWNLOAD_FAILURE = re.compile(
    r'\b(?:read|connect(?:ion)?|download|operation|TLS handshake|i/o) (?:timed?\s*out|timeout)\b|'
    r'\b\w*Timeout(?:Error|Exception)\b|Client\.Timeout|context deadline exceeded|could not resolve|temporary failure resolving|'
    r'connection (?:refused|reset|failed)|network is unreachable|tls handshake|'
    r'failed to fetch|failed to download|error downloading|proxyconnect|'
    r'ECONNRESET|ECONNREFUSED|ENOTFOUND|EAI_AGAIN|ETIMEDOUT|ENETUNREACH|'
    r'No matching distribution found|Could not find a version that satisfies|'
    r'ETARGET|E404|ENOVERSIONS|Unable to locate package|has no installation candidate|'
    r'404 Not Found|403 Forbidden|429 Too Many Requests|502 Bad Gateway|503 Service Unavailable|'
    r'package.*not found|not available from the repositories|no such package|fetching.*temporary error', re.I,
)


def download_diagnostic(text: str) -> str:
    """原始日志另行保留；错误摘要去掉 BuildKit 重印的下载初始化脚本。"""
    return "\n".join(line for line in text.splitlines() if "export PIP_DEFAULT_TIMEOUT=15" not in line)


def is_download_failure(text: str) -> bool:
    text = download_diagnostic(text)
    # Integrity, compiler, disk and permission errors must not trigger a network retry.
    if re.search(r'hash mismatch|checksum mismatch|CHECKSUM MISMATCH|EINTEGRITY|'
                 r'DO NOT MATCH THE HASHES|no space left on device|permission denied', text, re.I):
        return False
    return bool(_DOWNLOAD_FAILURE.search(text))


def render_downloads(text: str) -> str:
    """仅为实际 RUN 加构建源配置；不改 FROM、COPY、CMD、ENTRYPOINT 或 SHELL。"""
    if _MARKER in text or not re.search(r'(?mi)^\s*RUN\s+', text):
        return text
    result = []
    continuation = False
    heredocs = []
    lines = iter(text.splitlines(keepends=True))
    for line in lines:
        if heredocs:
            result.append(line)
            if line.strip() == heredocs[0]:
                heredocs.pop(0)
            continue
        current = re.match(r'^(\s*)([A-Za-z]+)\s+(.*?)(\r?\n)?$', line)
        if continuation or not current:
            result.append(line)
        else:
            indent, instruction, command, newline = current.groups()
            if instruction.upper() == 'FROM':
                result.extend((line if line.endswith('\n') else line + '\n', _MARKER + '\n'))
            elif instruction.upper() == 'RUN':
                flags = ''
                while command.startswith('--'):
                    flag, command = command.split(None, 1)
                    flags += flag + ' '
                if command.startswith('['):
                    while command.rstrip().endswith('\\'):
                        line = next(lines)
                        command = command.rstrip()[:-1] + line.strip()
                    command = shlex.join(json.loads(command))
                if re.fullmatch(r'<<-?[\'"]?\w+[\'"]?(?:\s+(?:ba)?sh)?', command):
                    # Docker's shell heredoc shorthand executes its body directly.
                    result.extend((line, _PREFIX + '\n'))
                else:
                    result.append(f'{indent}RUN {flags}{_PREFIX}{command}{newline or ""}')
            else:
                result.append(line)
            # COPY/RUN heredoc bodies are data, never Dockerfile instructions.
            if '<<' in command:
                lexer = shlex.shlex(command, posix=False, punctuation_chars='<')
                lexer.whitespace_split = True
                tokens = list(lexer)
                heredocs = [tokens[i+1].lstrip('-').strip("'\"") for i, token in enumerate(tokens[:-1]) if token == '<<']
        continuation = line.rstrip().endswith('\\')
    return ''.join(result)


def prepare_downloads(root: str, *, compose: bool = False) -> None:
    paths, _ = build_inputs(root, compose=compose)
    for name in paths:
        path = Path(name)
        if path.is_file():
            path.write_text(render_downloads(path.read_text(encoding='utf-8')), encoding='utf-8')


def build_with_downloads(argv, runner, *, proxy: str | None = None, timeout: int = 900, **kwargs):
    """复用同一构建预算与缓存。只有下载失败才发起第二次构建。"""
    proxy = parse_docker_proxy(proxy)
    deadline = time.monotonic() + timeout
    # Explicit blanks also override Docker CLI config.json's automatic proxy injection.
    direct = [part for key in _PROXY_NAMES for part in ('--build-arg', key + '=')]
    insertion = len(argv) if 'compose' in argv else len(argv) - 1
    def command(args):
        return [*argv[:insertion], *args, *argv[insertion:]]
    log_download('依赖国内源优先：pip=TUNA；npm=npmmirror；Go=goproxy.cn；apt=TUNA/阿里云；apk=阿里云；任务代理未启用')
    outcome = runner(command([*direct, '--build-arg', 'VULSCAN_DOWNLOAD_SOURCE=domestic']), timeout=timeout, **kwargs)
    out, err, code, timed = outcome
    if not code and not timed:
        log_download("国内依赖源构建成功，未启用任务代理", status="success")
        return outcome
    diagnostic = '\n'.join((out, err))
    if not is_download_failure(diagnostic):
        return outcome
    log_download('国内依赖源失败：' + download_diagnostic(diagnostic)[-1800:], status='error')
    remaining = int(deadline - time.monotonic())
    if not proxy or remaining <= 0:
        log_download('未配置任务代理或构建总预算已耗尽，未访问官方源')
        return outcome
    log_download(f'切换官方依赖源，使用任务代理 {proxy}（仅重试一次，剩余 {remaining}s）')
    with build_proxy_arguments(proxy, runner) as arguments:
        result = runner(command([*arguments, '--build-arg', 'ALL_PROXY=', '--build-arg', 'all_proxy=',
                               '--build-arg', 'VULSCAN_DOWNLOAD_SOURCE=official']), timeout=remaining, **kwargs)
        if result[2] or result[3]:
            log_download('官方依赖源代理构建失败：' + download_diagnostic('\n'.join(result[:2]))[-1800:], status='error')
        else:
            log_download('官方依赖源代理构建成功', status='success')
        return result
