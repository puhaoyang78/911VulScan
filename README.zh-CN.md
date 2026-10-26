# 911VulScan 中文版

911VulScan 基于 Knostic [OpenAnt](https://github.com/knostic/OpenAnt)，保留上游 Apache 2.0 许可证和署名。`911-dev` 分支提供中文扫描工作台、中文漏洞报告、默认 DeepSeek 配置，以及 C/C++ 隔离动态测试模板和 Python、JavaScript/TypeScript、Go 的动态构建指导。

## 本分支的变化

- 新的中文网页工作台：任务概览、分步扫描表单、模型选择、实时日志、摘要、漏洞报告和披露材料。
- 新安装默认使用 `deepseek-default`，所有七个扫描阶段使用 `deepseek-flash`；可选择 `deepseek-pro` 使用 `deepseek-v4-pro`。
- 已有显式 `default_llm` 和旧版 Anthropic 配置继续生效，不自动改写用户配置。网页的“DeepSeek（默认）”是本次任务选择；“使用已有模型配置”沿用原配置。
- 所有扫描模型调用增加简体中文叙述要求。报告标题、状态显示、摘要及修复建议采用中文；JSON 键、枚举、CWE/CVE、代码、文件路径和原始证据保持原样。
- C/C++ 从原先跳过动态测试改为固定 GCC/G++、ASan/UBSan 编译执行模板；只在 Docker 容器中执行扫描项目代码。

## 安装与启动

需要 Go 1.26+、Python 3.11+；JavaScript/TypeScript 解析另需 Node.js。动态验证另需已经启动的 Docker Engine。

```bash
git clone --branch 911-dev https://github.com/puhaoyang78/911VulScan.git
cd 911VulScan
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r libs/vulscan-core/requirements.txt
python -m pip install -e 'libs/vulscan-core[dev]'
cd apps/vulscan-cli
go build -o bin/vulscan .
cd ../..
export VULSCAN_PYTHON="$PWD/.venv/bin/python"
./apps/vulscan-cli/bin/vulscan serve
```

打开终端显示的本机地址，默认为 `http://127.0.0.1:8080`。服务不提供多用户身份认证，请保留回环地址监听，不要直接暴露到公网。网页产物保存在 `~/.vulscan/webui/`。

## 配置 DeepSeek

推荐使用交互向导：

```bash
./apps/vulscan-cli/bin/vulscan setup llm
```

也可在自己的终端设置 `DEEPSEEK_API_KEY`，或在网页中输入仅本次任务使用的密钥。网页输入不会保存到配置、任务元数据或日志中。`set-api-key --provider deepseek` 用于明确保存 DeepSeek 凭据；不要把密钥提交到代码库。

默认接口为 `https://api.deepseek.com`。已有配置的 `base_url` 优先于 `DEEPSEEK_BASE_URL`；使用自定义网关前，请核对网页显示的请求接收方。扫描会发送相关代码和模型提示，并产生 API 费用。

以下配置不包含密钥，可配合环境变量使用：

```json
{
  "$schema_version": 2,
  "default_llm": "deepseek-default",
  "llm_providers": {
    "deepseek": {
      "type": "deepseek",
      "base_url": "https://api.deepseek.com",
      "request_timeout": 120,
      "thinking": {"type": "enabled"}
    }
  }
}
```

保存位置为 `~/.config/vulscan/config.json`，或 `$XDG_CONFIG_HOME/vulscan/config.json`。内置配置不必重复定义在 `llm_configs` 中。DeepSeek 适配器保留工具调用所需的历次 `reasoning_content`，支持明确关闭思考模式，不借用 OpenAI/Anthropic 密钥。

`--api-key` 保留旧版 Anthropic 覆盖语义；DeepSeek 请使用自己的环境变量、网页字段或配置向导。Auto Patcher 同样继承模型配置的默认分析绑定；已有显式供应商选择保持不变。

模型名及计价依据核对于 2026-10-17：[DeepSeek 模型价格](https://api-docs.deepseek.com/quick_start/pricing/)、[思考模式和工具调用](https://api-docs.deepseek.com/guides/thinking_mode/)。旧 `deepseek-chat` / `deepseek-reasoner` 已停用。本地费用按登记费率估算，峰谷定价、缓存、网关计费及后续价格调整可能导致与账单不同。

## 扫描与中文报告

```bash
# 只扫描自己有权测试的代码。未准备 Docker 时明确跳过动态测试。
./apps/vulscan-cli/bin/vulscan scan /path/to/project \
  --llm-config deepseek-default --verify --skip-dynamic-test

# C/C++ 完整扫描（需要 Docker）
./apps/vulscan-cli/bin/vulscan scan /path/to/c-project \
  --language c --llm-config deepseek-default --verify

# 对现有扫描结果单独进行动态验证
./apps/vulscan-cli/bin/vulscan dynamic-test /path/to/pipeline_output.json \
  --repo-path /path/to/c-project --llm-config deepseek-default
```

网页中打开“摘要”“报告”查看中文结论。原始终端输出、编译器证据以及历史已有报告不会被模型重新翻译，以免改写证据；本分支生成的新报告和模型叙述明确要求中文。机器消费方继续使用原有 JSON/SARIF 字段和状态，不应解析中文显示文案。

## C/C++ 动态验证范围

- `.c` 采用 C11，C++ 扩展名采用 C++17，GCC/G++ 加载 AddressSanitizer 与 UndefinedBehaviorSanitizer。
- 当前支持单编译单元和标准库复现；仅预置发现所在的真实目标文件。不自动运行项目 Make/CMake，不宣称支持任意头文件、链接库或平台 ABI。
- 编译失败、依赖缺失、配置错误返回 `ERROR`；超时、普通崩溃、缺少有效证据返回 `INCONCLUSIVE`。`NOT_REPRODUCED` 只表示本次未复现，不代表已证明安全。
- 固定容器模板、只读根文件系统、无运行时外网、移除 capabilities、禁止新增权限、资源限额；没有宿主卷挂载或宿主执行回退。
- 镜像构建仍需拉取基础镜像和公开编译依赖。当前不提供 LeakSanitizer 内存泄漏检测保证。

详细协议和限制见 [动态验证说明](libs/vulscan-core/utilities/dynamic_tester/README.md)。自动生成的驱动仍需人工核对，运行时诊断必须与原始发现和目标调用栈相符。

## Docker 构建代理与工具链缓存

动态验证的构建阶段需要下载基础镜像和语言依赖。直连慢到一定程度时，构建会在预算内完不成，之前的版本只能记录“构建超时”。现在提供两条相互独立的改进：

- **可选的构建代理。** 网页扫描表单的“Docker 构建代理 IP / 代理端口”可填任意 HTTP（含 mixed）代理；两项都留空表示不启用代理，沿用 Docker 现有网络。CLI 对应 `--docker-proxy http://IP:端口`。代理只注入构建过程，不进入运行漏洞测试的容器；本机回环代理（如 mihomo 的 `127.0.0.1:7890`）经 Docker bridge 上的临时中继转发，代理地址在多次构建间保持稳定，避免代理端口变化导致依赖层缓存失效。
- **共享工具链镜像。** C/C++ 的 GCC/G++ 与 libc 头文件预置为 `vulscan/toolchain-c:gcc12-<内容摘要>`，首次构建后由全部发现和后续运行复用；单条发现的构建只复制文件。以前每次发现都要重新下载约 63 MiB 的编译器包，一次超时不会留下任何缓存层，后续发现只能重复同样的下载。
- **基础镜像按需准备。** `--build-arg` 只影响构建步骤里的 `RUN`，镜像拉取由 Docker 守护进程完成。程序在构建前解析 Dockerfile 的 `FROM`，只对缺失的镜像执行一次 `docker pull`；拉取失败会明确指向守护进程网络并停止模型重试，同时把本机已缓存的镜像告诉生成模型，优先复用。守护进程自身的代理配置（如 systemd drop-in）不在本程序的修改范围内。
- **按仓库的依赖镜像。** Python/Node/Go 不再让每条发现各自安装一遍依赖：程序按仓库清单（`requirements.txt`、`package.json`/锁文件、`go.mod`/`go.sum`）构建一次 `vulscan/deps-<语言>:<清单摘要>`，测试镜像直接以它为基础，依赖已在标准位置（`/app/node_modules`、`/go/pkg/mod`、site-packages）。清单不变就复用同一镜像；构建失败只告警并退回逐条安装，不影响扫描。

预检在开始生成测试之前检查 Docker 守护进程、buildx 与代理可达性，因此配置错误会立即以一条中文说明失败，而不是让每条发现各自耗尽构建预算。构建预算默认 900 秒、容器执行 120 秒、工具链 1800 秒，可用 `VULSCAN_DOCKER_BUILD_TIMEOUT`、`VULSCAN_DOCKER_RUN_TIMEOUT`、`VULSCAN_DOCKER_TOOLCHAIN_TIMEOUT` 覆盖。构建超时、容器执行超时和宿主环境错误都不再触发模型重试。

## 扫描历史版本

多数历史漏洞只存在于旧版本。网页表单在仓库地址下方提供“版本 / 标签（可选）”，旁边是“获取版本列表”：它向 `GET /refs?repo=…` 请求远端标签与分支（`git ls-remote`，只读、限时、拒绝回环与云元数据地址），填进候选框供选择。启动扫描后：

- 标签或分支用 `git clone --depth 1 --branch <版本>` 直接取回；
- 提交号（或 `--branch` 不接受的特殊引用）退化为完整克隆后 `git checkout --detach <版本>`；
- 检出失败会明确提示“无法检出该版本（标签/分支/提交不存在，或仓库不允许匿名访问）”，不会拿默认分支冒充目标版本；
- 任务页与 `meta.json` 记录所选版本，报告里的 `commit` 是实际检出的提交，便于复核结论对应哪份代码。

版本名只接受字母、数字与 `. _ - /`，不能以短横线开头、不能含 `..` 或 `@{`，避免被当成 git 选项。本机路径没有远端标签，直接在输入框填写分支名或提交号即可（程序不会替你切换本地工作区）。

## 靶场与教学项目的漏洞上报

DVWA、DSVW、OWASP Juice Shop、各种 `damn-vulnerable-*` 把漏洞当作演示功能。旧版会把“这是教学演示”写进应用上下文的免报清单，第 1 阶段再原样读成“不要上报”，结果整份扫描零产出——靶场里真正的 SQL 注入、XSS、命令执行全被当成设计意图。

现在扫描开始时先做一次可复现的判定：读取仓库 README 与目录名，命中“deliberately vulnerable”“靶场”“CTF”等信号就把应用上下文标记为靶场，并记录命中依据（写进 `application_context.json`）。标记为靶场后：

- 免报清单不再拼接，第 1 阶段提示词改为“这些缺陷仍按真实漏洞上报”，第 2 阶段只判断能否利用，不看作者意图；
- “只报远程可利用”的收窄对该仓库失效——练习程序的本地缺陷同样是它的考点。

自动判定漏掉时，用 `--include-intentional` 显式声明本次按靶场处理。判定依据会随上下文保存在扫描目录，便于事后核对。

## 二阶段资源回收与容量保护

每次验证使用独立的任务及尝试标识。结束、失败或超时后，按归属标签回收容器、临时镜像和网络；Compose 中需要构建的服务使用本次尝试的专属镜像标签，直接引用的公共镜像不删除。临时工作目录只在核对目录身份后删除，报告、检查点和重现材料继续保留。网页和 CLI 的外层进程在扫描子进程退出后另行执行有时间上限的清理，避免取消任务后仅杀死 Python、留下 Docker 资源。

默认保护：

- 同一操作系统用户的动态验证尝试串行执行，跨进程文件锁在进程退出时释放；不会同时启动多个大构建。
- 每个运行容器仍限制为 512 MiB 内存、1 个 CPU 和 256 个进程；Compose 最多允许 8 个服务。这些限制不等于整个构建过程的内存配额。
- Docker 日志采用 `local` 驱动，每个容器最多保留 2 份、每份 10 MB；命令 stdout/stderr 各保留末尾 256 KiB，超出时明确标记截断。
- 新尝试启动前检查默认 Docker builder 的共享构建缓存。达到 10 GiB 时拒绝继续构建；可用 `VULSCAN_DOCKER_CACHE_MAX_BYTES` 设置正整数字节阈值。本地暂存目录所在磁盘可用空间不足 2 GiB 时也拒绝新尝试。

需要支持 `--builder default` 的 Docker/Compose。程序显式使用所选 Docker context 的默认 builder，不沿用自定义 `BUILDKIT_HOST` 等构建后端覆盖，以免检查的缓存与实际构建后端不一致。环境或容量错误保留为动态验证错误，不表示漏洞不存在，也不应交给模型反复修改 PoC。

**临时镜像删除不等于 BuildKit 缓存删除。** 程序不会执行全局 `docker system prune` 或 `docker builder prune`，不会修改 daemon 配置。上述阈值是新任务准入保护，不是硬磁盘配额：单次构建或服务器上的其他程序仍可能使占用超过阈值。共享缓存的实际回收由服务器管理员或已有 Docker/BuildKit GC 策略管理。使用远程 Docker context 时，本地磁盘检查不能代表远程服务器的磁盘余量，仍需在远程主机配置存储监控与预算。

清理失败会显示警告，并保留任务资源清单用于重试；不要直接删除清单或清空整个 Docker 主机来掩盖失败。升级后的所有权标签只适用于新验证任务，旧版本已经遗留的无标签资源需要管理员单独核对后处理。

在支持文件租约锁的 Unix 系统上，CLI 将清单保存在系统用户配置目录下的 `vulscan/docker-lifecycle`（可用 `VULSCAN_DOCKER_STATE_DIR` 指定私有目录）。下一次调用扫描引擎时，只重试没有活跃进程持有租约、且 Docker 后端身份匹配的遗留任务。后台恢复有独立时间预算，失败则保留记录。Windows 保留本次退出时的清理，但不自动判断旧任务是否已失效。直接调用 Python 而绕过 Go CLI，也没有 Go 外层强杀后的兜底；不能将这些场景描述为已经完成自动恢复。

真实 Docker 生命周期烟测默认跳过。需要验收时，仅在专用测试 Docker 主机上进入 `libs/vulscan-core`，执行 `VULSCAN_DOCKER_LIFECYCLE_TESTS=1 python -m pytest tests/test_docker_lifecycle_integration.py -v`。该测试会拉取官方 `busybox:1.37`，验证正常退出、超时、构建失败、Compose 镜像隔离及 Python 被强杀后的回收；不调用模型，不运行外部项目 PoC，不执行全局缓存清理。Linux CI 单独启用这组测试。

## 验证方法

```bash
# Python 静态检查和回归
cd libs/vulscan-core
python -m ruff check .
python -m pytest tests/test_llm_deepseek_adapter.py \
  tests/test_chinese_reports.py tests/test_dynamic_c_templates.py -q
python -m pytest tests/ -q

# Go 构建、静态检查及回归
cd ../../apps/vulscan-cli
go vet ./...
go test ./...
go build -o bin/vulscan .
```

DeepSeek 测试使用模拟响应，不调用付费接口。C/C++ 原生回归只编译仓库自带、已审阅的漏洞版/修复版 fixture；Docker 路由 mock 不等于真实镜像构建或容器验证通过。真实 DeepSeek、Docker 和浏览器视觉验收应在具备相应环境时分别执行，不应将单元测试通过视为全部验收完成。

最小部署包的构建与运行步骤见 [部署说明](README.deploy.md)。开发回归结果以对应提交的 CI 记录为准。
