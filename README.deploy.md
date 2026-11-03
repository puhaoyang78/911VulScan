# 911VulScan 最小部署包

部署包只含运行代码、构建依赖清单、运行时提示词、必要配置和许可证；开发仓库继续保留测试与 CI。

Ubuntu 安装使用国内源：系统 APT 的官方 Ubuntu 地址切换为阿里云（同时兼容 `sources.list` 和 24.04 的 deb822 `.sources`），Python 包默认清华 PyPI，npm 使用 npmmirror，Go 模块使用 goproxy.cn 并保留校验数据库。Python 源码取自华为云，Git 源码取自南京大学 kernel.org 镜像，Go 元数据取自 golang.google.cn、安装包取自阿里云，Node 22 取自 npmmirror，20.04 的冻结 Docker 包取自阿里云 Docker CE 镜像。现有自定义第三方 APT 仓库、签名配置和显式设置的包管理器环境变量保留；APT 签名、压缩包 SHA-256 和 npm 锁文件检查不关闭。仅补装独立 Docker 插件时，也从阿里云 Docker CE 包提取固定版本的官方插件并校验，不安装软件包、不执行维护脚本、不改现有 Engine。

## 全新 Ubuntu 服务器一键部署

Ubuntu **20.04、22.04、24.04**（也支持 26.04），x86_64/arm64，使用 root 或具有 sudo 权限的用户执行：

```sh
tar -xzf 911VulScan-source.tar.gz
cd 911VulScan
sh scripts/install-deployment.sh --deploy
```

该命令补齐 Python、Git、Go、Node/npm、编译工具、Docker Engine、Compose 和 Buildx，安装 Python 与 JavaScript 依赖，并构建 CLI。它用本地样例实际检查全部已启用语言的解析器，再由服务启动检查 Docker 构建、Compose 执行和测试资源清理；这些检查不调用模型。只有服务处于运行状态且网页响应正常，才显示部署完成。

服务通过 **vulscan.service** 开机自启，以非 root 账号及 Docker 补充组运行，不修改用户的 Docker 组成员关系、socket 权限、系统 Python、daemon 配置或已有凭据。普通用户部署使用当前账号；通过 sudo 部署使用调用 sudo 的账号；直接以 root 部署时创建无登录权限的 `vulscan` 系统账号，主目录为 `/var/lib/vulscan`。也可用 `--service-user 用户名` 指定已有非 root 账号。重复部署保留原有非 root 服务账号。

安装目录必须能被服务账号读取和进入。直接以 root 部署时，将源码解压到 `/opt/911VulScan` 等共享程序目录，避免放在其他用户无法进入的 `/root` 下。已有 root 服务的数据不会被自动移动或改权限；切换账号前需停止旧服务，将其 `~/.vulscan` 迁移到新账号主目录并设置所有权，安装器发现未迁移的数据会停止更新。

默认自动选端口：优先使用 `8080`，已被占用时由系统分配空闲端口，安装结束显示实际访问地址。重复部署优先沿用正在运行的服务端口；选定端口写入 systemd，重启后保留。从另一台电脑访问时，将 SSH 转发的目标端口设为安装器显示的端口，例如：

```sh
ssh -N -L 8080:127.0.0.1:8080 用户名@服务器地址
# 然后在本机浏览器打开 http://127.0.0.1:8080
```

需要固定端口时，可用 `--port 端口号`（1024–65535）；指定端口被占用时，在停止旧服务或更新应用前报错。旧版服务即使曾自动换到其他端口，更新时也会先核对 systemd 主进程实际拥有的监听地址，再检查活动扫描，无需手动查端口或停止服务。

在网页中填写模型 API Key 后即可扫描。安装器不能代为提供账户余额或 API 权限；被扫描项目特有的依赖由动态测试 Docker 构建流程安装。CLI 动态测试同样需要当前会话具备 Docker 访问权限，systemd 服务的补充组不会改变交互式会话权限。

```sh
systemctl status vulscan
journalctl -u vulscan -f
# 只查看完整计划，不安装、不启动：
sh scripts/install-deployment.sh --deploy --dry-run
```

重复执行同一部署命令即可更新。安装器先读取现有网页中的活动任务数量；有运行、排队或取消中的扫描时拒绝更新，请等待任务结束后重试。旧服务先按正常关闭流程停止，再更新应用环境、启用并显式重启服务；停止失败时不会继续安装。每次显式部署会重置旧的启动失败计数，自动恢复仍受每 60 秒 3 次启动的限制。启动后核对 systemd 主进程的用户、实际加载的程序文件和网页监听端口，确认运行的是本次安装的程序。更新阶段失败时服务保持停止，可修复原因后重新执行同一命令；扫描结果与用户配置保留。

首次部署的 `DOCKER_CONFIG` 默认使用服务账号的 `~/.docker`，也可显式指定可被该账号访问的绝对路径。重复部署保留原服务的 `HOME` 与 `DOCKER_CONFIG`，显式传入新配置时才更换 Docker 配置路径。插件检测、缺失插件安装、部署检查和 systemd 服务使用同一个路径；不复制或重写已有 `config.json`，不放宽其权限。例如：

```sh
sudo env DOCKER_CONFIG=/home/用户名/.docker sh scripts/install-deployment.sh --deploy
```

Python 源码安装中断后，重新运行原命令即可续装到同一 `.tools/python`。安装器识别自己的未完成标记和旧版 CPython 3.12 目录，补齐标准库与 venv 后移除标记，不删除目录中的其他文件。未知或符号链接指向的工具目录仍会报错，避免覆盖自定义环境。

一键模式会在需要时启用官方 Ubuntu `universe` 组件。20.04 自带的 Git 2.25 不满足扫描所需的隔离选项，安装器将校验并编译已测试的 Git 2.56.x 维护分支到 `.tools/git`（使用上游支持的 `NO_RUST` 纯 C 构建）；20.04/22.04 使用本地 Python 3.12.16，均保留系统版本。工具下载遇到连接重置、超时、限流或临时服务错误时最多尝试 3 次，404、证书错误与校验失败直接报错。虚拟环境内的 pip 升级至 25.3+，依赖下载采用 60 秒读取时限和最多 3 次续传重试。

**20.04 的 Docker 已停止上游支持。** `--deploy` 包含安装下文所列官方保留冻结版本的授权，会明确显示版本；需要仍受上游支持的 Docker 时应使用 22.04/24.04。已有完整 Docker 会复用，其他来源的冲突安装不会被强制移除。已有自行配置的 `vulscan.service` 也不会被覆盖。一键模式要求系统实际运行 systemd；容器环境可使用下述仅安装应用的方式。

## CentOS Linux 7 一键部署

CentOS Linux **7 / x86_64** 使用独立入口，适用于 `3.10.0-957.27.6…el7.x86_64` 这类内核（最低 `3.10.0-514.el7`）。在完整源码或部署包的根目录，以 root 执行：

```sh
bash scripts/install-centos7.sh
```

此入口保留宿主机系统 Python、OpenSSL、glibc 和内核，应用在 Ubuntu 24.04 用户空间的容器中构建和运行，包含 Python 3.12、Go 1.26、Node 22、Git、Compose 与 Buildx。宿主机缺少 Docker 时，使用 Docker 官方 CentOS 7 归档的 Engine/CLI **26.1.4**、containerd **1.6.33**；RPM 保持签名校验，CentOS 依赖使用官方 7.9.2009 Vault，仅为本次 yum 调用启用源。已有可用 Docker 20.10+ 会复用，其他来源的残缺安装不会被替换或降级。安装不改写 yum 源、Docker daemon 配置和已有凭据。

服务仍为 `vulscan.service`，应用以无登录权限的 `vulscan` 账号运行，数据在 `/var/lib/vulscan/.vulscan`，Docker 配置在 `/var/lib/vulscan/.docker`。目录挂载在容器内的相同路径，重建镜像保留这些数据。服务通过 Docker 补充组访问 socket，不添加永久组成员、不放宽 socket 权限、不使用特权容器。应用镜像构建及应用容器使用宿主网络以保留回环地址和本机代理行为；安装时已有的 HTTP(S)_PROXY 通过 Docker 专用构建参数传入，不写入运行环境。网页绑定 `0.0.0.0:8080`，通过 `http://服务器内网IP:8080` 访问并登录；防火墙开放范围由服务器管理员配置。

构建先完成再停止旧服务，更新前后均检查有无活动扫描；有任务时保留旧服务。新镜像必须通过非 root 解析器检查与 Docker 构建、Compose 运行、资源清理检查才能安装。启动后核对镜像 ID、进程 UID、实际程序内容与监听端口。systemd 使用 219 兼容语法，开机启动时先按正常停止流程回收本服务遗留的容器，等待删除完成后再运行 Docker 检查和新程序，避免容器名称冲突。其他容器不会因此被停止。

```sh
bash scripts/install-centos7.sh --dry-run   # 仅查看计划
bash scripts/install-centos7.sh --check     # 复查已安装服务，不调用模型
systemctl status vulscan
journalctl -u vulscan -f
```

**CentOS 7 已于 2024-06-30 停止维护，以上 Docker 版本也没有当前安全维护。** 容器共享宿主机内核，不能把旧内核变成 Node 22 的官方支持平台；部署会实际运行解析器与 Docker 检查，兼容性失败时明确停止，不关闭 seccomp/SELinux、不升级或自动重启宿主机。若原 Docker 已启用容器 SELinux 隔离，需要管理员先配置访问 socket 的专用策略，脚本会报出原因而不关闭隔离。需要联网下载官方 RPM、Docker Hub 基础镜像、Ubuntu 包及语言依赖；下载失败可修复网络后重试原命令。

来源：[CentOS 7 停止维护说明](https://www.redhat.com/en/topics/linux/centos-linux-eol)、[Docker 官方 EL7 归档](https://download.docker.com/linux/centos/7/x86_64/stable/Packages/)、[Node 22 平台要求](https://github.com/nodejs/node/blob/v22.x/BUILDING.md#platform-list)。

## 多用户工作台与 HTTPS

新用户打开工作台即可注册账号，注册完成后自动登录；无需初始化口令或创建管理员。已有账号直接登录。每个账号在“用户设置”单独配置服务商、模型与 API 密钥，不继承服务器的 CLI 配置或其他账号的密钥。扫描页输入的临时密钥仍仅用于该任务。

旧账号、会话和扫描文件保留。旧版本已绑定的历史任务仍由原账号访问；未绑定的匿名历史文件留在原目录，不自动分配给新注册账号。

账号与会话保存在 `~/.vulscan/webui/.access/accounts.json`，个人模型配置在该目录下的 `users/<用户ID>/vulscan/config.json`；目录权限 0700、敏感文件 0600。备份整个服务账号的 `.vulscan`，并保留文件所有权与权限。密码使用带独立随机盐的 PBKDF2-HMAC-SHA256（600,000 次），会话凭据只存摘要，登录保持 7 天，退出即时撤销；修改密码会撤销其他会话。所有任务页面、接口、SSE、报告和下载都检查任务归属。共享的四个执行槽位和原扫描、Docker 清理流程保持一致。

新注册账号只扫描 HTTP(S) 仓库，不读取服务账号的 Git 凭据或服务器本机项目路径；旧账号已有的访问权限保留。共享服务器的 Web 账号用于受信任的内网团队，Docker 动态测试仍采用现有隔离方式；账号权限隔离不等同于为任意不受信任代码提供宿主机隔离。

内网 IP 的 HTTP 访问可直接使用登录功能；HTTP 不加密密码与密钥，公网或域名部署使用 HTTPS 反向代理，并显式固定外部地址：

```sh
./bin/vulscan serve --addr 127.0.0.1:8080 --external-url https://scan.example.com
```

代理需保留原始 `Host`，关闭 SSE 响应缓冲并允许长连接。服务不信任客户端传来的 `X-Forwarded-*`，配置 HTTPS 外部地址后 Cookie 自动启用 `Secure`，同时保留 `HttpOnly`、`SameSite=Lax` 和每会话 CSRF 校验。CSP 不增加外网权限。

systemd 部署可用 `sudo systemctl edit vulscan` 添加下列配置；CentOS 7 容器入口也会接收此变量，重新部署保留 drop-in。待扫描结束后重启服务：

```ini
[Service]
Environment=VULSCAN_EXTERNAL_URL=https://scan.example.com
```

```sh
sudo systemctl daemon-reload
sudo systemctl restart vulscan
```

重复部署通过仅允许本机访问的 `/internal/status` 检查所有用户的活动任务，使用服务账号目录里的独立部署凭据，不依赖某个用户的首页计数；有任务或无法确认状态时拒绝停止服务。部署凭据不对 Web 用户提供。

实现参考 [AutoCVE 用户配置与归属检查](https://github.com/larlarua/AutoCVE/tree/main/backend/app)，沿用本项目的 Go 模板、原生 JavaScript、SSE 和文件存储，没有引入数据库或新的 Web 运行服务。

## 构建与启动（Linux/macOS）

需要 Python 3.11+（含 venv/ensurepip）、Git 2.32+、Go 1.26+、Node.js 20 或 22+、npm 7+，以及依赖下载网络。安装器会用 `npm ci --engine-strict` 按解析器 package-lock 安装 JavaScript/TypeScript 依赖（Node 21 不符合锁文件要求）。Go 扫描会构建 Go 解析器。动态测试另需 Docker。离线部署需提前准备这些依赖；此包不是独立静态二进制。

```sh
tar -xzf 911VulScan-source.tar.gz
cd 911VulScan
sh scripts/install-deployment.sh
./bin/vulscan --help
./bin/vulscan setup
./bin/vulscan serve
```

保留整个部署目录：`bin/`、`.venv/`、`.tools/`（若存在）、`config/`、`libs/vulscan-core/` 必须共同存在。不要单独复制二进制；Go CLI 还需要相邻目录的语言/模型注册表。安装虚拟环境不可直接跨机器搬移。本版只提供新命令 `vulscan`、Python 包 `vulscan` 和 `VULSCAN_*` 环境变量；配置目录为 `~/.config/vulscan/`，运行数据目录为 `~/.vulscan/`。不提供旧命令、旧环境变量或旧配置的自动兼容/迁移，也不会删除已有旧数据。

便携部署版本不支持 `uninstall` 自动清理；停止服务后，确认不再需要再删除部署目录。用户配置和扫描结果在上述新用户目录，需单独备份和处理。

在开发仓库生成部署包：`python3 scripts/package-deployment.py`。包不含测试、CI、缓存、开发设计文档、示例扫描结果或密钥。不要向包中加入个人配置、API Key、虚拟环境或扫描产物。

## Ubuntu 自动补齐依赖

默认命令仍是**不使用 sudo 的应用安装**。`--check` 只检查本机依赖，缺失时返回非零；`--dry-run` 只显示计划，不下载、不创建文件、不执行 sudo。该入口自动补齐支持 Ubuntu **20.04、22.04、24.04、26.04** 的 x86_64/arm64；CentOS 7 使用上面的独立入口，其他发行版/架构请手动准备依赖。

```sh
sh scripts/install-deployment.sh --check
sh scripts/install-deployment.sh --install-deps --dry-run
# 交互确认后执行；Docker 安装脚本可能启动服务，须单独同意：
sh scripts/install-deployment.sh --install-deps --start-docker
# 自动化环境须明确同意计划；仅补依赖可追加 --deps-only：
sh scripts/install-deployment.sh --install-deps --start-docker --yes
```

### Ubuntu 20.04 特别说明

20.04 的系统 Python 3.8 不满足项目要求。安装器保留系统 Python，使用 python.org 源码与固定 SHA-256 编译 Python **3.12.16** 到部署目录 `.tools/python`，使用 `make altinstall`，再建立 `.venv`。22.04 的默认 Python 3.10 同样使用该流程。源码编译需要时间、磁盘与约两个编译任务的内存；安装器会先列出并征得同意后安装 APT 编译依赖。24.04/26.04 则使用发行版 Python/venv。已满足要求的 Python 会复用；可用 `PYTHON=/path/to/python3.12` 指定解释器。

**Docker 官方已经停止支持 Ubuntu 20.04。推荐升级 Ubuntu。** 仅使用 `--install-deps` 时不会自动接受 20.04 的冻结 Docker；`--deploy` 已包含该选项的授权。若已经有完整的 Engine、Compose v2、Buildx，会复用；若 Engine/CLI 正常、只缺 Buildx 或 Compose，则只补齐缺少的用户级 CLI 插件，不走冻结 Engine 软件包流程（见下节）。只有 Engine/CLI 缺失且你理解没有当前安全维护的风险并显式同意，才安装 Docker 官方仍保留的 Focal 软件包：Engine/CLI 28.1.1、containerd 1.7.27、Compose 2.35.1、Buildx 0.23.0。它们不是最新受支持版本。

```sh
# Ubuntu 20.04：先看计划；决定接受冻结版本后才执行第二条。
sh scripts/install-deployment.sh --install-deps --dry-run
sh scripts/install-deployment.sh --install-deps --allow-unsupported-docker --start-docker
# 非交互操作再加 --yes；不接受此风险请升级系统或自行配置 Docker。
```

### 已有 Docker，只补缺少的插件

安装器分别检测 **Engine/CLI、Compose、Buildx**。例如 Ubuntu 20.04 已有 Docker 26.1.3、Compose 5.5.1，但没有 Buildx：只安装 Buildx，不替换 Engine、不降级 Compose、不启停服务，也不要求 `--allow-unsupported-docker` 或 `--start-docker`。

```sh
sh scripts/install-deployment.sh --install-deps --dry-run
sh scripts/install-deployment.sh --install-deps --yes
# 只补依赖、不重装应用：追加 --deps-only
```

缺失的插件来自 Docker 官方 GitHub release：Buildx **0.38.1**、Compose **5.5.1**（只安装实际缺失者），校验官方 `checksums.txt` 后写入 `${DOCKER_CONFIG:-$HOME/.docker}/cli-plugins/`。该分支本身不执行 APT/sudo，也不改 Docker `config.json`、凭据或全局插件；其他缺失依赖仍可能需要计划中显示的 APT 操作。需要系统已有 curl 和 sha256sum。Buildx 文档声明最低 Engine 19.03；安装后验证 `docker buildx version`，这不等于已验证所有 daemon/build 功能。

已存在但不能正常运行的同名用户插件不会被覆盖；请检查错误并自行移走后重试。安装后 Docker 若仍未发现插件（例如额外插件目录遮蔽）或运行失败，安装器会明确报错，不会修改 Docker 配置强行修复。Docker CE 的残留配置记录不视为已安装；即使 Engine 包来源混杂，只补用户插件也不会因此强行替换或阻塞现有 Engine。

Go 使用官方元数据中最新稳定 **1.26.x**；Node.js 使用官方 **22.x LTS**（自带 npm）。下载后先验证 SHA-256，再解压到 `.tools/go`、`.tools/node`，启动器将这些目录加入自身 PATH，不改系统 PATH 或 shell 配置。已有合格版本优先复用。若 `.tools` 中存在不合格/未完成安装目录，安装器不会覆盖，请自行检查并移走后重试。

Docker 在 22.04/24.04/26.04 使用已配置的可信 Ubuntu APT 仓库中的 `docker.io`、`docker-compose-v2`、`docker-buildx`；这些包可能需要启用官方 `universe`/updates。仅使用 `--install-deps` 时不自行添加仓库/PPA；`--deploy` 会按需启用官方 Ubuntu `universe` 组件。20.04 冻结版本从 Docker 官方 HTTPS 仓库读取 Focal 元数据并验证每个 `.deb` 的 SHA-256，再由 APT 解析依赖，不添加新的 APT 信任密钥或源。APT 禁止自动移除包；只有需要安装 Engine/CLI 时，发现 Docker CE、Podman shim 或其他冲突安装才会报错，而不是替换、降级或迁移；用户级插件补齐不受此包迁移检查阻塞。

所有系统安装先显示计划；非交互需要 `--yes`。Docker 包的维护脚本可能启动/启用服务，所以安装它必须另加 `--start-docker`；该选项也允许执行 `systemctl start docker`。不会添加用户到拥有 root 等价权限的 `docker` 组，不修改 daemon 配置、socket 权限或凭据。Docker daemon 的可访问性应由管理员按部署环境检查，`--check` 不需要连接 daemon。无 systemd 的容器/WSL 环境应自行配置 Docker 后再运行默认安装。

来源：[Git 官方源代码与校验值](https://www.kernel.org/pub/software/scm/git/)、[Python 3.12.16 校验值](https://www.python.org/downloads/release/python-31216/)、[Go 官方下载元数据](https://go.dev/dl/?mode=json)、[Node.js 官方发行目录](https://nodejs.org/dist/)、[Docker Ubuntu 支持说明](https://docs.docker.com/engine/install/ubuntu/)、[Buildx 0.38.1](https://github.com/docker/buildx/releases/tag/v0.38.1)、[Compose 5.5.1](https://github.com/docker/compose/releases/tag/v5.5.1)。SHA-256 来自固定 Python 官方发布校验值或官方 HTTPS 元数据，并非宣称已额外验证独立签名。

## 许可与来源

911VulScan 基于 Knostic OpenAnt 开源项目进行了品牌、中文交互与功能调整。原始版权和 Apache-2.0 许可见 `LICENSE`；第三方前端资源的来源记录位于 `apps/vulscan-cli/{ui,internal/report}/vendor/SOURCES.txt`，资源内许可声明保持原样。产品品牌调整不改变原作者权利或第三方许可。
