# 911VulScan 最小部署包

部署包只含运行代码、构建依赖清单、运行时提示词、必要配置和许可证；开发仓库继续保留测试与 CI。

## 全新 Ubuntu 服务器一键部署

Ubuntu **20.04、22.04、24.04**（也支持 26.04），x86_64/arm64，使用 root 或具有 sudo 权限的用户执行：

```sh
tar -xzf 911VulScan-source.tar.gz
cd 911VulScan
sh scripts/install-deployment.sh --deploy
```

该命令补齐 Python、Git、Go、Node/npm、编译工具、Docker Engine、Compose 和 Buildx，安装 Python 与 JavaScript 依赖，并构建 CLI。它用本地样例实际检查全部已启用语言的解析器，再由服务启动检查 Docker 构建、Compose 执行和测试资源清理；这些检查不调用模型。只有服务处于运行状态且网页响应正常，才显示部署完成。

服务通过 **vulscan.service** 开机自启，使用安装用户及 Docker 补充组运行，不修改用户组、系统 Python、Docker daemon 配置或已有凭据。默认地址为 `http://127.0.0.1:8080`。从另一台电脑访问时，先建立 SSH 转发：

```sh
ssh -N -L 8080:127.0.0.1:8080 用户名@服务器地址
# 然后在本机浏览器打开 http://127.0.0.1:8080
```

在网页中填写模型 API Key 后即可扫描。安装器不能代为提供账户余额或 API 权限；被扫描项目特有的依赖由动态测试 Docker 构建流程安装。CLI 动态测试同样需要当前会话具备 Docker 访问权限，systemd 服务的补充组不会改变交互式会话权限。

```sh
systemctl status vulscan
journalctl -u vulscan -f
# 只查看完整计划，不安装、不启动：
sh scripts/install-deployment.sh --deploy --dry-run
```

一键模式会在需要时启用官方 Ubuntu `universe` 组件。20.04 自带的 Git 2.25 不满足扫描所需的隔离选项，安装器将校验并编译已测试的 Git 2.56.x 维护分支到 `.tools/git`（使用上游支持的 `NO_RUST` 纯 C 构建）；20.04/22.04 使用本地 Python 3.12.16，均保留系统版本。工具下载遇到连接重置、超时、限流或临时服务错误时最多尝试 3 次，404、证书错误与校验失败直接报错。虚拟环境内的 pip 升级至 25.3+，依赖下载采用 60 秒读取时限和最多 3 次续传重试。

**20.04 的 Docker 已停止上游支持。** `--deploy` 包含安装下文所列官方保留冻结版本的授权，会明确显示版本；需要仍受上游支持的 Docker 时应使用 22.04/24.04。已有完整 Docker 会复用，其他来源的冲突安装不会被强制移除。已有自行配置的 `vulscan.service` 也不会被覆盖。一键模式要求系统实际运行 systemd；容器环境可使用下述仅安装应用的方式。

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

默认命令仍是**不使用 sudo 的应用安装**。`--check` 只检查本机依赖，缺失时返回非零；`--dry-run` 只显示计划，不下载、不创建文件、不执行 sudo。自动补齐支持 Ubuntu **20.04、22.04、24.04、26.04** 的 x86_64/arm64；其他发行版/架构请手动准备依赖。

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
