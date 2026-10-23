# 911VulScan 最小部署包

部署包只含运行代码、构建依赖清单、运行时提示词、必要配置和许可证；开发仓库继续保留测试与 CI。

## 构建与启动（Linux/macOS）

需要 Python 3.11+（含 venv/ensurepip）、Go 1.26+、Node.js 20 或 22+、npm 7+，以及依赖下载网络。安装器会用 `npm ci --engine-strict` 按解析器 package-lock 安装 JavaScript/TypeScript 依赖（Node 21 不符合锁文件要求）。Go 扫描会构建 Go 解析器。动态测试另需 Docker。离线部署需提前准备这些依赖；此包不是独立静态二进制。

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

20.04 的系统 Python 3.8 不满足项目要求。安装器保留系统 Python，使用 python.org 源码与固定 SHA-256 编译 Python **3.12.15** 到部署目录 `.tools/python`，使用 `make altinstall`，再建立 `.venv`。22.04 的默认 Python 3.10 同样使用该流程。源码编译需要时间、磁盘与约两个编译任务的内存；安装器会先列出并征得同意后安装 APT 编译依赖。24.04/26.04 则使用发行版 Python/venv。已满足要求的 Python 会复用；可用 `PYTHON=/path/to/python3.12` 指定解释器。

**Docker 官方已经停止支持 Ubuntu 20.04。推荐升级 Ubuntu。** 安装器不会默认为 20.04 安装已冻结的 Docker。若已经有完整的 Engine、Compose v2、Buildx，会复用；若 Engine/CLI 正常、只缺 Buildx 或 Compose，则只补齐缺少的用户级 CLI 插件，不走冻结 Engine 软件包流程（见下节）。只有 Engine/CLI 缺失且你理解没有当前安全维护的风险并显式同意，才安装 Docker 官方仍保留的 Focal 软件包：Engine/CLI 28.1.1、containerd 1.7.27、Compose 2.35.1、Buildx 0.23.0。它们不是最新受支持版本。

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

Docker 在 22.04/24.04/26.04 使用已配置的可信 Ubuntu APT 仓库中的 `docker.io`、`docker-compose-v2`、`docker-buildx`；这些包可能需要启用官方 `universe`/updates。安装器不自行添加仓库/PPA。20.04 冻结版本从 Docker 官方 HTTPS 仓库读取 Focal 元数据并验证每个 `.deb` 的 SHA-256，再由 APT 解析依赖，不添加新的 APT 信任密钥或源。APT 禁止自动移除包；只有需要安装 Engine/CLI 时，发现 Docker CE、Podman shim 或其他冲突安装才会报错，而不是替换、降级或迁移；用户级插件补齐不受此包迁移检查阻塞。

所有系统安装先显示计划；非交互需要 `--yes`。Docker 包的维护脚本可能启动/启用服务，所以安装它必须另加 `--start-docker`；该选项也允许执行 `systemctl start docker`。不会添加用户到拥有 root 等价权限的 `docker` 组，不修改 daemon 配置、socket 权限或凭据。Docker daemon 的可访问性应由管理员按部署环境检查，`--check` 不需要连接 daemon。无 systemd 的容器/WSL 环境应自行配置 Docker 后再运行默认安装。

来源：[Python 3.12.15 校验值](https://www.python.org/downloads/release/python-31215/)、[Go 官方下载元数据](https://go.dev/dl/?mode=json)、[Node.js 官方发行目录](https://nodejs.org/dist/)、[Docker Ubuntu 支持说明](https://docs.docker.com/engine/install/ubuntu/)、[Buildx 0.38.1](https://github.com/docker/buildx/releases/tag/v0.38.1)、[Compose 5.5.1](https://github.com/docker/compose/releases/tag/v5.5.1)。SHA-256 来自固定 Python 官方发布校验值或官方 HTTPS 元数据，并非宣称已额外验证独立签名。

## 许可与来源

911VulScan 基于 Knostic OpenAnt 开源项目进行了品牌、中文交互与功能调整。原始版权和 Apache-2.0 许可见 `LICENSE`；第三方前端资源的来源记录位于 `apps/vulscan-cli/{ui,internal/report}/vendor/SOURCES.txt`，资源内许可声明保持原样。产品品牌调整不改变原作者权利或第三方许可。
