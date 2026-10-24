# 动态漏洞验证

读取 `pipeline_output.json`，为可动态测试的发现生成复现程序，在 Docker 沙箱中构建、运行并保存结果。生成阶段使用当前配置的 `dynamic_test` 模型，不绑定特定厂商。自然语言输出采用简体中文，JSON 字段和状态枚举保持稳定。

## 前提与调用

- 已安装并启动 Docker Engine；生产路径不会改为在宿主机直接运行目标代码。
- 已配置模型服务凭据。生成及重试可能产生模型费用。
- 已有静态分析结果；仅对 `DYNAMIC_TESTABLE` 范围内的发现进行验证。
- C/C++ 必须提供真实仓库路径。仓库按原目录结构预置于构建上下文的 `repository/`，包括头文件、兄弟模块、资源和依赖清单；排除版本控制目录、本机环境、已安装依赖和凭据文件。

```bash
# 常规命令（活动项目自动提供仓库路径）
vulscan dynamic-test /path/to/pipeline_output.json --repo-path /path/to/repository

# Python 模块入口
python -m utilities.dynamic_tester /path/to/pipeline_output.json \
  --repo-path /path/to/repository --output-dir /tmp/dynamic-results
```

网页的“Docker 构建代理 IP / 代理端口”均为可选项：全部留空时使用 Docker 现有网络配置；本机 mihomo 可填 `127.0.0.1` 和 HTTP/mixed 端口（例如 `7890`）。命令行 `scan` 和 `dynamic-test` 对应 `--docker-proxy http://127.0.0.1:7890`。代理只供构建期间下载依赖，不传入运行漏洞测试的容器。环回代理通过仅在构建期间存在的 Docker bridge 转发访问，无需修改 mihomo 配置或重启 Docker。基础镜像拉取仍使用 Docker daemon 自身的网络配置。

## 构建环境

二阶段把“宿主环境”从单条发现的构建里拆出来（`utilities/docker_build/`），执行器只负责编排：

| 关注点 | 位置 | 说明 |
| --- | --- | --- |
| 代理 | `docker_build/proxy.py` | 校验 `http://IP:端口`；留空即直连；回环代理经 bridge 中继，端口固定复用，避免代理地址变化让 BuildKit 缓存层失效 |
| 工具链 | `docker_build/toolchain.py` | C/C++ 编译器预置为共享镜像 `vulscan/toolchain-c:gcc12-<内容摘要>`，一次构建、全部发现复用；镜像不带 owner/run 标签，按发现回收时不会被删除 |
| 时间预算 | `docker_build/policy.py` | 构建/执行/工具链三档预算与失败分类的唯一来源，可用 `VULSCAN_DOCKER_BUILD_TIMEOUT`、`VULSCAN_DOCKER_RUN_TIMEOUT`、`VULSCAN_DOCKER_TOOLCHAIN_TIMEOUT` 覆盖（秒，正整数） |
| 预检 | `docker_build/preflight.py` | 在花费模型调用之前检查守护进程、buildx 与代理可达性，宿主问题只报一次 |

失败分类决定是否让模型重写测试：构建失败、运行时异常按可修复处理；构建超时、容器执行超时、环境/工具链不可用、资源回收失败都停止重试，并在日志中写明原因（旧版本把构建超时一并说成“执行超时”）。构建超时的诊断会明确标注“Docker 构建超时”，与容器执行超时（`INCONCLUSIVE`）分开。

```python
from utilities.dynamic_tester import run_dynamic_tests
results = run_dynamic_tests(
    "/path/to/pipeline_output.json",
    output_dir="/tmp/dynamic-results",
    repo_path="/path/to/repository",
)
```

输出包括中文 `DYNAMIC_TEST_RESULTS.md`、机器可读 `dynamic_test_results.json` 以及可恢复的逐项检查点。动态验证不会证明仓库整体安全。

## C/C++ 模板

语言注册表将 C/C++ 路由到 `c.Dockerfile`。`.c` 使用 GCC/C11；`.cpp`、`.cc`、`.cxx`、`.hpp`、`.hh`、`.hxx` 和 `.C` 使用 G++/C++17。无明确扩展名时接受 `c`、`c++`、`cpp`、`cxx`、`c/c++`；`.h` 使用扫描语言作区分。其他可识别语言的文件不会因为扫描默认值是 C 而错误进入该模板。

C/C++ 生成结果只能提供复现源码，执行器强制使用项目自带的 Dockerfile、Python 包装器和编译命令。模型不能替换运行器或关闭 sanitizer。复现程序应引入并调用已预置的真实目标文件，构造攻击输入，并在正常结束时打印结构化结果。

工具链镜像基于 `python:3.12-slim-bookworm`，安装 GCC、G++ 和 libc 开发头文件（配方见 `docker_templates/toolchain-c/Dockerfile`）。`c.Dockerfile` 只声明 `FROM <该镜像>`，因此每条发现的构建只复制文件，不会重复下载编译器。包装器执行真实编译：

```text
gcc -std=c11 -O1 -g -fno-omit-frame-pointer -fsanitize=address,undefined \
    -fno-sanitize-recover=all -fno-pie -no-pie -x c test_exploit.c -o /tmp/.../test_exploit -lm
```

C++ 使用 `g++ -std=c++17 -x c++`。编译最多 60 秒，程序执行最多 30 秒；产物及运行时文件仅写入 `/tmp`。禁用 LeakSanitizer，避免受限容器中的 ptrace 兼容问题；当前不提供内存泄漏检测保证。

### 支持边界

- 当前是单编译单元、标准库复现；不会自动运行整个项目的 CMake、Make 或自定义脚本。
- 预置仓库内头文件并保留相对路径。缺失外部头文件、额外链接库或特定编译参数会明确返回 `ERROR`，不能当作“未复现”；确定的目标依赖缺失会停止模型重试。
- 缺少真实目标文件、文件名与固定 scaffold 冲突、无法启动编译器、sanitizer 初始化失败，也都返回 `ERROR`。
- C/C++ 多容器依赖和自定义依赖安装目前不受支持；生成器会拒绝这类结果。
- 当前 C11/C++17 是可复现测试环境的固定基线，不代表已复现目标项目原有的编译器、平台或 ABI。
- 动态诊断应结合原发现和目标调用栈复核；自动生成的驱动仍可能存在逻辑错误。

## Python、JavaScript/TypeScript 与 Go

保持现有“模型生成 Dockerfile → 容器构建 → 隔离执行 → 结果收集”流程，只按发现所在文件附加对应语言的构建规则和参考模板：

- Python：标准库不安装为 PyPI 包；无外部依赖时允许不生成 requirements.txt。直接导入或显式路径加载真实单文件，核对目标身份；不伪造缺失包。关闭字节码写入并启用无缓冲输出，保留退出前日志。
- JavaScript/TypeScript：明确 CommonJS/ESM 扩展名和 package.json type；构建阶段保留 devDependencies 供 TypeScript 编译，不在容器运行时使用 npm/npx 下载依赖。TypeScript 必须按实际模块/JSX 需求编译，不能把任意源码直接交给 Node。
- Go：采用声明工具链；无声明时参考模板使用 Go 1.26。源码布局准备完成后再初始化模块、解析依赖和编译；同包目标与 harness 一起构建，库包放入独立目录。固定 GOTOOLCHAIN=local，构建产物和依赖缓存不放在运行时会被 tmpfs 覆盖的位置；运行阶段只启动已编译二进制。
- 运行时声明从仓库根目录已有清单读取，只接受受限版本语法；无法可靠解析的约束不猜测。不会执行项目脚本来推断版本。

原仓库位于 `repository/`，生成的测试和依赖清单位于其外部，不能覆盖真实目标。生成器获得文件列表及原始根目录依赖清单，Dockerfile 需据此按实际包布局调整；私有依赖和项目专用构建参数仍需显式提供。上下文超过 10000 个文件或 100 MiB、不可读或包含越界链接时明确失败，不静默丢弃依赖。通用构建失败保留 stdout 与 stderr；超时保留已捕获的输出，运行超时仍是 INCONCLUSIVE。

## 结果含义

| 机器状态 | 中文含义 |
| --- | --- |
| `CONFIRMED` | 通用模板验证攻击证据；C/C++ 模板仅在具体 ASan/UBSan 诊断指向真实目标且程序错误终止时自动确认 |
| `NOT_REPRODUCED` | 测试完成，但本次输入未复现；不等于证明安全 |
| `BLOCKED` | 攻击被目标控制措施阻止 |
| `INCONCLUSIVE` | 超时、普通异常退出、只有 `DEADLYSIGNAL` 或缺少明确结果 |
| `ERROR` | 生成、构建、编译、配置或执行环境出错 |
| `SKIPPED` | 对应语言没有动态测试模板，未执行 |

正常退出且无 JSON 不能推断 `NOT_REPRODUCED`。构建输出、一般崩溃、sanitizer 启动失败不能自动确认漏洞。sanitizer 首个目标/驱动源码位置若指向驱动，或未匹配真实目标文件，则为 `INCONCLUSIVE`；空证据的 `CONFIRMED` 同样降为 `INCONCLUSIVE`。C/C++ 程序自行打印的 `CONFIRMED` 即使附带非空证据，也会降为 `INCONCLUSIVE` 并保留证据，供人工复核；当前模板不自动确认缺少 sanitizer 佐证的逻辑漏洞。sanitizer 形式的日志若伴随正常退出，同样不能确认。容器以非零状态退出时，结果收集器不会采信此前打印的成功 JSON。

这些门槛用于减少误报，不是不可伪造的证据来源证明。生成的驱动或目标仍可能伪造诊断文本、源文件位置并主动以非零状态退出。重要结论必须人工检查驱动是否真正调用目标、完整诊断与原始发现是否对应，并在可信环境复现；自动状态不能替代人工证据审核。

```json
{"status":"NOT_REPRODUCED","details":"越界输入被拒绝，本次未复现。","evidence":[]}
```

## 隔离边界

单容器使用无外部网络、只读根文件系统、移除全部 capabilities、禁止新增权限及进程/内存/CPU 限额；没有宿主卷挂载或特权模式。多容器路径重建 compose 白名单并使用内部网络。构建阶段仍可能下载基础镜像与公开依赖；这不是完全离线构建。

不要在宿主机直接运行生成的 C/C++ 程序。`docker_templates/c_runner.py` 是容器内部组件，只有回归测试会在本机编译仓库自带、已审阅的 fixture。

## 离线回归验证

```bash
cd libs/vulscan-core
python -m pytest tests/test_dynamic_c_templates.py tests/test_dynamic_tester_language.py tests/test_docker_scaffold.py -q
```

测试分别覆盖真实 C/C++ 漏洞版和修复版编译执行、UBSan、编译失败、超时、无效 JSON，以及模拟 Docker 的文件预置和安全参数。若本机没有编译器，对应原生测试明确跳过。Docker 接线 mock 通过不等于真实 Docker 镜像构建或容器集成已通过。
