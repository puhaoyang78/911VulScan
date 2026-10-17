# 动态漏洞验证

读取 `pipeline_output.json`，为可动态测试的发现生成复现程序，在 Docker 沙箱中构建、运行并保存结果。生成阶段使用当前配置的 `dynamic_test` 模型，不绑定特定厂商。自然语言输出采用简体中文，JSON 字段和状态枚举保持稳定。

## 前提与调用

- 已安装并启动 Docker Engine；生产路径不会改为在宿主机直接运行目标代码。
- 已配置模型服务凭据。生成及重试可能产生模型费用。
- 已有静态分析结果；仅对 `DYNAMIC_TESTABLE` 范围内的发现进行验证。
- C/C++ 必须提供真实仓库路径；单文件对应的源文件会先复制到隔离构建目录。

```bash
# 常规命令（活动项目自动提供仓库路径）
openant dynamic-test /path/to/pipeline_output.json --repo-path /path/to/repository

# Python 模块入口
python -m utilities.dynamic_tester /path/to/pipeline_output.json \
  --repo-path /path/to/repository --output-dir /tmp/dynamic-results
```

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

容器基于 `python:3.12-slim-bookworm`，安装 GCC、G++ 和 libc 开发头文件。包装器执行真实编译：

```text
gcc -std=c11 -O1 -g -fno-omit-frame-pointer -fsanitize=address,undefined \
    -fno-sanitize-recover=all -fno-pie -no-pie -x c test_exploit.c -o /tmp/.../test_exploit
```

C++ 使用 `g++ -std=c++17 -x c++`。编译最多 60 秒，程序执行最多 30 秒；产物及运行时文件仅写入 `/tmp`。禁用 LeakSanitizer，避免受限容器中的 ptrace 兼容问题；当前不提供内存泄漏检测保证。

### 支持边界

- 当前是单编译单元、标准库复现；不会自动运行整个项目的 CMake、Make 或自定义脚本。
- 仅预置发现所在的一个目标文件；缺失本地头文件、额外链接库或特定编译参数会明确返回 `ERROR`，不能当作“未复现”。
- 缺少真实目标文件、文件名与固定 scaffold 冲突、无法启动编译器、sanitizer 初始化失败，也都返回 `ERROR`。
- C/C++ 多容器依赖和自定义依赖安装目前不受支持；生成器会拒绝这类结果。
- 当前 C11/C++17 是可复现测试环境的固定基线，不代表已复现目标项目原有的编译器、平台或 ABI。
- 动态诊断应结合原发现和目标调用栈复核；自动生成的驱动仍可能存在逻辑错误。

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
cd libs/openant-core
python -m pytest tests/test_dynamic_c_templates.py tests/test_dynamic_tester_language.py tests/test_docker_scaffold.py -q
```

测试分别覆盖真实 C/C++ 漏洞版和修复版编译执行、UBSan、编译失败、超时、无效 JSON，以及模拟 Docker 的文件预置和安全参数。若本机没有编译器，对应原生测试明确跳过。Docker 接线 mock 通过不等于真实 Docker 镜像构建或容器集成已通过。
