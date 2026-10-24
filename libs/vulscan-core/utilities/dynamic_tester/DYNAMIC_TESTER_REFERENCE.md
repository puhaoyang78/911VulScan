# 动态测试开发参考

## 主要文件

| 文件 | 职责 |
| --- | --- |
| `__init__.py` | 按发现调度、恢复检查点、重试与结果落盘 |
| `test_generator.py` | 解析语言、构造生成提示、校验模型输出 |
| `docker_executor.py` | 隔离目录预置、Docker 构建执行、资源清理 |
| `result_collector.py` | 校验结构化结果并保留发现 identity_key |
| `models.py` | 稳定结果字段与状态枚举 |
| `reporter.py` | 中文 Markdown 报告 |
| `docker_templates/c_runner.py` | 容器内部真实 C/C++ 编译、执行和 sanitizer 证据收集 |

## 模板基线

| 模板 | 基础镜像 |
| --- | --- |
| `python.Dockerfile` | `python:3.11-slim` |
| `node.Dockerfile` | `node:24-slim` |
| `go.Dockerfile` | `golang:1.26-alpine` |
| `c.Dockerfile` | `python:3.12-slim-bookworm`，安装 GCC/G++/libc 头文件 |

其他语言仍按语言注册表解析。C/C++ 固定模板由程序强制应用，不能通过模型输出自定义 Dockerfile。Python/Node/Go 的既有生成路径保持原有模型生成方式。

## C/C++ 数据流

1. `resolve_docker_template` 按发现文件扩展名优先解析，未知扩展名才回退到扫描语言。
2. `resolve_native_language` 区分 `c` 与 `cpp`，生成提示要求真实源码及中文结果。
3. `_finalize_native_generation` 固定 Dockerfile、文件名和 `native_language`，拒绝未支持的依赖或 compose。
4. 调度器把发现源路径限制在仓库根目录内，阻止 `..`、绝对路径和符号链接逃逸。
5. `source_context.py` 统一描述并预置 `repository/`，保留本地头文件、模块和依赖清单；`_write_native_test_files` 写入复现源码、自带运行器和固定 JSON 配置，目标路径指向原仓库文件；冲突或缺失明确失败。
6. Docker 运行器在容器内编译到 `/tmp` 并执行，stdout 只输出结构化结果。
7. 结果收集器校验对象类型，保留身份键、证据、生成代码和用量数据；非零容器退出不能伪装成功。

编译命令包含 ASan/UBSan、不可恢复模式、调试信息和 frame pointer。普通崩溃或泛化 `DEADLYSIGNAL` 只标记 `INCONCLUSIVE`；已知 sanitizer 启动失败为 `ERROR`。具体运行时缺陷诊断只有在首个目标/驱动源码位置匹配真实目标路径，且程序以非零状态错误终止时才保留调用栈并标记 `CONFIRMED`；只有驱动缺陷或无法匹配目标路径则为 `INCONCLUSIVE`。生成程序自行输出的 `CONFIRMED` 无论证据是否非空，若没有上述 sanitizer 佐证，一律降为 `INCONCLUSIVE` 并保留原证据。正常退出时打印 sanitizer 形式的文本也不能确认。

这是保守的自动分类，不是可信执行证明：不受信任的程序仍可伪造诊断与源码位置并主动非零退出。人工审核需核实真实目标调用、驱动代码、原始诊断和漏洞对应关系；当前模板不以自报 JSON 自动确认逻辑漏洞。

## 错误与恢复

机器状态、JSON 字段名及错误分类键保持不变。新详情使用中文；错误分类器同时识别旧英文检查点与新中文详情。`ERROR` 可在恢复时重试，缺少 Docker 可执行文件或预置配置错误不会在同一次运行中继续消耗模型重试。

## 验证范围

`tests/test_dynamic_c_templates.py` 中的原生测试只编译固定自有 fixture。它们验证真实 C 和 C++ 的缺陷/修复对照及诊断分类。Docker 文件预置和命令参数使用 mock 测试；发布前仍应在有 Docker 的环境单独执行真实镜像构建与容器验证。生产代码没有“Docker 不可用时在宿主直接执行”的降级路径。

更多调用方式、安全边界和支持限制见 [README.md](README.md)。
