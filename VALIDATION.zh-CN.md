# 911-dev 验证记录

## 动态验证错误反馈修复（2026-10-17）

本轮基线为 `6902b98df5ebc54c5ba361813b1cca0a384b9f7a`。只修复动态测试失败后的反馈、重试与记账，不调整扫描阶段顺序、stage2 候选筛选、判定枚举或 C/C++ 支持范围。

- 将结构化 `ERROR` 的 evidence 和标准错误一并传给下一次修复提示，覆盖 C/C++ 运行器“进程退出码为 0、JSON 报编译失败”的情况。
- 错误反馈限制为 6,000 字符以内。长诊断保留开头和结尾、显式标记截断；编译器输出、结果收集和提示构建三个环节不再只截取前缀。反馈沿用凭据脱敏规则，并使用独立安全围栏；原测试代码、Dockerfile 和 Compose 配置可供核对。
- 只对 `ERROR` 进行有界修复。只有执行配置和原始失败输出均完全重复时才提前停止；代码或依赖变更、错误变化均可继续尝试。停止后仍保留 `ERROR`，不会变为“安全”或“已确认”。
- 单项修复调用抛异常或返回无效内容时，保留最后执行的代码和证据，记录生成错误、检查点及全部已记录调用的花费，继续下一项发现；键盘中断仍向上传播。
- 新增 34 项回归通过，包括真实 GCC/G++ 长编译诊断经过“编排器 → 修复提示 → 受控测试完成”的链路，以及重复失败终止、重试上限、分项隔离、成本、凭据脱敏、提示围栏等。

凭据扫描补充：脱敏测试现使用分段构造的纯假密钥，当前测试文件不触发 gitleaks。历史提交 `57c6eee90357c1f7bb23eb0acb3b7dc61973916c` 中该用例的字面量仍会在包含此提交的历史扫描中触发 `generic-api-key`（`tests/test_dynamic_retry_feedback.py:232`），因此未来 PR 的历史扫描仍有一个已知假阳性。本轮未增加安全扫描豁免，也未改写提交历史。

本轮完整 Python 套件：12,873 项通过、20 项条件性跳过、无失败；仅有既有 `ast.Str` 弃用警告。相关专项 257 项通过。Go 全部 13 个测试包、`go vet`、CLI 与 Go 解析器构建、Ruff 和 `git diff --check` 均通过。

本轮本地环境为 Python 3.12.14、GCC/G++ 14.2.0、Node.js 24.19.0、Go 1.26.0；Python 依赖按仓库安装，并补齐当前沙箱代理所需的 SOCKS 支持；使用可编辑源码安装及已安装 npm 依赖验证 CLI。真实编译仅使用本测试构造的源码和仓库内已审阅样例。Docker 与模型调用使用 mock，没有执行真实 Docker、付费模型调用或外部目标 PoC。

## 上一轮验证记录

验证日期：2026-10-17（UTC）。基线为 `c16e6167b9641ac3c43d3364765a16a503c7109a`，分支保留该版本已有修复。本记录区分离线回归与真实外部服务验收。

## 已验证的范围

- 新增 Python 专项：109 项通过，其中 DeepSeek 适配器 27 项、中文报告 16 项、C/C++ 模板 66 项。
- Go 完整套件：13 个测试包通过，604 个用例/子用例通过，3 个有条件跳过；另有主程序包无测试。`go vet ./...` 和 `go build` 通过。
- 3 个 Go 跳过项：真实浏览器烟测（需显式启用）、已覆盖运行时条件下不适用的 runtime 测试、Windows 专用路径测试。
- 服务端与 UI 的 `go test -race` 通过。新增真实子进程 fixture 验证扫描、HTML 补生成、摘要三条路径传递同一模型配置与单次密钥环境；密钥不进入命令参数或持久任务文件。
- 编译后的新 CLI 在隔离、未配置密钥的本机环境通过 11 项 HTTP 检查：中文页面、品牌、空状态、DeepSeek 默认值/当前模型、CSRF、数据提示、CSP nonce、主机头防重绑定和中文 404 等。未启动任何实际扫描。
- Ruff、`git diff --check`、渲染后 JavaScript 语法/状态测试通过；报告 CSS 按仓库固定 Tailwind 配方重新生成后逐字节一致。

完整 Python 套件：12,812 项通过、45 项跳过，无失败；仅有一条既有 `ast.Str` 弃用警告。随后补齐 CLI 二进制路径和 wheel 构建工具，补跑 CLI/安装布局测试 28 项全部通过，其中 25 项原先被跳过，另外 3 项为重复验证。因此尚有 20 项条件性跳过（平台差异、未提交的旧版对照夹具、显式禁用的外部仓库测试或不适用的工具能力分支）。新增 DeepSeek/C/C++/中文报告专项均未跳过。

安装布局回归还验证 wheel 实际包含新的 DeepSeek 适配器、中文输出策略、C/C++ Dockerfile 和运行器，避免仅源码检出可用而安装后缺失。

## 关键回归与证据边界

- DeepSeek 采用模拟 SDK/HTTP 响应，检查工具循环及纯文本轮次的 `reasoning_content` 回传、并发历史隔离、缓存计费、错误类型、当前模型默认值和原有配置兼容性。
- 中文报告回归检查正常、空、错误和未知判定的中文回退；JSON 字段、状态枚举、SARIF 标识、代码和路径保持不变，保留 XSS 防护。
- C/C++ 测试实际调用本机 GCC/G++ 编译仓库自带的已审阅样例，覆盖漏洞版/修复版 C 与 C++、ASan/UBSan、驱动自身错误、编译失败、超时和普通崩溃。Docker 调用链只作 mock 验证。
- C/C++ 驱动自行输出 `CONFIRMED` 不构成确认；需要对应真实目标的 sanitizer 诊断及异常终止。无有效证据返回 `INCONCLUSIVE`，构建/环境错误返回 `ERROR`，不当作“已证明安全”。
- 诊断文本与退出状态仍不是防伪证明：恶意目标/驱动可能伪造它们，需人工核对调用栈与原始发现。当前模板限单编译单元和标准库，不保证任意 Make/CMake 项目、第三方依赖、平台 ABI 或内存泄漏检测。
- 修正测试默认模型迁移时保留原行为断言；同时修复三个已有测试模块将局部 autouse fixture 注册为全局插件的问题，防止模型/工具能力检查被无意 mock。

## 未执行及原因

- 真实 DeepSeek API：未提供凭据，未调用付费服务；模拟通过不等于线上可用性验证。
- 真实 Docker 镜像构建与容器运行：本环境没有 Docker，未安装或宣称通过。
- 真实浏览器视觉验收：本环境 Chromium 启动受沙箱限制，未绕过限制。仓库已有的浏览器 CSP/DOM 烟测已更新交互断言，须在允许的浏览器环境或 CI 中执行；静态和 HTTP 检查不能替代视觉验收。
- 历史报告不自动翻译；原始编译器/工具证据保留原文。LLM 已明确要求中文叙述，但模型生成内容仍需人工复核。

## 复现命令

先按 [中文使用说明](README.zh-CN.md) 安装依赖，并确保 JavaScript 解析器的 npm 依赖和 Go 解析器已构建。仅运行仓库测试，不调用实际模型接口：

```bash
# 从仓库根目录开始；先构建 Python 集成测试所需的 CLI 路径
(cd apps/openant-cli && go build -o openant .)
python -m pip install build
cd libs/openant-core/parsers/javascript && npm ci --ignore-scripts
cd ../go/go_parser && go build -o go_parser .
cd ../../..
python -m ruff check .
python -m pytest tests/test_llm_deepseek_adapter.py tests/test_chinese_reports.py tests/test_dynamic_c_templates.py -q
python -m pytest tests/ -q -ra
cd ../../apps/openant-cli
go test ./...
go test -race ./internal/server ./ui
go vet ./...
go build -o bin/openant .
```

浏览器烟测请参照 `.github/workflows/CI.yaml` 的依赖步骤，再显式设置 `OPENANT_BROWSER_TESTS=1` 执行 `go test ./internal/server -run TestBrowserSmoke -v -count=1`。这不代表已完成人工视觉验收。
