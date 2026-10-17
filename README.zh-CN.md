# 911VulScan 中文版

911VulScan 基于 Knostic [OpenAnt](https://github.com/knostic/OpenAnt)，保留上游 Apache 2.0 许可证和署名。`911-dev` 分支提供中文扫描工作台、中文漏洞报告、默认 DeepSeek 配置，以及 C/C++ 隔离动态测试模板和 Python、JavaScript/TypeScript、Go 的动态构建指导。

## 本分支的变化

- 新的中文网页工作台：任务概览、分步扫描表单、模型选择、实时日志、摘要、漏洞报告和披露材料。
- 新安装默认使用 `deepseek-default`，所有七个扫描阶段使用 `deepseek-flash`；可选择 `deepseek-pro` 使用 `deepseek-v4-pro`。
- 已有显式 `default_llm` 和旧版 Anthropic 配置继续生效，不自动改写用户配置。网页的“DeepSeek（默认）”是本次任务选择；“使用已有模型配置”沿用原配置。
- 所有扫描模型调用增加简体中文叙述要求。报告标题、状态显示、摘要及修复建议采用中文；JSON 键、枚举、CWE/CVE、代码、文件路径和原始证据保持原样。
- C/C++ 从原先跳过动态测试改为固定 GCC/G++、ASan/UBSan 编译执行模板；只在 Docker 容器中执行扫描项目代码。

## 安装与启动

需要 Go 1.25+、Python 3.11+；JavaScript/TypeScript 解析另需 Node.js。动态验证另需已经启动的 Docker Engine。

```bash
git clone --branch 911-dev https://github.com/puhaoyang78/911VulScan.git
cd 911VulScan
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r libs/openant-core/requirements.txt
python -m pip install -e 'libs/openant-core[dev]'
cd apps/openant-cli
go build -o bin/openant .
cd ../..
export OPENANT_PYTHON="$PWD/.venv/bin/python"
./apps/openant-cli/bin/openant serve
```

打开终端显示的本机地址，默认为 `http://127.0.0.1:8080`。服务不提供多用户身份认证，请保留回环地址监听，不要直接暴露到公网。网页产物保存在 `~/.openant/webui/`。

## 配置 DeepSeek

推荐使用交互向导：

```bash
./apps/openant-cli/bin/openant setup llm
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

保存位置为 `~/.config/openant/config.json`，或 `$XDG_CONFIG_HOME/openant/config.json`。内置配置不必重复定义在 `llm_configs` 中。DeepSeek 适配器保留工具调用所需的历次 `reasoning_content`，支持明确关闭思考模式，不借用 OpenAI/Anthropic 密钥。

`--api-key` 保留旧版 Anthropic 覆盖语义；DeepSeek 请使用自己的环境变量、网页字段或配置向导。Auto Patcher 同样继承模型配置的默认分析绑定；已有显式供应商选择保持不变。

模型名及计价依据核对于 2026-10-17：[DeepSeek 模型价格](https://api-docs.deepseek.com/quick_start/pricing/)、[思考模式和工具调用](https://api-docs.deepseek.com/guides/thinking_mode/)。旧 `deepseek-chat` / `deepseek-reasoner` 已停用。本地费用按登记费率估算，峰谷定价、缓存、网关计费及后续价格调整可能导致与账单不同。

## 扫描与中文报告

```bash
# 只扫描自己有权测试的代码。未准备 Docker 时明确跳过动态测试。
./apps/openant-cli/bin/openant scan /path/to/project \
  --llm-config deepseek-default --verify --skip-dynamic-test

# C/C++ 完整扫描（需要 Docker）
./apps/openant-cli/bin/openant scan /path/to/c-project \
  --language c --llm-config deepseek-default --verify

# 对现有扫描结果单独进行动态验证
./apps/openant-cli/bin/openant dynamic-test /path/to/pipeline_output.json \
  --repo-path /path/to/c-project --llm-config deepseek-default
```

网页中打开“摘要”“报告”查看中文结论。原始终端输出、编译器证据以及历史已有报告不会被模型重新翻译，以免改写证据；本分支生成的新报告和模型叙述明确要求中文。机器消费方继续使用原有 JSON/SARIF 字段和状态，不应解析中文显示文案。

## C/C++ 动态验证范围

- `.c` 采用 C11，C++ 扩展名采用 C++17，GCC/G++ 加载 AddressSanitizer 与 UndefinedBehaviorSanitizer。
- 当前支持单编译单元和标准库复现；仅预置发现所在的真实目标文件。不自动运行项目 Make/CMake，不宣称支持任意头文件、链接库或平台 ABI。
- 编译失败、依赖缺失、配置错误返回 `ERROR`；超时、普通崩溃、缺少有效证据返回 `INCONCLUSIVE`。`NOT_REPRODUCED` 只表示本次未复现，不代表已证明安全。
- 固定容器模板、只读根文件系统、无运行时外网、移除 capabilities、禁止新增权限、资源限额；没有宿主卷挂载或宿主执行回退。
- 镜像构建仍需拉取基础镜像和公开编译依赖。当前不提供 LeakSanitizer 内存泄漏检测保证。

详细协议和限制见 [动态验证说明](libs/openant-core/utilities/dynamic_tester/README.md)。自动生成的驱动仍需人工核对，运行时诊断必须与原始发现和目标调用栈相符。

## 验证方法

```bash
# Python 静态检查和回归
cd libs/openant-core
python -m ruff check .
python -m pytest tests/test_llm_deepseek_adapter.py \
  tests/test_chinese_reports.py tests/test_dynamic_c_templates.py -q
python -m pytest tests/ -q

# Go 构建、静态检查及回归
cd ../../apps/openant-cli
go vet ./...
go test ./...
go build -o bin/openant .
```

DeepSeek 测试使用模拟响应，不调用付费接口。C/C++ 原生回归只编译仓库自带、已审阅的漏洞版/修复版 fixture；Docker 路由 mock 不等于真实镜像构建或容器验证通过。真实 DeepSeek、Docker 和浏览器视觉验收应在具备相应环境时分别执行，不应将单元测试通过视为全部验收完成。

本分支的测试结果、证据边界和未执行项目见 [验证记录](VALIDATION.zh-CN.md)。
