# DeepSeek 适配与默认配置

911VulScan 新安装默认使用 `deepseek-default`，全部扫描阶段调用 `deepseek-flash`。界面也可选择 `deepseek-pro`，对应 `deepseek-v4-pro`。明确选择的已有配置不变；历史 Anthropic 密钥、模型或 provider 配置，以及只设置了 `ANTHROPIC_API_KEY` 的旧环境，会继续使用 `openant-default`。

模型及接口根据 DeepSeek 官方文档于 2026-10-17 核对：

- [模型与价格](https://api-docs.deepseek.com/quick_start/pricing/)
- [思考模式与工具调用](https://api-docs.deepseek.com/guides/thinking_mode/)
- [旧模型退役公告](https://api-docs.deepseek.com/news/news260424/)

`deepseek-chat`、`deepseek-reasoner` 已退役，适配器会在发请求前报错。旧名 `deepseek-v4-flash` 目前由官方转到新 Flash 模型，新配置直接使用 `deepseek-flash`。

## 配置

建议在启动进程的环境中设置 `DEEPSEEK_API_KEY`，或使用 `openant set-api-key --provider deepseek`。`openant setup llm` 可创建自定义按阶段配置。历史 `--api-key` 扫描参数仍然仅适用于 Anthropic；DeepSeek 使用专用环境变量或 provider 配置。

默认地址为 `https://api.deepseek.com`，可通过 provider 的 `base_url` 或 `DEEPSEEK_BASE_URL` 使用自己的兼容端点。不会回退使用 `OPENAI_API_KEY`、`ANTHROPIC_API_KEY` 或 `OPENAI_BASE_URL`。

```json
{
  "$schema_version": 2,
  "default_llm": "deepseek-default",
  "llm_providers": {
    "deepseek": {
      "type": "deepseek",
      "request_timeout": 120,
      "thinking": {"type": "enabled"}
    }
  }
}
```

密钥顺序为：界面隔离子进程中的单次覆盖值 > provider 中显式配置的密钥 > `DEEPSEEK_API_KEY`。单次覆盖变量 `OPENANT_DEEPSEEK_API_KEY_OVERRIDE` 供界面工作进程使用，不需要在日常环境中设置。界面输入密钥不写入配置文件。

## 思考、工具和中文输出

- 默认明确启用思考模式。设置 `thinking: {"type": "disabled"}` 可关闭。
- 多轮工具调用会回传所有历史 assistant 轮次的 `reasoning_content`，包括仅有普通文本的轮次；推理文本不会混入展示内容。每轮内容自行携带元数据，没有全局历史或工具 ID 缓存，支持并发。
- `max_tokens` 保持调用方上限，推理也会消耗该预算。空回复、截断、拒绝与无效工具参数均会明确报错，不能作为“未发现漏洞”处理。
- 密钥探测是明确关闭思考的 1-token 请求。真实执行探测仍会调用服务并可能计费；本次测试仅使用 mock。
- 所有经 registry 调用的 provider 都附加简体中文输出要求；JSON 字段、枚举、代码、路径及标识符不翻译。该语言策略参与检查点指纹，旧的不同语言结果不会被误认为同一次分析。

## 费用与验证边界

费用是估算值：模型表采用官方高峰美元费率作为保守估计，官方空闲时段费率为其一半。静态表不判断中国法定节假日或每次请求的实际计费时段，不能替代服务商账单。`prompt_cache_hit_tokens` 按输入总数中的缓存命中部分计价，避免重复计费。

离线测试覆盖真实 SDK + MockTransport、文本/工具历史回传、并发隔离、两种思考模式、请求格式、原生缓存用量、错误映射、配置迁移和中文策略指纹。没有使用真实密钥或发起付费模型请求；线上账户权限、可用性与扫描质量仍需用户配置后验证。
