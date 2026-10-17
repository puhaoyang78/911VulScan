package cmd

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/charmbracelet/x/term"
	"github.com/knostic/open-ant-cli/internal/config"
	"github.com/knostic/open-ant-cli/internal/models"
	"github.com/knostic/open-ant-cli/internal/output"
	"github.com/spf13/cobra"
)

// errStdinClosed surfaces when reader.ReadString hits EOF without any
// input on the current line. The wizard treats that as "user aborted"
// and exits cleanly — without it, every required-prompt loop would
// spin forever in a non-interactive context (no TTY, piped input
// exhausted, etc.).
var errStdinClosed = errors.New("stdin closed before answer provided")

// Pipeline phases that every llm-config must list. Mirrors PHASES in
// “libs/openant-core/utilities/llm/config.py“ — adding a phase requires
// touching both lists. The order here drives the wizard's question flow
// and matches the actual scan execution order in “core/scanner.py“, so
// a user setting up their config walks through phases in the same
// sequence they'll see when they run “openant scan“.
//
// The per-phase prefill model is no longer hardcoded here: it is resolved
// (and validated as a current, non-retired id) from the shared
// config/models.json registry via internal/models.DefaultModel(provider,
// phase), and the per-provider "known models" hint list comes from
// internal/models.KnownModels. See internal/models for the phase→tier
// mapping that drives the picks (stronger reasoning for detect / verify /
// reachability, lighter models for the generation phases). Users can always
// override at the prompt.
var setupLLMPhases = []phaseSpec{
	{name: "app_context", short: "应用场景分类（扫描时首先运行）。"},
	{name: "llm_reach", short: "LLM 可达性复核（可选阶段）。"},
	{name: "enhance", short: "上下文增强（单次请求及工具调用）。"},
	{name: "analyze", short: "第一阶段：漏洞检测。"},
	{name: "verify", short: "第二阶段：攻击验证（工具调用）。"},
	{name: "dynamic_test", short: "Docker 漏洞利用测试生成。"},
	{name: "report", short: "漏洞披露、摘要及修复建议生成。"},
}

// Provider adapter types the wizard offers in the picker. All of them
// ship with a Python adapter (deepseek, anthropic, openai, google, bedrock,
// openrouter, ollama) — see
// “libs/openant-core/utilities/llm/providers/__init__.py“ — so a
// completed wizard config runs without further changes. The wizard
// probes each provider+model pair against the real provider API
// before saving, so a typo'd key or model ID surfaces immediately.
var supportedProviderTypes = []string{"deepseek", "anthropic", "openai", "google", "bedrock", "openrouter", "ollama"}

// apiKeyHints maps a provider type to a one-line reminder shown right
// before the wizard asks for the API key. Used to head off the common
// "I have a ChatGPT/Claude/Gemini subscription, why doesn't it work?"
// confusion — consumer subscriptions are NOT the same product as the
// REST API and do not share quota. Entries also document provider-specific
// environment variables and credential-free local or cloud-auth paths.
var apiKeyHints = map[string]string{
	"deepseek":   "DeepSeek API 密钥：https://platform.deepseek.com/api_keys；也可设置 DEEPSEEK_API_KEY。默认端点为 https://api.deepseek.com，支持 DEEPSEEK_BASE_URL。",
	"openai":     "注意：ChatGPT/Codex 订阅不包含 API 额度，请在 platform.openai.com 获取独立计费的 API 密钥。",
	"bedrock":    "注意：Bedrock 使用 AWS 凭证链，请将密钥留空，并配置 AWS 凭证和 AWS_REGION。",
	"openrouter": "注意：在 openrouter.ai/keys 创建 API 密钥；默认地址为 https://openrouter.ai/api/v1。",
	"ollama":     "注意：Ollama 本地运行时无需 API 密钥，请留空。默认地址为 http://localhost:11434/v1，需先运行 ollama pull <model> 下载模型。",
}

type phaseSpec struct {
	name  string
	short string
}

var setupCmd = &cobra.Command{
	Use:   "setup",
	Short: "交互式配置向导",
	Long: `首次使用 911VulScan 的交互式配置向导。

通过问答将设置保存到 ~/.config/openant/config.json，
无需手动编写配置文件。`,
}

var setupLLMCmd = &cobra.Command{
	Use:   "llm",
	Short: "交互式创建 LLM 配置",
	Long: `交互式创建 LLM 配置。

为各个扫描阶段选择服务商和模型，同名服务商共用凭证。
保存前会对每个不同的服务商与模型组合发送最小验证请求，可能计费。

首次使用默认选择内置 deepseek-default（DeepSeek Flash）。
deepseek-pro 使用 DeepSeek V4 Pro；openant-default 保留 Anthropic 兼容配置。
这些内置配置无需运行向导即可使用。需要自定义阶段、模型或代理端点时，
可通过 setup llm 创建自己的具名配置。`,
	Args: cobra.NoArgs,
	Run:  runSetupLLM,
}

func init() {
	setupCmd.AddCommand(setupLLMCmd)
	rootCmd.AddCommand(setupCmd)
}

// ---------------------------------------------------------------------------
// Wizard entry point
// ---------------------------------------------------------------------------

func runSetupLLM(cmd *cobra.Command, args []string) {
	cfg, err := config.Load()
	if err != nil {
		output.PrintError(err.Error())
		os.Exit(1)
	}

	// Load the shared model registry once, up front. Fail loud on a missing
	// config: the wizard's prefills and hints are derived from it, and a wizard
	// that silently suggested nothing (or a retired id) is the bug this
	// replaces. Per-phase lookups below use this snapshot.
	modelReg, err := models.Load()
	if err != nil {
		output.PrintError(fmt.Sprintf("无法读取模型注册表（config/models.json）：%v", err))
		os.Exit(1)
	}

	reader := bufio.NewReader(os.Stdin)
	writeIntro(os.Stderr, cfg)

	// Name + overwrite confirmation.
	configName, ok, err := promptLLMConfigName(reader, cfg)
	if err != nil {
		exitOnInputError(err)
	}
	if !ok {
		return
	}

	// Walk every phase. Provider details collected once per provider
	// name and reused within the session. ``shownModelHints`` tracks
	// which providers have already had their known-models list shown
	// in this session so we don't repeat the hint on every phase.
	sessionProviders := map[string]config.ProviderEntry{}
	shownModelHints := map[string]bool{}
	phaseChoices := map[string]config.LLMPhaseRef{}
	lastProvider := defaultStartingProvider(cfg)

	for _, spec := range setupLLMPhases {
		fmt.Fprintln(os.Stderr)
		fmt.Fprintf(os.Stderr, "--- %s 阶段 ---\n", spec.name)
		fmt.Fprintln(os.Stderr, spec.short)

		providerName, err := promptRequired(reader, "服务商名称", lastProvider)
		if err != nil {
			exitOnInputError(err)
		}

		// Establish provider details exactly once per name per session.
		if _, alreadyAsked := sessionProviders[providerName]; !alreadyAsked {
			provEntry, provExisted := cfg.GetProvider(providerName)
			if provExisted {
				fmt.Fprintf(os.Stderr, "使用已有服务商 %q（类型=%s）\n", providerName, provEntry.Type)
				sessionProviders[providerName] = provEntry
			} else {
				entry, err := promptNewProvider(reader, providerName)
				if err != nil {
					exitOnInputError(err)
				}
				sessionProviders[providerName] = entry
			}
		}

		prov := sessionProviders[providerName]
		// Show the known-models hint the first time a provider is
		// referenced in this session. Suppressed when a base_url
		// override is set — the user is hitting a proxy with its
		// own model namespace, so the stock list would mislead.
		if !shownModelHints[providerName] {
			shownModelHints[providerName] = true
			if prov.BaseURL == "" {
				if opts := modelReg.KnownModels(prov.Type); len(opts) > 0 {
					fmt.Fprintf(os.Stderr, "  可用的 %s 模型：%s\n", prov.Type, strings.Join(opts, ", "))
				}
			}
		}

		// Per-phase suggested model for the provider type. A custom
		// base_url short-circuits the suggestion (proxy may not host
		// the same model IDs).
		defaultModel := ""
		if prov.BaseURL == "" {
			// Resolve the per-phase prefill from the registry. A provider type
			// with no mapping (or a custom one) simply yields no prefill — the
			// user types the model — exactly as the old empty-map lookup did.
			if m, derr := modelReg.DefaultModel(prov.Type, spec.name); derr == nil {
				defaultModel = m
			}
		}
		model, err := promptRequired(reader, "模型", defaultModel)
		if err != nil {
			exitOnInputError(err)
		}

		phaseChoices[spec.name] = config.LLMPhaseRef{Provider: providerName, Model: model}
		lastProvider = providerName
	}

	// default_llm flag.
	fmt.Fprintln(os.Stderr)
	makeDefault, err := promptYesNo(reader, fmt.Sprintf("将 %q 设为默认 LLM 配置？", configName), true)
	if err != nil {
		exitOnInputError(err)
	}

	// Probe each unique (provider, model) pair.
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "正在验证服务商（每个不同的服务商与模型组合发送最小请求，可能计费）...")
	if err := probeAllPhases(sessionProviders, phaseChoices); err != nil {
		output.PrintError(err.Error())
		os.Exit(1)
	}

	// Commit.
	cfg.WriteLLMConfig(configName, phaseChoices, sessionProviders, makeDefault)
	if err := config.Save(cfg); err != nil {
		output.PrintError(err.Error())
		os.Exit(1)
	}

	fmt.Fprintln(os.Stderr)
	output.PrintSuccess(fmt.Sprintf("LLM 配置 %q 已保存。", configName))
	if makeDefault {
		fmt.Fprintf(os.Stderr, "  default_llm: %s\n", configName)
	}
	path, _ := config.Path()
	fmt.Fprintf(os.Stderr, "  配置文件：   %s\n", path)
}

// ---------------------------------------------------------------------------
// Intro
// ---------------------------------------------------------------------------

func writeIntro(w io.Writer, cfg *config.Config) {
	fmt.Fprintln(w, "911VulScan LLM 配置向导")
	fmt.Fprintln(w, "在 ~/.config/openant/config.json 中创建具名 LLM 配置。")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "每个扫描阶段使用各自配置的服务商与模型。")
	fmt.Fprintln(w, "扫描阶段：")
	for _, spec := range setupLLMPhases {
		fmt.Fprintf(w, "  - %-13s %s\n", spec.name, spec.short)
	}
	fmt.Fprintln(w)

	existingConfigs := cfg.LLMConfigNames()
	sort.Strings(existingConfigs)
	if len(existingConfigs) > 0 {
		fmt.Fprintln(w, "已有 LLM 配置：")
		for _, name := range existingConfigs {
			fmt.Fprintf(w, "  - %s\n", name)
		}
	} else {
		fmt.Fprintln(w, "（尚无自定义配置。内置 deepseek-default、deepseek-pro 和兼容配置 openant-default 始终可用。）")
	}
	existingProviders := cfg.ProviderNames()
	sort.Strings(existingProviders)
	if len(existingProviders) > 0 {
		fmt.Fprintln(w, "已有服务商（重复使用时无需再次输入密钥）：")
		for _, name := range existingProviders {
			if p, ok := cfg.GetProvider(name); ok {
				fmt.Fprintf(w, "  - %s (type=%s)\n", name, p.Type)
			}
		}
	}
	fmt.Fprintln(w)
}

// ---------------------------------------------------------------------------
// Prompt helpers
// ---------------------------------------------------------------------------

func promptLLMConfigName(reader *bufio.Reader, cfg *config.Config) (string, bool, error) {
	for {
		name, err := promptString(reader, "LLM 配置名称", "")
		if err != nil {
			return "", false, err
		}
		name = strings.TrimSpace(name)
		if name == "" {
			fmt.Fprintln(os.Stderr, "名称不能为空。")
			continue
		}
		if config.IsBuiltinLLM(name) {
			fmt.Fprintf(os.Stderr, "%q 是内置配置，不能覆盖，请换一个名称。\n", name)
			continue
		}
		if cfg.LLMConfigExists(name) {
			replace, yesErr := promptYesNo(reader, fmt.Sprintf("LLM 配置 %q 已存在，是否覆盖？", name), false)
			if yesErr != nil {
				return "", false, yesErr
			}
			if !replace {
				fmt.Fprintln(os.Stderr, "已取消。")
				return "", false, nil
			}
		}
		return name, true, nil
	}
}

func promptNewProvider(reader *bufio.Reader, name string) (config.ProviderEntry, error) {
	// When the provider name matches a known type ("anthropic",
	// "openai", "google"), default the type field to that — saves
	// the user a keystroke in the common case where they name the
	// provider after its type. Otherwise no default; the user picks
	// explicitly from the supported list.
	defaultType := ""
	if stringSliceContains(supportedProviderTypes, name) {
		defaultType = name
	}

	for {
		provType, err := promptRequired(reader, fmt.Sprintf("服务商类型 %v", supportedProviderTypes), defaultType)
		if err != nil {
			return config.ProviderEntry{}, err
		}
		if !stringSliceContains(supportedProviderTypes, provType) {
			fmt.Fprintf(os.Stderr, "未知服务商类型 %q，可选类型：%v。\n", provType, supportedProviderTypes)
			fmt.Fprintln(os.Stderr, "如需使用其他服务商，请按项目文档添加对应适配器。")
			continue
		}
		// Per-provider subscription-vs-API reminder — the wizard needs
		// an API key, not consumer-subscription credentials. ChatGPT /
		// Claude Pro / Gemini Advanced subscriptions are separate
		// billing tiers from each provider's API, and users frequently
		// hit this confusion because it's the same company and login.
		if hint, ok := apiKeyHints[provType]; ok {
			fmt.Fprintln(os.Stderr, hint)
		}
		// No-echo read so the pasted key never lands in the terminal
		// scrollback. Blank input is still allowed (read from env), and
		// on a non-TTY this transparently falls back to a normal line read.
		apiKey, err := promptSecret(reader, "API 密钥（粘贴；留空则读取环境变量）")
		if err != nil {
			return config.ProviderEntry{}, err
		}
		baseURL, err := promptString(reader, "API 基础地址（可选；留空则使用服务商默认地址）", "")
		if err != nil {
			return config.ProviderEntry{}, err
		}
		return config.ProviderEntry{Type: provType, APIKey: apiKey, BaseURL: baseURL}, nil
	}
}

// exitOnInputError prints a clean message and exits when the wizard
// can't continue because stdin is closed. Used at every prompt
// invocation site so the calling code stays linear.
func exitOnInputError(err error) {
	if errors.Is(err, errStdinClosed) {
		fmt.Fprintln(os.Stderr)
		output.PrintError("已取消：输入已结束。")
		os.Exit(1)
	}
	output.PrintError(err.Error())
	os.Exit(1)
}

// readLine reads one line. Returns “errStdinClosed“ if the reader
// hits EOF on an empty line — which is how non-interactive contexts
// (piped input exhausted, no TTY) surface "no answer". Without this
// signal, every required-prompt loop would spin forever.
func readLine(reader *bufio.Reader) (string, error) {
	line, err := reader.ReadString('\n')
	line = strings.TrimRight(line, "\r\n")
	if errors.Is(err, io.EOF) && line == "" {
		return "", errStdinClosed
	}
	return line, nil
}

// promptString reads a line. Empty input → returns “defaultVal“. The
// prompt is printed to stderr (not stdout) so the wizard composes
// cleanly with shell redirection — a user piping output to a file
// still sees the questions.
func promptString(reader *bufio.Reader, prompt, defaultVal string) (string, error) {
	if defaultVal == "" {
		fmt.Fprintf(os.Stderr, "%s: ", prompt)
	} else {
		fmt.Fprintf(os.Stderr, "%s [%s]: ", prompt, defaultVal)
	}
	line, err := readLine(reader)
	if err != nil {
		return "", err
	}
	if line == "" {
		return defaultVal, nil
	}
	return line, nil
}

// promptSecret reads a single secret line (e.g. an API key) WITHOUT
// echoing it to the terminal — closing the shoulder-surf / scrollback
// leak that the plain “promptString“ path left open for the API key.
//
// On an interactive terminal it uses term.ReadPassword (no echo) and
// prints a trailing newline to stderr (the no-echo read swallows the
// user's Enter). When stdin is NOT a terminal — piped/scripted input,
// CI, or the test suite — there is no echo to suppress and ReadPassword
// would error on the non-TTY fd, so it falls back to the ordinary
// reader-based “promptString“ path. This keeps scripted setup and the
// existing tests working while protecting real interactive use.
//
// The prompt is written to stderr (like every other wizard prompt) so
// the secret read composes with shell redirection of stdout.
func promptSecret(reader *bufio.Reader, prompt string) (string, error) {
	if !term.IsTerminal(os.Stdin.Fd()) {
		// Non-interactive: nothing to hide, and ReadPassword can't
		// operate on a pipe — defer to the standard line read.
		return promptString(reader, prompt, "")
	}
	fmt.Fprintf(os.Stderr, "%s: ", prompt)
	raw, err := term.ReadPassword(os.Stdin.Fd())
	// ReadPassword consumes the Enter keystroke without echoing it, so
	// emit the newline ourselves to keep subsequent output on its own
	// line — even on the error path.
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(raw)), nil
}

// promptRequired loops until the user supplies a non-empty value.
// Required questions like "Model" can't fall back to a blank default
// silently — the resulting config would be malformed.
func promptRequired(reader *bufio.Reader, prompt, defaultVal string) (string, error) {
	for {
		val, err := promptString(reader, prompt, defaultVal)
		if err != nil {
			return "", err
		}
		val = strings.TrimSpace(val)
		if val != "" {
			return val, nil
		}
		fmt.Fprintln(os.Stderr, "  （此项必填）")
	}
}

// promptYesNo accepts y/n/yes/no (case-insensitive). Empty input
// returns “defaultVal“ so the user can mash enter to accept.
func promptYesNo(reader *bufio.Reader, prompt string, defaultVal bool) (bool, error) {
	hint := "[y/N]"
	if defaultVal {
		hint = "[Y/n]"
	}
	for {
		fmt.Fprintf(os.Stderr, "%s %s ", prompt, hint)
		line, err := readLine(reader)
		if err != nil {
			return false, err
		}
		line = strings.TrimSpace(strings.ToLower(line))
		switch line {
		case "":
			return defaultVal, nil
		case "y", "yes":
			return true, nil
		case "n", "no":
			return false, nil
		default:
			fmt.Fprintln(os.Stderr, "  请输入 y 或 n。")
		}
	}
}

// ---------------------------------------------------------------------------
// Probing
// ---------------------------------------------------------------------------

func probeAllPhases(
	providers map[string]config.ProviderEntry,
	phases map[string]config.LLMPhaseRef,
) error {
	seen := map[string]bool{}
	// Sort phase names so the probe order is deterministic — matters
	// when the user is watching output scroll by.
	phaseNames := make([]string, 0, len(phases))
	for p := range phases {
		phaseNames = append(phaseNames, p)
	}
	sort.Strings(phaseNames)

	for _, phase := range phaseNames {
		ref := phases[phase]
		key := ref.Provider + "|" + ref.Model
		if seen[key] {
			continue
		}
		seen[key] = true

		prov, ok := providers[ref.Provider]
		if !ok {
			return fmt.Errorf("internal: provider %q referenced by phase %q but not collected", ref.Provider, phase)
		}
		fmt.Fprintf(os.Stderr, "  %s/%s ... ", ref.Provider, ref.Model)
		if prov.APIKey == "" && prov.Type != "ollama" {
			// Blank key means "read from the environment" (the wizard
			// offers this and WriteLLMConfig persists the env-read shape).
			// Leave this validation to the scan-start registry rather than
			// copying environment credentials into the wizard state. The
			// Python registry surfaces a missing/blank env
			// key at scan start instead. Ollama is exempt: it needs no
			// key at all (the adapter sends a placeholder), so its probe
			// always runs.
			fmt.Fprintln(os.Stderr, "已跳过（密钥从环境变量读取，扫描时验证）")
			continue
		}
		var probeErr error
		switch prov.Type {
		case "deepseek":
			probeErr = probeDeepSeek(prov.APIKey, prov.BaseURL, ref.Model)
		case "anthropic":
			probeErr = probeAnthropic(prov.APIKey, prov.BaseURL, ref.Model)
		case "openai":
			probeErr = probeOpenAI(prov.APIKey, prov.BaseURL, ref.Model)
		case "google":
			probeErr = probeGoogle(prov.APIKey, prov.BaseURL, ref.Model)
		case "bedrock":
			// Bedrock authenticates via the AWS credential chain, not an API
			// key, so there's nothing to probe here (a blank key is already
			// SKIPPED above; this covers a non-blank value). The AWS creds are
			// validated at scan start by the Python registry.
			fmt.Fprintln(os.Stderr, "已跳过（使用 AWS 凭证链）")
			continue
		case "openrouter":
			// OpenRouter speaks the OpenAI wire API but on its own endpoint;
			// probeOpenRouter defaults a blank base_url to openrouter.ai/api/v1
			// (NOT api.openai.com) and appends /chat/completions correctly.
			probeErr = probeOpenRouter(prov.APIKey, prov.BaseURL, ref.Model)
		case "ollama":
			// Ollama speaks the OpenAI wire API on localhost:11434/v1 and does
			// not check keys — probe with the same placeholder the adapter uses.
			probeErr = probeOllama(prov.APIKey, prov.BaseURL, ref.Model)
		default:
			fmt.Fprintln(os.Stderr, "已跳过")
			return fmt.Errorf("服务商类型 %q 尚不支持连接验证", prov.Type)
		}
		if probeErr != nil {
			fmt.Fprintln(os.Stderr, "失败")
			return fmt.Errorf("服务商 %q 的模型 %q 验证失败：%w", ref.Provider, ref.Model, probeErr)
		}
		fmt.Fprintln(os.Stderr, "通过")
	}
	return nil
}

// ---------------------------------------------------------------------------
// Small utilities
// ---------------------------------------------------------------------------

func defaultStartingProvider(cfg *config.Config) string {
	if ref, ok := cfg.LLMPhase("", "analyze"); ok {
		return ref.Provider
	}
	names := cfg.ProviderNames()
	sort.Strings(names)
	if len(names) > 0 {
		return names[0]
	}
	return "deepseek"
}

func stringSliceContains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}
