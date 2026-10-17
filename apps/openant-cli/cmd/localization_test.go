package cmd

import (
	"bytes"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestChineseHelpPreservesRunnableUsageAndFlagIdentifiers(t *testing.T) {
	root := &cobra.Command{Use: "openant", Short: "中文扫描器"}
	scan := &cobra.Command{Use: "scan <path>", Run: func(*cobra.Command, []string) {}}
	scan.Flags().String("llm-config", "", "legacy English")
	root.PersistentFlags().String("output", "", "legacy English")
	root.AddCommand(scan)
	localizeCommandHelp(root)
	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetErr(&buf)
	if err := scan.Help(); err != nil {
		t.Fatal(err)
	}
	help := buf.String()
	for _, want := range []string{"用法：", "openant scan <path>", "--llm-config", "模型配置名称", "全局选项：", "显示帮助"} {
		if !strings.Contains(help, want) {
			t.Errorf("help missing %q: %s", want, help)
		}
	}
	for _, forbidden := range []string{"Usage:", "Global Flags:", "help for", "<no value>", "template:"} {
		if strings.Contains(help, forbidden) {
			t.Errorf("unexpected %q in help: %s", forbidden, help)
		}
	}
	if scan.Name() != "scan" || scan.Flags().Lookup("llm-config") == nil {
		t.Fatal("localization changed machine command/flag identifiers")
	}
}
