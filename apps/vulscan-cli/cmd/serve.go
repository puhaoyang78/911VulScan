// Modified 2026-10-23 for the VulScan-only product namespace.
package cmd

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"

	"github.com/puhaoyang78/911VulScan/apps/vulscan-cli/internal/output"
	"github.com/puhaoyang78/911VulScan/apps/vulscan-cli/internal/server"
	"github.com/spf13/cobra"
)

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "启动 911VulScan 中文网页工作台",
	Long: `启动本地网页服务（默认 http://127.0.0.1:8080），并自动打开浏览器。

扫描结果保存在 ~/.vulscan/webui/，重启后仍可查看。
按 Ctrl+C 关闭服务；退出前会取消正在运行的扫描。`,
	Args: cobra.NoArgs,
	Run:  runServe,
}

var serveAddr string

func init() {
	serveCmd.Flags().StringVar(&serveAddr, "addr", "127.0.0.1:8080", "监听地址")
}

func runServe(_ *cobra.Command, _ []string) {
	rt, err := ensurePython()
	if err != nil {
		output.PrintError(err.Error())
		os.Exit(2)
	}

	// Resolve output root: ~/.vulscan/webui/
	home, err := os.UserHomeDir()
	if err != nil {
		output.PrintError("无法确定用户目录：" + err.Error())
		os.Exit(2)
	}
	outDir := filepath.Join(home, ".vulscan", "webui")
	if err := os.MkdirAll(outDir, 0750); err != nil {
		output.PrintError("无法创建结果目录：" + err.Error())
		os.Exit(2)
	}

	srv, err := server.New(rt.Path, outDir)
	if err != nil {
		output.PrintError("初始化服务失败：" + err.Error())
		os.Exit(2)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	url, err := srv.Start(ctx, serveAddr)
	if err != nil {
		output.PrintError("启动服务失败：" + err.Error())
		os.Exit(2)
	}

	fmt.Println("911VulScan 中文工作台已启动：", url)
	openBrowser(url)
	fmt.Println("按 Ctrl+C 停止服务。")

	<-ctx.Done()
	fmt.Println("\n正在停止服务…")
	srv.WaitShutdown() // wait for in-flight scans to be cancelled before exiting
}

// openBrowser opens url in the default system browser.
func openBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	_ = cmd.Start()
}
