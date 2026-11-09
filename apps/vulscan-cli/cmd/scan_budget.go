package cmd

import (
	"fmt"
	"os"
)

// 开启动态测试时，Python 进程要构建镜像、编译并运行 Docker 容器，
// 30 分钟的默认预算经常不够，进程会被直接杀掉。这里给 scan 一个
// 更大的默认值；用户显式设置 VULSCAN_INVOKE_TIMEOUT 时以用户为准。
const scanDynamicInvokeBudget = "3h"

func applyScanInvokeBudget(dynamic bool, quiet bool) {
	if !dynamic || os.Getenv("VULSCAN_INVOKE_TIMEOUT") != "" {
		return
	}
	if err := os.Setenv("VULSCAN_INVOKE_TIMEOUT", scanDynamicInvokeBudget); err != nil {
		return
	}
	if !quiet {
		fmt.Fprintln(os.Stderr, "[vulscan] 本次运行预算：3h0m（已开启动态测试）")
	}
}
