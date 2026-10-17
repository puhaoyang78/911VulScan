package cmd

import (
	"strings"
	"testing"
)

func TestDynamicCRepoPathFlag(t *testing.T) {
	flag := dynamicTestCmd.Flags().Lookup("repo-path")
	if flag == nil {
		t.Fatal("C/C++ 独立动态验证缺少 --repo-path 参数")
	}
	if flag.DefValue != "" || !strings.Contains(flag.Usage, "C/C++") {
		t.Fatalf("仓库路径参数应保留活动项目默认值并解释 C/C++ 用途：%+v", flag)
	}
	if !strings.Contains(dynamicTestCmd.Long, "ASan/UBSan") {
		t.Fatal("动态测试帮助必须说明真实 sanitizer 模板")
	}
}
