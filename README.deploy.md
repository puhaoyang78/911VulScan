# 911VulScan 最小部署包

部署包只含运行代码、构建依赖清单、运行时提示词、必要配置和许可证；开发仓库继续保留测试与 CI。

## 构建与启动（Linux/macOS）

需要 Python 3.11+（含 venv）、Go 1.26+、Git，以及依赖下载网络。JavaScript/TypeScript 扫描另需 Node.js/npm；首次使用会按 package-lock 安装解析器依赖。Go 扫描会构建 Go 解析器。动态测试另需 Docker。离线部署需提前准备这些依赖；此包不是独立静态二进制。

```sh
tar -xzf 911VulScan-source.tar.gz
cd 911VulScan
sh scripts/install-deployment.sh
./bin/vulscan --help
./bin/vulscan setup
./bin/vulscan serve
```

保留整个部署目录：`bin/`、`.venv/`、`config/`、`libs/vulscan-core/` 必须共同存在。不要单独复制二进制；Go CLI 还需要相邻目录的语言/模型注册表。安装虚拟环境不可直接跨机器搬移。本版只提供新命令 `vulscan`、Python 包 `vulscan` 和 `VULSCAN_*` 环境变量；配置目录为 `~/.config/vulscan/`，运行数据目录为 `~/.vulscan/`。不提供旧命令、旧环境变量或旧配置的自动兼容/迁移，也不会删除已有旧数据。

便携部署版本不支持 `uninstall` 自动清理；停止服务后，确认不再需要再删除部署目录。用户配置和扫描结果在上述新用户目录，需单独备份和处理。

在开发仓库生成部署包：`python3 scripts/package-deployment.py`。包不含测试、CI、缓存、开发设计文档、示例扫描结果或密钥。不要向包中加入个人配置、API Key、虚拟环境或扫描产物。

## 许可与来源

911VulScan 基于 Knostic OpenAnt 开源项目进行了品牌、中文交互与功能调整。原始版权和 Apache-2.0 许可见 `LICENSE`；第三方前端资源的来源记录位于 `apps/vulscan-cli/{ui,internal/report}/vendor/SOURCES.txt`，资源内许可声明保持原样。产品品牌调整不改变原作者权利或第三方许可。
