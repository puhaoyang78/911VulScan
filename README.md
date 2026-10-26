# 911VulScan

中文代码漏洞扫描工作台，提供 DeepSeek 等模型配置、两阶段分析、漏洞报告和隔离动态验证。

- [中文使用说明](README.zh-CN.md)：配置、命令与能力边界
- [最小部署说明](README.deploy.md)：干净部署包、安装和运行

## 快速部署

需要 Python 3.11+（含 venv）、Go 1.26+ 和依赖下载网络。
远程仓库扫描需要 Git；JavaScript/TypeScript 解析另需 Node.js/npm；动态验证另需 Docker。
补丁检查和阶段重放需要 Git 2.32+，以确保配置隔离生效。

```sh
python3 scripts/package-deployment.py
tar -xzf dist/911VulScan-source.tar.gz -C /你的部署目录
cd /你的部署目录/911VulScan
sh scripts/install-deployment.sh
./bin/vulscan setup
./bin/vulscan serve
```

部署目录须预先创建。网页服务仅监听本机回环地址；远程访问方式另行配置。
开发仓库保留测试与 CI，部署包只包含运行和构建所需文件。

## Supported languages

Python、JavaScript/TypeScript、Go、C/C++、Ruby、PHP、Zig、Swift、Rust。
语言支持不代表每种语言的动态验证能力相同，详见中文使用说明。

## 命名与数据

本版只提供 `vulscan` 命令、Python 包及 `VULSCAN_*` 环境变量。
配置使用 `~/.config/vulscan/`，运行数据使用 `~/.vulscan/`。
不提供旧名称别名或自动迁移；不会删除已有旧配置和扫描数据。

## 来源与许可

本项目基于 Knostic [OpenAnt](https://github.com/knostic/OpenAnt) 修改，
不是上游官方发行版。原版权和 Apache-2.0 许可见 [LICENSE](LICENSE)；
上游作者名单、第三方来源和修改说明见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。
