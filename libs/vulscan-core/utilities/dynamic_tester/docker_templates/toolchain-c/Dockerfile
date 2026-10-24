# VulScan 共享 C/C++ 工具链镜像（由 VulScan 自己维护，不经过模型）。
# 内容摘要会进入镜像标签：修改本文件即产生新标签，旧镜像不会被误用。
FROM python:3.12-slim-bookworm

# 复现驱动是 Python，编译目标是 C11 / C++17，运行时依赖 ASan/UBSan。
RUN apt-get update \
    && apt-get install -y --no-install-recommends gcc g++ libc6-dev \
    && rm -rf /var/lib/apt/lists/*

ENV PYTHONDONTWRITEBYTECODE=1
WORKDIR /test
