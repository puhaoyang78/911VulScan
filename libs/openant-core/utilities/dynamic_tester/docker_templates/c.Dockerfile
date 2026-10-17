FROM python:3.12-slim-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends gcc g++ libc6-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /test
ENV PYTHONDONTWRITEBYTECODE=1
COPY . /test/
# 编译输出和运行时临时文件只写入容器的 /tmp。
CMD ["python3", "_openant_c_runner.py", "_openant_c_spec.json"]
