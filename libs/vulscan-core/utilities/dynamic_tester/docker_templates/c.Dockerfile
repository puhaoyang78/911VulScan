# VulScan 固定 C/C++ 复现模板。
# 编译器工具链由 VulScan 预置的共享镜像提供（见 docker_templates/toolchain-c/），
# 每条发现的构建只复制文件，不再重复下载 gcc/g++。
FROM {{VULSCAN_TOOLCHAIN}}
WORKDIR /test
COPY . /test/
CMD ["python3", "_vulscan_c_runner.py", "_vulscan_c_spec.json"]
