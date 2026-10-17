FROM python:3.11-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /test
# 上下文包含真实目标源文件；标准库测试可以不提供 requirements.txt。
COPY . .
RUN if [ -f requirements.txt ]; then python -m pip install --no-cache-dir -r requirements.txt; fi
CMD ["python", "test_exploit.py"]
