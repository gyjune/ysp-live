FROM python:3.9-slim AS builder

WORKDIR /app

# 1. 更换pip源为国内源，加速下载
# 2. 先单独安装核心依赖
RUN pip config set global.index-url https://pypi.tuna.tsinghua.edu.cn/simple && \
    pip config set global.trusted-host pypi.tuna.tsinghua.edu.cn

COPY requirements.txt .

# 先更新pip，然后尝试安装
RUN pip install --upgrade pip && \
    pip install --no-cache-dir construct==2.8.8 && \
    pip install --no-cache-dir fastapi==0.127.0 && \
    pip install --no-cache-dir requests==2.32.5 && \
    pip install --no-cache-dir uvicorn==0.40.0

# ============== 第二阶段：运行时 ==============
FROM python:3.9-slim

WORKDIR /app

# 安装运行时依赖（如果需要）
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# 从构建阶段复制已安装的包
COPY --from=builder /usr/local/lib/python3.9/site-packages /usr/local/lib/python3.9/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# 复制应用文件
COPY yspapp.py .
COPY ysp.txt .

# 暴露端口
EXPOSE 10001

# 设置环境变量
ENV PYTHONUNBUFFERED=1
ENV PORT=10001

# 健康检查
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import requests; requests.get('http://localhost:10001/', timeout=5)"

# 启动命令
CMD ["python", "yspapp.py"]