# 使用 Python 3.9 的完整版本而不是 slim 版本
FROM python:3.9 AS builder

WORKDIR /app

# 复制依赖文件
COPY requirements.txt .

# 安装依赖 - 使用阿里云镜像源
RUN pip install --no-cache-dir -i https://mirrors.aliyun.com/pypi/simple/ --trusted-host mirrors.aliyun.com \
    construct==2.8.8 \
    fastapi==0.127.0 \
    requests==2.32.5 \
    uvicorn==0.40.0

# 第二阶段：运行时
FROM python:3.9-slim

WORKDIR /app

# 从构建阶段复制已安装的包
COPY --from=builder /usr/local/lib/python3.9/site-packages /usr/local/lib/python3.9/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# 复制应用文件
COPY yspapp.py .
COPY ysp.txt .

# 暴露端口
EXPOSE 10001

# 启动命令
CMD ["python", "yspapp.py"]