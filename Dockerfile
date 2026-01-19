FROM python:3.9-slim

WORKDIR /app

# 安装依赖
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# 复制应用文件
COPY requirements.txt .
COPY yspapp.py .
COPY ysp.txt .

# 安装Python依赖
RUN pip install --no-cache-dir -r requirements.txt

# 暴露端口
EXPOSE 10001

# 启动命令
CMD ["python", "yspapp.py"]