FROM python:3.9-slim

WORKDIR /app

# 安装编译工具
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    curl \
    && rm -rf /var/lib/apt/lists/*

# 复制应用文件
COPY . .

# 尝试多个镜像源
RUN pip install --no-cache-dir -i https://pypi.tuna.tsinghua.edu.cn/simple --trusted-host pypi.tuna.tsinghua.edu.cn \
    construct==2.8.8 fastapi==0.127.0 requests==2.32.5 uvicorn==0.40.0 || \
    pip install --no-cache-dir -i https://mirrors.cloud.tencent.com/pypi/simple --trusted-host mirrors.cloud.tencent.com \
    construct==2.8.8 fastapi==0.127.0 requests==2.32.5 uvicorn==0.40.0 || \
    pip install --no-cache-dir -i https://pypi.douban.com/simple --trusted-host pypi.douban.com \
    construct==2.8.8 fastapi==0.127.0 requests==2.32.5 uvicorn==0.40.0 || \
    pip install --no-cache-dir \
    construct==2.8.8 fastapi==0.127.0 requests==2.32.5 uvicorn==0.40.0

EXPOSE 10001

CMD ["python", "yspapp.py"]