FROM python:3.10-slim

WORKDIR /app

# 安装依赖
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 复制应用文件
COPY yspapp.py .
COPY ysp.txt .

# 暴露端口 - 根据你的需求用 10001 或 9006
EXPOSE 10001

# 运行应用
CMD ["python", "yspapp.py"]