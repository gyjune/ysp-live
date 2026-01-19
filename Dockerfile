# 使用包含常用依赖的 Python 镜像
FROM python:3.9

WORKDIR /app

# 复制文件
COPY yspapp.py .
COPY ysp.txt .
COPY requirements.txt .

# 使用系统默认源，不指定镜像
# 只安装核心依赖，去掉版本号
RUN pip install --no-cache-dir \
    construct \
    fastapi \
    requests \
    uvicorn

EXPOSE 10001

CMD ["python", "yspapp.py"]