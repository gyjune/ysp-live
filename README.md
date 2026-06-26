# 从 Docker Hub 拉取并运行
docker run -d \
  --name ysp-live \
  --restart unless-stopped \
  -p 10001:10001 \
  gyjune/ysp-live:latest

# 从 GitHub Packages 拉取并运行
docker run -d \
  --name ysp-live \
  --restart unless-stopped \
  -p 10001:10001 \
  ghcr.io/gyjune/ysp-live:latest
