FROM python:3.14-slim

WORKDIR /app
ENV APP_ENV=production
# 复制requirements文件
COPY requirements.txt .

# 安装依赖
RUN pip3 install --no-cache-dir -r requirements.txt

# 复制应用文件
COPY . .

# 赋予entrypoint脚本执行权限
RUN chmod +x docker-entrypoint.sh

# 设置entrypoint
ENTRYPOINT ["/bin/bash", "docker-entrypoint.sh"]
