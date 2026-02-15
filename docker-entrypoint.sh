#!/bin/bash
set -e

# 运行数据库迁移脚本

python3 db_migrate.py


# 启动server.py
python3 server.py
