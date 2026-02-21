# 导入pgsql
import psycopg2
from psycopg2 import sql
import os
from datetime import datetime
import dotenv
from core.helper.ContainerCustomLog.index import custom_log

# 连接数据库
# 从环境变量获取 DATABASE_URL
def connect_to_database():
    """连接到数据库"""
    # 如果.env文件存在
    if os.path.exists('.env'):
        dotenv.load_dotenv('.env')
        url = os.getenv('DATABASE_URL')
    else:
        # 否则从环境变量获取 DATABASE_URL
        url = os.getenv('DATABASE_URL')
    
    try:
        conn = psycopg2.connect(url)
        custom_log("SUCCESS", "数据库连接成功")
        return conn
    except psycopg2.Error as e:
        custom_log("ERROR", f"数据库连接失败: {e}")
        raise

# 创建migration_history表
def create_migration_history_table(conn):
    """创建migration_history表来记录迁移历史"""
    cursor = conn.cursor()
    
    try:
        # 创建migration_history表
        create_table_sql = """
        CREATE TABLE IF NOT EXISTS migration_history (
            id SERIAL PRIMARY KEY,
            migration_name VARCHAR(255) NOT NULL UNIQUE,
            executed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            status VARCHAR(50) DEFAULT 'success',
            error_message TEXT
        );
        """
        
        cursor.execute(create_table_sql)
        conn.commit()
        custom_log("SUCCESS", "migration_history 表创建成功")
        
    except psycopg2.Error as e:
        conn.rollback()
        custom_log("ERROR", f"创建表失败: {e}")
        raise
    finally:
        cursor.close()


def execute_migrations(conn):
    # 导入migration列表
    from core.database.migrations.migration_history import migration_history
    """执行迁移脚本"""
    for migration in migration_history:
        if migration not in os.listdir('core/database/migrations/SQL'):
            custom_log("ERROR", f"迁移脚本不存在: {migration}")
            continue
        cursor = conn.cursor()
        try:
            # 检查该迁移是否已执行
            check_sql = "SELECT COUNT(*) FROM migration_history WHERE migration_name = %s;"
            cursor.execute(check_sql, (migration,))
            count = cursor.fetchone()[0]
            if count == 0:
                # 执行迁移脚本
                with open(f'core/database/migrations/SQL/{migration}', 'r') as f:
                    sql_script = f.read()
                cursor.execute(sql_script)
                # 记录迁移历史
                insert_sql = "INSERT INTO migration_history (migration_name, status, executed_at) VALUES (%s, %s, CURRENT_TIMESTAMP AT TIME ZONE 'Asia/Shanghai');"
                cursor.execute(insert_sql, (migration, 'success'))
                conn.commit()
                custom_log("SUCCESS", f"迁移脚本执行成功: {migration}")
        except Exception as e:
            conn.rollback()
            cursor.execute("INSERT INTO migration_history (migration_name, status, error_message) VALUES (%s, %s, %s);", (migration, 'failed', str(e)))
            conn.commit()
            custom_log("ERROR", f"执行迁移脚本失败: {migration}, 错误: {e}")
        finally:
            cursor.close()

# 主函数
if __name__ == "__main__":
    try:
        # 连接数据库
        conn = connect_to_database()
        
        # 创建migration_history表
        create_migration_history_table(conn)

        # 执行迁移脚本
        execute_migrations(conn)
        
        # 关闭连接
        conn.close()
        custom_log("SUCCESS", "数据库迁移完成，连接已关闭")
        
    except Exception as e:
        custom_log("ERROR", f"执行迁移时出错: {e}")
        exit(1)
