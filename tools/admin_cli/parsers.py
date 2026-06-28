"""argparse 子命令解析器。"""

from __future__ import annotations

import argparse


def build_users_subparser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="users")
    sub = parser.add_subparsers(dest="action", required=True)

    list_p = sub.add_parser("list", help="列出用户")
    list_p.add_argument("--keyword", help="关键词搜索")
    list_p.add_argument("--status", help="按状态筛选")
    list_p.add_argument("--role", help="按角色筛选")
    list_p.add_argument("--limit", type=int, default=20)
    list_p.add_argument("--offset", type=int, default=0)

    get_p = sub.add_parser("get", help="查看用户详情")
    get_p.add_argument("uuid", nargs="?", help="用户 UUID")

    create_p = sub.add_parser("create", help="创建用户")
    create_p.add_argument("--data", help="JSON 数据（不提供则交互式输入）")

    update_p = sub.add_parser("update", help="更新用户")
    update_p.add_argument("uuid", nargs="?", help="用户 UUID")
    update_p.add_argument("--data", help="JSON 数据（不提供则交互式输入）")

    delete_p = sub.add_parser("delete", help="删除用户")
    delete_p.add_argument("uuid", nargs="?", help="用户 UUID")
    delete_p.add_argument("--super-password", help="超级密码")

    reset_p = sub.add_parser("reset-password", help="重置用户密码")
    reset_p.add_argument("uuid", nargs="?", help="用户 UUID")
    reset_p.add_argument("--super-password", help="超级密码")
    reset_p.add_argument("--new-password", help="新密码（不提供则自动生成）")

    for action in ("ban", "unban", "disable", "enable"):
        p = sub.add_parser(action, help=f"{action} 用户")
        p.add_argument("uuid", nargs="?", help="用户 UUID")

    return parser


def build_questions_subparser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="questions")
    sub = parser.add_subparsers(dest="action", required=True)

    list_p = sub.add_parser("list", help="列出题目")
    list_p.add_argument("--keyword", help="关键词搜索")
    list_p.add_argument("--type", help="按题型筛选")
    list_p.add_argument("--status", help="按状态筛选")
    list_p.add_argument("--limit", type=int, default=20)
    list_p.add_argument("--offset", type=int, default=0)

    get_p = sub.add_parser("get", help="查看题目详情")
    get_p.add_argument("uuid", nargs="?", help="题目 UUID")

    create_p = sub.add_parser("create", help="创建题目")
    create_p.add_argument("--data", help="JSON 数据（不提供则交互式输入）")

    update_p = sub.add_parser("update", help="更新题目")
    update_p.add_argument("uuid", nargs="?", help="题目 UUID")
    update_p.add_argument("--data", help="JSON 数据（不提供则交互式输入）")

    delete_p = sub.add_parser("delete", help="删除题目")
    delete_p.add_argument("uuid", nargs="?", help="题目 UUID")

    return parser


def build_logs_subparser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="logs")
    sub = parser.add_subparsers(dest="action", required=True)

    for name in ("system", "personal"):
        p = sub.add_parser(name, help=f"查询{name}日志")
        p.add_argument("--event-type", help="事件类型")
        p.add_argument("--log-type", help="日志类型")
        p.add_argument("--status", help="状态")
        p.add_argument("--severity", help="严重级别")
        p.add_argument("--trace-id", help="Trace ID")
        p.add_argument("--client-ip", help="客户端 IP")
        p.add_argument("--keyword", help="内容关键词")
        p.add_argument("--start-time", help="开始时间 ISO")
        p.add_argument("--end-time", help="结束时间 ISO")
        p.add_argument("--limit", type=int, default=20)
        p.add_argument("--offset", type=int, default=0)

    personal = sub.choices["personal"]  # type: ignore[index]
    personal.add_argument("--user-uuid", help="指定用户 UUID（仅 superadmin）")
    return parser


def build_top_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Tinder 全系统管理 CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  %(prog)s                              # 启动交互式菜单
  %(prog)s --mode api users list
  %(prog)s --mode api --username admin --password xxx users reset-password <uuid>
  %(prog)s --mode db users get <uuid>
  %(prog)s --mode db db sql "SELECT * FROM users LIMIT 5"
        """.strip(),
    )
    parser.add_argument(
        "--mode",
        choices=("api", "db"),
        default=None,
        help="运行模式：api 通过接口调用，db 直连数据库（不传则交互式选择）",
    )
    parser.add_argument(
        "--api-url",
        default="http://localhost:1912",
        help="API 模式下的基础 URL",
    )
    parser.add_argument("--username", help="API 登录用户名")
    parser.add_argument("--password", help="API 登录密码（推荐交互式输入）")
    parser.add_argument(
        "--super-password", help="高危操作所需的超级密码（推荐交互式输入）"
    )
    parser.add_argument(
        "--non-interactive",
        action="store_true",
        help="禁用交互式 Q&A（脚本场景下缺失参数将报错）",
    )
    return parser


def build_base_parser() -> argparse.ArgumentParser:
    """仅解析全局选项的子解析器。"""
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--mode", choices=("api", "db"), default="api")
    parser.add_argument("--api-url", default="http://localhost:1912")
    parser.add_argument("--username")
    parser.add_argument("--password")
    parser.add_argument("--super-password")
    return parser
