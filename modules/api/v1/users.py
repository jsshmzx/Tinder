"""用户注册相关接口。

流程概述
--------
1. GET  /users/register/questions
   从 register_questions 表随机抽取 5 道 active 题目，将题目信息（含答案）
   序列化后存入 Redis（key 格式：``reg:qsheet:{sheet_id}``，TTL 24 小时）。
   返回给客户端的数据 **不含答案**，仅含题目 uuid 和题干。
   每个 IP 每天最多获取 4 张问题表（初始 1 张 + 换题 3 次）。

2. POST /users/register
   客户端携带问题表 id（``sheet_id``）和对应的答案列表（``answers``）提交注册请求。
   依次执行以下校验：
   a. IP 当日尝试总次数 ≤ 10
   b. real_name 当日尝试次数 ≤ 3
   c. sheet_id 对应的问题表存在且尝试次数 ≤ 3
   d. 至少 3 道题目答对
   e. 数据库中不存在相同姓名 + 班级的学生
   全部通过后写入用户信息，返回 JWT token 及基本用户数据。
"""

import json
import uuid as uuid_lib
from datetime import date
from typing import Any, Literal

from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel, Field, field_validator

from core.database.connection.pgsql import get_session
from core.database.connection.redis import redis_conn
from core.database.dao.register_questions import RegisterQuestionsDAO
from core.database.dao.users import UsersDAO
from core.helper.ContainerCustomLog.index import custom_log
from core.middleware.firewall.helpers import get_client_ip
from core.security.jwt_handler import create_access_token

router = APIRouter(prefix="/users", tags=["Users v1"])

# ---------------------------------------------------------------------------
# Redis key 前缀常量
# ---------------------------------------------------------------------------
_REDIS_QSHEET_PREFIX = "reg:qsheet:"          # reg:qsheet:{sheet_id}  → JSON
_REDIS_QSHEET_ATTEMPTS = "reg:qsheet_atm:"    # reg:qsheet_atm:{sheet_id} → int
_REDIS_IP_ATTEMPTS = "reg:ip_atm:"            # reg:ip_atm:{ip}:{date} → int
_REDIS_NAME_ATTEMPTS = "reg:name_atm:"        # reg:name_atm:{name}:{date} → int
_REDIS_IP_SHEETS = "reg:ip_sheets:"           # reg:ip_sheets:{ip}:{date} → int

# 限额配置
_MAX_IP_ATTEMPTS_PER_DAY = 10     # IP 每日最大注册尝试次数
_MAX_NAME_ATTEMPTS_PER_DAY = 3    # 同一 real_name 每日最大尝试次数
_MAX_SHEET_ATTEMPTS = 3           # 每张问题表最大回答尝试次数
_MAX_SHEETS_PER_IP_PER_DAY = 4   # 每个 IP 每天最多获取的问题表数（含首张）
_CORRECT_THRESHOLD = 3            # 答对题目数阈值
_QUESTION_COUNT = 5               # 每张问题表的题目数量
_SHEET_TTL_SECONDS = 86400        # 问题表在 Redis 中的过期时间（24 小时）


# ---------------------------------------------------------------------------
# Pydantic 模型
# ---------------------------------------------------------------------------

class AnswerItem(BaseModel):
    """单题答案。"""

    question_uuid: str = Field(..., description="题目的 uuid")
    answer: str = Field(..., description="用户的回答（大小写不敏感）")


class RegisterRequest(BaseModel):
    """注册请求体。"""

    nickname: str = Field(..., min_length=1, max_length=50, description="昵称")
    real_name: str = Field(..., min_length=1, max_length=50, description="真实姓名")
    classtype: Literal["high-school", "university"] = Field(..., description="学段：high-school 或 university")
    class_: str = Field(..., alias="class", min_length=1, max_length=50, description="班级")
    sheet_id: str = Field(..., description="问题表 ID（从 GET /users/register/questions 获取）")
    answers: list[AnswerItem] = Field(..., description="答案列表，需包含 5 道题的回答")

    model_config = {"populate_by_name": True}

    @field_validator("nickname", "real_name", "class_")
    @classmethod
    def no_control_chars(cls, v: str) -> str:
        """拒绝包含控制字符的输入，防止注入风险。"""
        if any(ord(c) < 0x20 for c in v):
            raise ValueError("字段不能包含控制字符")
        return v.strip()


# ---------------------------------------------------------------------------
# Redis 辅助函数
# ---------------------------------------------------------------------------

def _today_str() -> str:
    """返回今日日期字符串，格式 YYYY-MM-DD（上海时区与 UTC 差 8 小时，此处使用 UTC 日期即可）。"""
    return date.today().isoformat()


def _normalize_answer(text: str) -> str:
    """统一答案格式：去除首尾空白并转换为小写，用于答案存储和校验时的一致比较。"""
    return text.strip().lower()


def _redis_get_int(client, key: str) -> int:
    """安全地从 Redis 获取整数值，键不存在或出错时返回 0。"""
    try:
        val = client.get(key)
        return int(val) if val else 0
    except Exception:
        return 0


def _redis_incr_with_ttl(client, key: str, ttl: int) -> int:
    """原子地递增 Redis 计数器并设置/刷新 TTL，返回递增后的值。"""
    try:
        count = client.incr(key)
        if count == 1:
            client.expire(key, ttl)
        return count
    except Exception as exc:
        custom_log("ERROR", f"[Register] Redis incr 失败 key={key}: {exc}")
        return 0


# ---------------------------------------------------------------------------
# GET /users/register/questions — 获取问题表
# ---------------------------------------------------------------------------

@router.get("/register/questions", response_model=dict[str, Any])
async def get_register_questions(request: Request):
    """随机生成一张注册问题表并存入 Redis，返回题目信息（不含答案）。

    每个 IP 每天最多获取 {_MAX_SHEETS_PER_IP_PER_DAY} 张问题表。
    """
    client_ip = get_client_ip(request)
    redis = redis_conn.get_client()

    # ----- 检查 IP 换题次数 -----
    if redis is not None:
        today = _today_str()
        sheets_key = f"{_REDIS_IP_SHEETS}{client_ip}:{today}"
        current_sheets = _redis_get_int(redis, sheets_key)
        if current_sheets >= _MAX_SHEETS_PER_IP_PER_DAY:
            custom_log(
                "WARNING",
                f"[Register] IP {client_ip} 今日问题表申请次数已达上限 {_MAX_SHEETS_PER_IP_PER_DAY}",
            )
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"今日问题表申请次数已达上限（{_MAX_SHEETS_PER_IP_PER_DAY} 张），请明日再试",
            )

    # ----- 随机抽取题目 -----
    questions = await RegisterQuestionsDAO.find_random_active(count=_QUESTION_COUNT)
    if len(questions) < _QUESTION_COUNT:
        custom_log("WARNING", f"[Register] 题库中 active 题目不足 {_QUESTION_COUNT} 道，实际获取 {len(questions)} 道")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="题库暂时不可用，请稍后再试",
        )

    # ----- 生成 sheet_id，存入 Redis -----
    sheet_id = str(uuid_lib.uuid4())
    # 存储完整题目数据（含答案），供校验时使用
    sheet_data = {
        "questions": [{"uuid": q["uuid"], "question": q["question"]} for q in questions],
        "answers": {q["uuid"]: q["answer"].strip().lower() for q in questions},
        "issued_ip": client_ip,
    }

    if redis is not None:
        try:
            redis.set(
                f"{_REDIS_QSHEET_PREFIX}{sheet_id}",
                json.dumps(sheet_data, ensure_ascii=False),
                ex=_SHEET_TTL_SECONDS,
            )
            # 递增 IP 今日问题表计数
            _redis_incr_with_ttl(redis, f"{_REDIS_IP_SHEETS}{client_ip}:{_today_str()}", _SHEET_TTL_SECONDS)
        except Exception as exc:
            custom_log("ERROR", f"[Register] Redis 写入问题表失败: {exc}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="服务暂时不可用，请稍后再试",
            )
    else:
        # Redis 不可用时拒绝服务，避免无限制注册
        custom_log("ERROR", "[Register] Redis 不可用，拒绝问题表请求")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="服务暂时不可用，请稍后再试",
        )

    custom_log("SUCCESS", f"[Register] IP {client_ip} 获取问题表 sheet_id={sheet_id}")
    return {
        "sheet_id": sheet_id,
        "questions": sheet_data["questions"],  # 不含答案
    }


# ---------------------------------------------------------------------------
# POST /users/register — 注册
# ---------------------------------------------------------------------------

@router.post("/register", response_model=dict[str, Any], status_code=status.HTTP_201_CREATED)
async def register_user(body: RegisterRequest, request: Request):
    """用户注册接口。

    校验流程：
    1. IP 当日尝试次数 ≤ 10
    2. real_name 当日尝试次数 ≤ 3
    3. sheet_id 对应的问题表存在且尝试次数 ≤ 3
    4. 至少 3 道题目答对
    5. 数据库中不存在相同 real_name + class 的学生
    全部通过后创建用户并返回 JWT token。
    """
    client_ip = get_client_ip(request)
    today = _today_str()
    redis = redis_conn.get_client()

    # ----------------------------------------------------------------
    # 步骤 1：检查 IP 当日注册尝试次数
    # ----------------------------------------------------------------
    if redis is None:
        custom_log("ERROR", "[Register] Redis 不可用，拒绝注册请求")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="服务暂时不可用，请稍后再试",
        )

    ip_attempts_key = f"{_REDIS_IP_ATTEMPTS}{client_ip}:{today}"
    ip_attempts = _redis_get_int(redis, ip_attempts_key)
    if ip_attempts >= _MAX_IP_ATTEMPTS_PER_DAY:
        custom_log("WARNING", f"[Register] IP {client_ip} 今日注册尝试次数已达上限")
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"该 IP 今日注册尝试次数已达上限（{_MAX_IP_ATTEMPTS_PER_DAY} 次），请明日再试",
        )

    # ----------------------------------------------------------------
    # 步骤 2：检查 real_name 当日尝试次数
    # ----------------------------------------------------------------
    # 使用 real_name 的十六进制编码作为 key，避免特殊字符问题
    name_key_part = body.real_name.encode("utf-8").hex()
    name_attempts_key = f"{_REDIS_NAME_ATTEMPTS}{name_key_part}:{today}"
    name_attempts = _redis_get_int(redis, name_attempts_key)
    if name_attempts >= _MAX_NAME_ATTEMPTS_PER_DAY:
        custom_log("WARNING", f"[Register] real_name '{body.real_name}' 今日尝试次数已达上限")
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"该姓名今日注册尝试次数已达上限（{_MAX_NAME_ATTEMPTS_PER_DAY} 次），请明日再试",
        )

    # ----------------------------------------------------------------
    # 步骤 3：验证问题表存在且未超过最大尝试次数
    # ----------------------------------------------------------------
    sheet_redis_key = f"{_REDIS_QSHEET_PREFIX}{body.sheet_id}"
    sheet_attempts_key = f"{_REDIS_QSHEET_ATTEMPTS}{body.sheet_id}"

    try:
        sheet_raw = redis.get(sheet_redis_key)
    except Exception as exc:
        custom_log("ERROR", f"[Register] Redis 读取问题表失败: {exc}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="服务暂时不可用，请稍后再试",
        )

    if not sheet_raw:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="问题表不存在或已过期，请重新获取",
        )

    try:
        sheet_data: dict = json.loads(sheet_raw)
    except (json.JSONDecodeError, TypeError):
        custom_log("ERROR", f"[Register] 问题表数据损坏 sheet_id={body.sheet_id}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="服务暂时不可用，请稍后再试",
        )

    sheet_attempts = _redis_get_int(redis, sheet_attempts_key)
    if sheet_attempts >= _MAX_SHEET_ATTEMPTS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"该问题表尝试次数已达上限（{_MAX_SHEET_ATTEMPTS} 次），请换一张问题表",
        )

    # ----------------------------------------------------------------
    # 递增各计数器（在校验答案前，防止暴力枚举）
    # ----------------------------------------------------------------
    _redis_incr_with_ttl(redis, ip_attempts_key, _SHEET_TTL_SECONDS)
    _redis_incr_with_ttl(redis, name_attempts_key, _SHEET_TTL_SECONDS)
    _redis_incr_with_ttl(redis, sheet_attempts_key, _SHEET_TTL_SECONDS)

    # ----------------------------------------------------------------
    # 步骤 4：校验答案（大小写不敏感，至少答对 3 题）
    # ----------------------------------------------------------------
    correct_answers: dict[str, str] = sheet_data.get("answers", {})
    correct_count = 0
    for item in body.answers:
        expected = correct_answers.get(item.question_uuid)
        if expected is not None and item.answer.strip().lower() == expected:
            correct_count += 1

    custom_log(
        "SUCCESS" if correct_count >= _CORRECT_THRESHOLD else "WARNING",
        f"[Register] IP={client_ip} real_name='{body.real_name}' "
        f"sheet_id={body.sheet_id} 答对 {correct_count}/{_QUESTION_COUNT}",
    )

    if correct_count < _CORRECT_THRESHOLD:
        remaining = _MAX_SHEET_ATTEMPTS - (sheet_attempts + 1)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"答题未通过（答对 {correct_count} 道，需至少 {_CORRECT_THRESHOLD} 道）。"
                   f"该问题表剩余尝试次数：{max(remaining, 0)}",
        )

    # ----------------------------------------------------------------
    # 步骤 5：检查是否存在重复学生（相同 real_name + class）
    # ----------------------------------------------------------------
    async with get_session() as session:
        duplicate = await UsersDAO.find_duplicate_student(session, body.real_name, body.class_)
        if duplicate:
            custom_log(
                "WARNING",
                f"[Register] 重复学生 real_name='{body.real_name}' class='{body.class_}'",
            )
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="该姓名和班级的学生已存在，如有问题请联系管理员",
            )

    # ----------------------------------------------------------------
    # 步骤 6：创建用户
    # ----------------------------------------------------------------
    new_uuid = str(uuid_lib.uuid4())
    user_data = {
        "uuid": new_uuid,
        "nickname": body.nickname,
        "real_name": body.real_name,
        "class": body.class_,
        "class_type": body.classtype,
        "user_role": "normal-user",
        "is_verified": False,
        "current_status": "normal",
    }

    try:
        created_user = await UsersDAO().create(user_data)
    except Exception as exc:
        custom_log("ERROR", f"[Register] 用户写入数据库失败: {exc}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="注册失败，请稍后重试",
        )

    # 注册成功后删除问题表，防止同一张表被再次使用
    try:
        redis.delete(sheet_redis_key)
        redis.delete(sheet_attempts_key)
    except Exception as exc:
        custom_log("WARNING", f"[Register] 清理 Redis 问题表失败（不影响注册结果）: {exc}")

    # ----------------------------------------------------------------
    # 步骤 7：生成初始 JWT token 并返回
    # ----------------------------------------------------------------
    access_token = create_access_token(subject=new_uuid)
    custom_log("SUCCESS", f"[Register] 新用户注册成功 uuid={new_uuid} real_name='{body.real_name}'")

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": {
            "uuid": created_user["uuid"],
            "nickname": created_user["nickname"],
            "real_name": created_user["real_name"],
            "class": created_user.get("class"),
            "class_type": created_user["class_type"],
            "role": created_user["user_role"],
            "is_verified": created_user["is_verified"],
            "status": created_user["current_status"],
        },
    }
