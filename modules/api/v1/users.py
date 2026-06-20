"""用户模块 — 注册、个人信息、注销。

注册流程（三步）
--------------
1. POST /users/register/sheet/request
   获取答题卡（IP 每日 4 次），返回 sheet_id + 5 道不含答案的题目。

2. POST /users/register
   提交答案（IP 每日 10 次 / 姓名每日 3 次 / 每答题卡 3 次），
   至少答对 3 道 → 创建用户（password=NULL）→ 颁发临时 token（15min）。

3. POST /users/register/complete
   携带临时 token，设置 username + password + email → 返回正式 JWT token。

其他端点
--------
- GET    /users/me              — 获取完整个人信息
- PATCH  /users/me/password     — 修改密码
- PATCH  /users/me/profile      — 修改个人信息
- DELETE /users/me              — 账号注销（30 天冷却期）
"""

import json
import uuid as uuid_lib
from datetime import date, datetime, timedelta
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field, field_validator, model_validator

from core.database.connection.pgsql import get_session
from core.database.connection.redis import redis_conn
from core.database.dao.refresh_tokens import RefreshTokensDAO
from core.database.dao.register_questions import RegisterQuestionsDAO
from core.database.dao.users import UsersDAO
from core.config import settings
from core.helper.ContainerCustomLog.index import custom_log
from core.middleware.auth.dependencies import get_current_user, get_temp_user, invalidate_user_cache
from core.middleware.firewall.helpers import get_client_ip
from core.security.hash import get_password_hash, verify_password
from core.security.jwt_handler import create_access_token, create_temp_token, generate_refresh_token

router = APIRouter(prefix="/users", tags=["Users v1"])

# ---------------------------------------------------------------------------
# Redis key 前缀常量
# ---------------------------------------------------------------------------
_REDIS_QSHEET_PREFIX = "reg:qsheet:"          # reg:qsheet:{sheet_id}  → JSON
_REDIS_QSHEET_ATTEMPTS = "reg:qsheet_atm:"    # reg:qsheet_atm:{sheet_id} → int
_REDIS_IP_ATTEMPTS = "reg:ip_atm:"            # reg:ip_atm:{ip}:{date} → int
_REDIS_NAME_ATTEMPTS = "reg:name_atm:"        # reg:name_atm:{name}:{date} → int
_REDIS_IP_SHEETS = "reg:ip_sheets:"           # reg:ip_sheets:{ip}:{date} → int


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
# POST /users/register/sheet/request — 获取答题卡
# ---------------------------------------------------------------------------

@router.post("/register/sheet/request", response_model=dict[str, Any])
async def request_register_sheet(request: Request):
    """随机生成一张注册问题表并存入 Redis，返回题目信息（不含答案）。

    每个 IP 每天最多获取 {settings.REG_MAX_SHEETS_PER_IP_PER_DAY} 张问题表。
    """
    client_ip = get_client_ip(request)
    redis = redis_conn.get_client()

    # ----- 检查 IP 换题次数 -----
    if redis is not None:
        today = _today_str()
        sheets_key = f"{_REDIS_IP_SHEETS}{client_ip}:{today}"
        current_sheets = _redis_get_int(redis, sheets_key)
        if current_sheets >= settings.REG_MAX_SHEETS_PER_IP_PER_DAY:
            custom_log(
                "WARNING",
                f"[Register] IP {client_ip} 今日问题表申请次数已达上限 {settings.REG_MAX_SHEETS_PER_IP_PER_DAY}",
            )
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"今日问题表申请次数已达上限（{settings.REG_MAX_SHEETS_PER_IP_PER_DAY} 张），请明日再试",
            )

    # ----- 随机抽取题目 -----
    questions = await RegisterQuestionsDAO.find_random_active(count=settings.REG_QUESTION_COUNT)
    if len(questions) < settings.REG_QUESTION_COUNT:
        custom_log("WARNING", f"[Register] 题库中 active 题目不足 {settings.REG_QUESTION_COUNT} 道，实际获取 {len(questions)} 道")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="题库暂时不可用，请稍后再试",
        )

    # ----- 生成 sheet_id，存入 Redis -----
    sheet_id = str(uuid_lib.uuid4())
    # 存储完整题目数据（含答案），供校验时使用
    sheet_data = {
        "questions": [{"uuid": q["uuid"], "question": q["question"]} for q in questions],
        "answers": {q["uuid"]: _normalize_answer(q["answer"]) for q in questions},
        "issued_ip": client_ip,
    }

    if redis is not None:
        try:
            redis.set(
                f"{_REDIS_QSHEET_PREFIX}{sheet_id}",
                json.dumps(sheet_data, ensure_ascii=False),
                ex=settings.REG_SHEET_TTL_SECONDS,
            )
            # 递增 IP 今日问题表计数
            _redis_incr_with_ttl(redis, f"{_REDIS_IP_SHEETS}{client_ip}:{_today_str()}", settings.REG_SHEET_TTL_SECONDS)
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
    if ip_attempts >= settings.REG_MAX_IP_ATTEMPTS_PER_DAY:
        custom_log("WARNING", f"[Register] IP {client_ip} 今日注册尝试次数已达上限")
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"该 IP 今日注册尝试次数已达上限（{settings.REG_MAX_IP_ATTEMPTS_PER_DAY} 次），请明日再试",
        )

    # ----------------------------------------------------------------
    # 步骤 2：检查 real_name 当日尝试次数
    # ----------------------------------------------------------------
    # 使用 real_name 的十六进制编码作为 key，避免特殊字符问题
    name_key_part = body.real_name.encode("utf-8").hex()
    name_attempts_key = f"{_REDIS_NAME_ATTEMPTS}{name_key_part}:{today}"
    name_attempts = _redis_get_int(redis, name_attempts_key)
    if name_attempts >= settings.REG_MAX_NAME_ATTEMPTS_PER_DAY:
        custom_log("WARNING", f"[Register] real_name '{body.real_name}' 今日尝试次数已达上限")
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"该姓名今日注册尝试次数已达上限（{settings.REG_MAX_NAME_ATTEMPTS_PER_DAY} 次），请明日再试",
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
    if sheet_attempts >= settings.REG_MAX_SHEET_ATTEMPTS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"该问题表尝试次数已达上限（{settings.REG_MAX_SHEET_ATTEMPTS} 次），请换一张问题表",
        )

    # ----------------------------------------------------------------
    # 递增各计数器（在校验答案前，防止暴力枚举）
    # ----------------------------------------------------------------
    _redis_incr_with_ttl(redis, ip_attempts_key, settings.REG_SHEET_TTL_SECONDS)
    _redis_incr_with_ttl(redis, name_attempts_key, settings.REG_SHEET_TTL_SECONDS)
    _redis_incr_with_ttl(redis, sheet_attempts_key, settings.REG_SHEET_TTL_SECONDS)

    # ----------------------------------------------------------------
    # 步骤 4：校验答案（大小写不敏感，至少答对 3 题）
    # ----------------------------------------------------------------
    correct_answers: dict[str, str] = sheet_data.get("answers", {})
    correct_count = 0
    for item in body.answers:
        expected = correct_answers.get(item.question_uuid)
        if expected is not None and _normalize_answer(item.answer) == expected:
            correct_count += 1

    custom_log(
        "SUCCESS" if correct_count >= settings.REG_CORRECT_THRESHOLD else "WARNING",
        f"[Register] IP={client_ip} real_name='{body.real_name}' "
        f"sheet_id={body.sheet_id} 答对 {correct_count}/{settings.REG_QUESTION_COUNT}",
    )

    if correct_count < settings.REG_CORRECT_THRESHOLD:
        # sheet_attempts 已在步骤 3 之后递增，所以此处加 1 反映本次消耗后的最新值
        remaining = settings.REG_MAX_SHEET_ATTEMPTS - (sheet_attempts + 1)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"答题未通过（答对 {correct_count} 道，需至少 {settings.REG_CORRECT_THRESHOLD} 道）。"
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
    # 步骤 7：颁发临时 token（仅用于 Step 2 完成注册）
    # ----------------------------------------------------------------
    temp_token = create_temp_token(subject=new_uuid, purpose="register_complete", expires_minutes=settings.TEMP_TOKEN_EXPIRE_MINUTES)
    custom_log("SUCCESS", f"[Register] 新用户答题通过 uuid={new_uuid} real_name='{body.real_name}'")

    return {
        "temp_token": temp_token,
        "token_type": "bearer",
        "expires_in": 900,
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


# ---------------------------------------------------------------------------
# POST /users/register/complete — Step 2 完成注册
# ---------------------------------------------------------------------------

@router.post("/register/complete", response_model=dict[str, Any], status_code=status.HTTP_201_CREATED)
async def complete_register(
    body: CompleteRegisterRequest,
    temp_user: dict = Depends(get_temp_user),
):
    """完成注册 Step 2：设置用户名和密码，返回正式 JWT token。

    认证：临时 token（purpose="register_complete"），15 分钟有效。
    验证用户名和邮箱唯一性后，写入 password/username/email。
    """
    user_uuid: str = temp_user["uuid"]

    async with get_session() as session:
        # 验证 username 唯一性
        existing = await UsersDAO.find_by_username(session, body.username)
        if existing and str(existing.uuid) != user_uuid:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="用户名已被使用",
            )

        # 验证 email 唯一性（若提供）
        if body.email:
            email_user = await UsersDAO.find_by_username_or_email(session, body.email)
            if email_user and str(email_user.uuid) != user_uuid:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="邮箱已被使用",
                )

    # 更新用户：设置密码、用户名、邮箱
    update_data: dict[str, Any] = {
        "password": body.password,
        "username": body.username,
    }
    if body.email:
        update_data["email"] = body.email

    updated_user = await UsersDAO().update(user_uuid, update_data)
    if updated_user is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="完成注册失败，用户不存在",
        )

    # 颁发正式 token
    access_token = create_access_token(subject=user_uuid)
    plaintext, token_hash = generate_refresh_token()
    await RefreshTokensDAO.create(user_uuid=user_uuid, token_hash=token_hash)

    custom_log("SUCCESS", f"[RegisterComplete] uuid={user_uuid} username={body.username} 注册完成")

    return {
        "access_token": access_token,
        "refresh_token": plaintext,
        "token_type": "bearer",
        "user": {
            "uuid": updated_user["uuid"],
            "nickname": updated_user.get("nickname"),
            "real_name": updated_user.get("real_name"),
            "username": updated_user.get("username"),
            "email": updated_user.get("email"),
            "class": updated_user.get("class"),
            "class_type": updated_user.get("class_type"),
            "role": updated_user.get("user_role"),
            "is_verified": updated_user.get("is_verified"),
            "status": updated_user.get("current_status"),
        },
    }


# ---------------------------------------------------------------------------
# Pydantic 模型 — 修改密码 & 修改个人信息
# ---------------------------------------------------------------------------

class ChangePasswordRequest(BaseModel):
    """修改密码请求体。"""

    old_password: str = Field(..., min_length=64, max_length=64, description="当前密码（64 字符 SHA256 hex）")
    new_password: str = Field(
        ..., min_length=64, max_length=64, description="新密码（64 字符 SHA256 hex）"
    )
    refresh_token: str | None = Field(
        None,
        description="当前设备的 Refresh Token（可选，提供后将自动吊销该设备的 Refresh Token）",
    )

    @field_validator("old_password", "new_password")
    @classmethod
    def password_must_be_hex64(cls, v: str) -> str:
        """密码必须为 64 字符 SHA256 hex 字符串。"""
        import re
        if not re.fullmatch(r"[a-fA-F0-9]{64}", v):
            raise ValueError("密码必须为 64 字符 SHA256 哈希值（hex）")
        return v


class CompleteRegisterRequest(BaseModel):
    """Step 2 完成注册请求体。"""

    username: str = Field(
        ..., min_length=3, max_length=20, description="用户名（3-20 字符，仅字母数字下划线）"
    )
    password: str = Field(..., description="SHA256 双重哈希后的 64 字符 hex 字符串")
    email: str | None = Field(None, description="邮箱（可选）")

    @field_validator("username")
    @classmethod
    def username_alphanumeric(cls, v: str) -> str:
        """仅允许字母、数字、下划线。"""
        import re
        if not re.fullmatch(r"[a-zA-Z0-9_]+", v):
            raise ValueError("用户名仅允许字母、数字和下划线")
        return v

    @field_validator("password")
    @classmethod
    def password_must_be_hex64(cls, v: str) -> str:
        """密码必须为 64 字符 SHA256 hex 字符串。"""
        import re
        if len(v) != 64 or not re.fullmatch(r"[a-fA-F0-9]{64}", v):
            raise ValueError("密码必须为 64 字符 SHA256 哈希值（hex）")
        return v


class DeleteAccountRequest(BaseModel):
    """账号注销请求体 — 需密码确认。"""

    password: str = Field(..., description="SHA256 双重哈希后的 64 字符 hex 字符串")


class UpdateProfileRequest(BaseModel):
    """修改个人信息请求体，所有字段均为可选，但至少需要提供一个。"""

    nickname: str | None = Field(None, min_length=1, max_length=50, description="新昵称")
    real_name: str | None = Field(None, min_length=1, max_length=50, description="新真实姓名")
    class_: str | None = Field(None, alias="class", min_length=1, max_length=50, description="新班级")

    model_config = {"populate_by_name": True}

    @field_validator("nickname", "real_name", "class_")
    @classmethod
    def no_control_chars(cls, v: str | None) -> str | None:
        """拒绝包含控制字符的输入，防止注入风险。"""
        if v is None:
            return v
        if any(ord(c) < 0x20 for c in v):
            raise ValueError("字段不能包含控制字符")
        return v.strip()

    @model_validator(mode="after")
    def at_least_one_field_provided(self) -> "UpdateProfileRequest":
        """至少需要提供一个修改字段。"""
        if self.nickname is None and self.real_name is None and self.class_ is None:
            raise ValueError("至少需要提供一个修改字段（nickname、real_name 或 class）")
        return self


# ---------------------------------------------------------------------------
# PATCH /users/me/password — 修改密码
# ---------------------------------------------------------------------------

@router.patch("/me/password", response_model=dict[str, Any])
async def change_password(
    body: ChangePasswordRequest,
    current_user: dict = Depends(get_current_user),
):
    """已登录用户修改密码接口。

    校验流程：
    1. 账号状态正常（未被封禁）
    2. Redis 限流：每用户每天最多 {settings.MAX_PWD_CHG_ATTEMPTS_PER_DAY} 次
    3. 账号已设置密码
    4. 旧密码验证正确
    5. 新密码与旧密码不相同
    全部通过后更新数据库中的哈希密码。
    """
    user_uuid: str = current_user["uuid"]

    # ----------------------------------------------------------------
    # 步骤 1：检查账号状态（已封禁或异常的账号拒绝操作）
    # ----------------------------------------------------------------
    if current_user.get("current_status") not in (None, "normal"):
        custom_log("WARNING", f"[ChangePassword] uuid={user_uuid} 账号状态异常，拒绝修改密码")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="账号状态异常，无法修改密码",
        )

    # ----------------------------------------------------------------
    # 步骤 2：Redis 限流（每用户每天最多尝试 settings.MAX_PWD_CHG_ATTEMPTS_PER_DAY 次）
    # ----------------------------------------------------------------
    redis = redis_conn.get_client()
    if redis is not None:
        today = _today_str()
        pwd_chg_key = f"user:pwd_chg:{user_uuid}:{today}"
        attempts = _redis_get_int(redis, pwd_chg_key)
        if attempts >= settings.MAX_PWD_CHG_ATTEMPTS_PER_DAY:
            custom_log("WARNING", f"[ChangePassword] uuid={user_uuid} 今日修改密码次数已达上限")
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"今日修改密码次数已达上限（{settings.MAX_PWD_CHG_ATTEMPTS_PER_DAY} 次），请明日再试",
            )
        # 在验证前递增计数器，防止暴力枚举
        _redis_incr_with_ttl(redis, pwd_chg_key, settings.REG_SHEET_TTL_SECONDS)

    # ----------------------------------------------------------------
    # 步骤 3：检查账号是否已设置密码
    # ----------------------------------------------------------------
    async with get_session() as session:
        current_hashed: str | None = await UsersDAO.find_password_hash(session, user_uuid)
    if not current_hashed:
        custom_log("WARNING", f"[ChangePassword] uuid={user_uuid} 账号未设置密码，无法通过旧密码验证")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="当前账号未设置密码，无法通过旧密码验证修改密码",
        )

    # ----------------------------------------------------------------
    # 步骤 4：验证旧密码
    # ----------------------------------------------------------------
    if not verify_password(body.old_password, current_hashed):
        custom_log("WARNING", f"[ChangePassword] uuid={user_uuid} 旧密码验证失败")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="旧密码不正确",
        )

    # ----------------------------------------------------------------
    # 步骤 5：新密码不能与旧密码相同
    # ----------------------------------------------------------------
    if verify_password(body.new_password, current_hashed):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="新密码不能与旧密码相同",
        )

    # ----------------------------------------------------------------
    # 步骤 6：更新数据库
    # ----------------------------------------------------------------
    new_hashed = get_password_hash(body.new_password)
    try:
        updated = await UsersDAO().update(user_uuid, {"password": new_hashed})
    except Exception as exc:
        custom_log("ERROR", f"[ChangePassword] uuid={user_uuid} 密码更新失败: {exc}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="密码修改失败，请稍后重试",
        )

    if updated is None:
        custom_log("ERROR", f"[ChangePassword] uuid={user_uuid} 用户不存在（update 返回 None）")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="用户不存在",
        )

    # 密码变更后，撤销该用户的所有 Refresh Token，强制所有设备重新登录
    await RefreshTokensDAO.revoke_all_for_user(user_uuid)


    if body.refresh_token is not None:
        import hashlib
        token_hash = hashlib.sha256(body.refresh_token.encode()).hexdigest()
        await RefreshTokensDAO.revoke(token_hash)

    custom_log("SUCCESS", f"[ChangePassword] uuid={user_uuid} 密码修改成功")
    return {"message": "密码修改成功"}


# ---------------------------------------------------------------------------
# PATCH /users/me/profile — 修改个人信息
# ---------------------------------------------------------------------------

@router.patch("/me/profile", response_model=dict[str, Any])
async def update_profile(
    body: UpdateProfileRequest,
    current_user: dict = Depends(get_current_user),
):
    """已登录用户修改个人信息接口。

    支持修改昵称（nickname）、班级（class）、真实姓名（real_name）中的一个或多个字段。

    若修改了 real_name 或 class，会检查数据库中是否已存在相同姓名+班级的其他用户，
    防止数据冲突。
    """
    user_uuid: str = current_user["uuid"]

    # ----------------------------------------------------------------
    # 检查账号状态
    # ----------------------------------------------------------------
    if current_user.get("current_status") not in (None, "normal"):
        custom_log("WARNING", f"[UpdateProfile] uuid={user_uuid} 账号状态异常，拒绝修改信息")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="账号状态异常，无法修改个人信息",
        )

    # ----------------------------------------------------------------
    # 构建更新数据字典（仅包含非 None 的字段）
    # ----------------------------------------------------------------
    update_data: dict[str, Any] = {}
    if body.nickname is not None:
        update_data["nickname"] = body.nickname
    if body.real_name is not None:
        update_data["real_name"] = body.real_name
    if body.class_ is not None:
        update_data["class"] = body.class_  # 注意：传入数据库列名 "class"

    # ----------------------------------------------------------------
    # 若涉及 real_name 或 class 的变更，检查是否与其他用户冲突
    # ----------------------------------------------------------------
    if "real_name" in update_data or "class" in update_data:
        # 取变更后的有效值（未变更的字段沿用当前值）；使用 is None 而非 or，
        # 避免将空字符串（数据库中理论上可能存在）错误地当作"未提供"处理。
        effective_real_name: str = (
            update_data["real_name"] if "real_name" in update_data else (current_user.get("real_name") or "")
        )
        effective_class: str = (
            update_data["class"] if "class" in update_data else (current_user.get("class") or "")
        )

        async with get_session() as session:
            duplicate = await UsersDAO.find_duplicate_student_exclude_self(
                session, effective_real_name, effective_class, user_uuid
            )
        if duplicate:
            custom_log(
                "WARNING",
                f"[UpdateProfile] uuid={user_uuid} real_name='{effective_real_name}' "
                f"class='{effective_class}' 与已有用户冲突",
            )
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="该姓名和班级的学生已存在，如有问题请联系管理员",
            )

    # ----------------------------------------------------------------
    # 更新数据库
    # ----------------------------------------------------------------
    try:
        updated = await UsersDAO().update(user_uuid, update_data)
    except Exception as exc:
        custom_log("ERROR", f"[UpdateProfile] uuid={user_uuid} 个人信息更新失败: {exc}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="个人信息修改失败，请稍后重试",
        )

    if updated is None:
        custom_log("ERROR", f"[UpdateProfile] uuid={user_uuid} 用户不存在（update 返回 None）")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="用户不存在",
        )

    custom_log("SUCCESS", f"[UpdateProfile] uuid={user_uuid} 个人信息修改成功 fields={list(update_data.keys())}")
    return {
        "uuid": updated["uuid"],
        "nickname": updated["nickname"],
        "real_name": updated["real_name"],
        "class": updated.get("class"),
        "class_type": updated["class_type"],
        "role": updated["user_role"],
        "is_verified": updated["is_verified"],
        "status": updated["current_status"],
    }


# ---------------------------------------------------------------------------
# GET /users/me — 完整用户信息
# ---------------------------------------------------------------------------

@router.get("/me", response_model=dict[str, Any])
async def read_users_me(current_user: dict = Depends(get_current_user)):
    """返回当前用户的完整个人信息（非敏感字段）。

    注意：不从 Redis 缓存读取，直接从数据库获取最新数据。
    排除字段：password, id, other_info, deletion_scheduled_at, last_login_ip
    """
    user_uuid: str = current_user["uuid"]
    user = await UsersDAO().find_by_uuid(user_uuid)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="用户不存在",
        )

    return {
        "uuid": user.get("uuid"),
        "username": user.get("username"),
        "email": user.get("email"),
        "avatar_url": user.get("avatar_url"),
        "nickname": user.get("nickname"),
        "real_name": user.get("real_name"),
        "class": user.get("class"),
        "class_type": user.get("class_type"),
        "joined_at": str(user.get("joined_at")) if user.get("joined_at") else None,
        "current_status": user.get("current_status"),
        "last_login_at": str(user.get("last_login_at")) if user.get("last_login_at") else None,
        "score": user.get("score"),
        "user_role": user.get("user_role"),
        "title": user.get("title"),
        "invited_by": user.get("invited_by"),
        "views": user.get("views"),
        "is_verified": user.get("is_verified"),
    }


# ---------------------------------------------------------------------------
# DELETE /users/me — 账号注销（30 天冷却期）
# ---------------------------------------------------------------------------

@router.delete("/me", response_model=dict[str, Any])
async def delete_account(
    body: DeleteAccountRequest,
    current_user: dict = Depends(get_current_user),
):
    """注销当前账号，进入 30 天冷却期。

    30 天内登录自动恢复；超期后由定时清理任务物理删除。
    需要密码确认。
    """
    user_uuid: str = current_user["uuid"]

    # 验证账号状态
    status_val = current_user.get("current_status")
    if status_val not in (None, "normal"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="账号状态异常，无法注销",
        )

    # 验证密码
    async with get_session() as session:
        stored_hash = await UsersDAO.find_password_hash(session, user_uuid)

    if not stored_hash:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="账号未设置密码，无法验证身份",
        )

    if not verify_password(body.password, stored_hash):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="密码不正确",
        )

    # 设置冷却期
    deletion_time = datetime.now() + timedelta(days=settings.ACCOUNT_DELETION_GRACE_DAYS)
    await UsersDAO().update(user_uuid, {
        "current_status": "pending_deletion",
        "deletion_scheduled_at": deletion_time,
    })

    # 撤销所有 refresh token，强制重新登录
    await RefreshTokensDAO.revoke_all_for_user(user_uuid)
    invalidate_user_cache(user_uuid)

    custom_log("SUCCESS", f"[DeleteAccount] uuid={user_uuid} 已进入注销冷却期，预定删除时间={deletion_time.isoformat()}")

    return {"message": "账号已进入注销冷却期，30天内登录可恢复"}
