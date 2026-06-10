from datetime import datetime, timedelta, timezone

from sqlalchemy import Integer, Text, delete, select
from sqlalchemy.dialects.postgresql import TIMESTAMP
from sqlalchemy.orm import Mapped, mapped_column

from core.database.connection.pgsql import Base, get_session
from core.database.dao.base import BaseDAO


class RefreshToken(Base):
    __tablename__ = "refresh_tokens"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_uuid: Mapped[str] = mapped_column(Text, nullable=False)
    token_hash: Mapped[str] = mapped_column(Text, nullable=False, unique=True)
    created_at: Mapped[datetime | None] = mapped_column(
        TIMESTAMP(timezone=True), server_default="now()"
    )
    revoked_at: Mapped[datetime | None] = mapped_column(
        TIMESTAMP(timezone=True), nullable=True
    )


class RefreshTokensDAO(BaseDAO):
    MODEL = RefreshToken

    @staticmethod
    async def create(user_uuid: str, token_hash: str) -> None:
        async with get_session() as session:
            obj = RefreshToken(user_uuid=user_uuid, token_hash=token_hash)
            session.add(obj)
            await session.flush()

    @classmethod
    async def find_active(cls, token_hash: str) -> dict | None:
        async with get_session() as session:
            obj = (
                await session.scalars(
                    select(RefreshToken).where(
                        RefreshToken.token_hash == token_hash,
                        RefreshToken.revoked_at.is_(None),
                    )
                )
            ).first()
            if obj is None:
                return None
            return cls._to_dict(obj)

    @staticmethod
    async def revoke(token_hash: str) -> None:
        async with get_session() as session:
            obj = (
                await session.scalars(
                    select(RefreshToken).where(RefreshToken.token_hash == token_hash)
                )
            ).first()
            if obj:
                obj.revoked_at = datetime.now(timezone.utc)
                await RefreshTokensDAO._cleanup_old_revoked()
                await session.flush()

    @staticmethod
    async def revoke_all_for_user(user_uuid: str) -> None:
        async with get_session() as session:
            objs = (
                await session.scalars(
                    select(RefreshToken).where(
                        RefreshToken.user_uuid == user_uuid,
                        RefreshToken.revoked_at.is_(None),
                    )
                )
            ).all()
            now = datetime.now(timezone.utc)
            for obj in objs:
                obj.revoked_at = now
            await session.flush()

    @staticmethod
    async def _cleanup_old_revoked() -> None:
        """删除吊销超过 7 天的旧 token 记录。"""
        cutoff = datetime.now(timezone.utc) - timedelta(days=7)
        async with get_session() as session:
            await session.execute(
                delete(RefreshToken).where(
                    RefreshToken.revoked_at < cutoff
                )
            )
            await session.flush()
