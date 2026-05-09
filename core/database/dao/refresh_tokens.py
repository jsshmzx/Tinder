from datetime import datetime, timezone

from sqlalchemy import Integer, Text, select
from sqlalchemy.dialects.postgresql import TIMESTAMP
from sqlalchemy.orm import Mapped, mapped_column

from core.database.connection.pgsql import Base, get_session


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


class RefreshTokensDAO:

    @staticmethod
    async def create(user_uuid: str, token_hash: str) -> None:
        async with get_session() as session:
            obj = RefreshToken(user_uuid=user_uuid, token_hash=token_hash)
            session.add(obj)
            await session.flush()

    @staticmethod
    async def find_active(token_hash: str) -> dict | None:
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
            return {"user_uuid": obj.user_uuid, "token_hash": obj.token_hash}

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
