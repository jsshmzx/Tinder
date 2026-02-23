from typing import Any, ClassVar, Type

from sqlalchemy import select

from core.database.connection.db import Base, get_session


class BaseDAO:
    """所有 DAO 的基类，基于 SQLAlchemy 异步 ORM 提供通用 CRUD 操作。

    子类只需声明 :attr:`MODEL` 属性（对应 ORM 模型类），即可继承：

    * :meth:`find_by_uuid` – 根据 uuid 查询单条记录
    * :meth:`find_all`     – 分页查询所有记录
    * :meth:`create`       – 插入新记录
    * :meth:`update`       – 根据 uuid 更新记录
    * :meth:`delete`       – 根据 uuid 删除记录
    """

    #: 子类必须将此属性设置为对应的 SQLAlchemy ORM 模型类。
    MODEL: ClassVar[Type[Base]]

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_model(self) -> Type[Base]:
        """返回 MODEL，未设置时抛出 NotImplementedError。"""
        model = getattr(self, "MODEL", None)
        if model is None:
            raise NotImplementedError(
                f"{type(self).__name__} must define the MODEL class attribute"
            )
        return model

    @staticmethod
    def _to_dict(obj) -> dict[str, Any]:
        """将 ORM 实例转换为以数据库列名为键的字典。"""
        if obj is None:
            return {}
        return {
            col_prop.columns[0].name: getattr(obj, col_prop.key)
            for col_prop in type(obj).__mapper__.column_attrs
        }

    @classmethod
    def _data_to_kwargs(cls, data: dict[str, Any]) -> dict[str, Any]:
        """将数据库列名字典转换为 ORM 模型属性名字典（处理列名与属性名不同的情况）。"""
        col_to_attr = {
            col_prop.columns[0].name: col_prop.key
            for col_prop in cls.MODEL.__mapper__.column_attrs
        }
        return {col_to_attr.get(k, k): v for k, v in data.items()}

    # ------------------------------------------------------------------
    # CRUD
    # ------------------------------------------------------------------

    async def find_by_uuid(self, uuid: str) -> dict[str, Any] | None:
        """根据 uuid 查询单条记录，不存在时返回 None。"""
        model = self._get_model()
        async with get_session() as session:
            obj = (
                await session.scalars(select(model).where(model.uuid == uuid))
            ).first()
            return self._to_dict(obj) if obj else None

    async def find_all(self, limit: int = 100, offset: int = 0) -> list[dict[str, Any]]:
        """分页查询所有记录，默认返回前 100 条。"""
        model = self._get_model()
        async with get_session() as session:
            objs = await session.scalars(
                select(model).order_by(model.id).limit(limit).offset(offset)
            )
            return [self._to_dict(o) for o in objs]

    async def create(self, data: dict[str, Any]) -> dict[str, Any]:
        """插入新记录并返回完整行（含数据库生成的字段）。"""
        model = self._get_model()
        obj = model(**self._data_to_kwargs(data))
        async with get_session() as session:
            session.add(obj)
            await session.flush()
            await session.refresh(obj)
            return self._to_dict(obj)

    async def update(self, uuid: str, data: dict[str, Any]) -> dict[str, Any] | None:
        """根据 uuid 更新字段，返回更新后的行，若记录不存在则返回 None。"""
        model = self._get_model()
        async with get_session() as session:
            obj = (
                await session.scalars(select(model).where(model.uuid == uuid))
            ).first()
            if obj is None:
                return None
            for k, v in self._data_to_kwargs(data).items():
                setattr(obj, k, v)
            await session.flush()
            await session.refresh(obj)
            return self._to_dict(obj)

    async def delete(self, uuid: str) -> bool:
        """根据 uuid 删除记录，成功删除返回 True，记录不存在返回 False。"""
        model = self._get_model()
        async with get_session() as session:
            obj = (
                await session.scalars(select(model).where(model.uuid == uuid))
            ).first()
            if obj is None:
                return False
            await session.delete(obj)
            return True

