from __future__ import annotations

from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    """Declarative SQLAlchemy base for all ORM models."""


__all__ = ["Base"]
