from sqlalchemy import (
    create_engine,
    Column,
    Integer,
    String,
    DateTime,
    ForeignKey,
)
from sqlalchemy.orm import declarative_base, sessionmaker
from datetime import datetime

DATABASE_URL = "sqlite:///shieldai.db"

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False}
)

SessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,
    autocommit=False
)

Base = declarative_base()


class Scan(Base):
    __tablename__ = "scans"

    id = Column(
        Integer,
        primary_key=True
    )

    target_url = Column(
        String(500),
        nullable=False
    )

    scan_name = Column(
        String(200)
    )

    status = Column(
        String(50),
        default="Completed"
    )

    created_at = Column(
        DateTime,
        default=datetime.utcnow
    )


class Finding(Base):
    __tablename__ = "findings"

    id = Column(
        Integer,
        primary_key=True
    )

    scan_id = Column(
        Integer,
        ForeignKey("scans.id"),
        nullable=True
    )

    vulnerability = Column(
        String(200),
        nullable=False
    )

    severity = Column(
        String(20),
        nullable=False
    )

    url = Column(
        String(500),
        nullable=False
    )

    description = Column(
        String(1000)
    )

    status = Column(
        String(50),
        default="Open"
    )

    created_at = Column(
        DateTime,
        default=datetime.utcnow
    )


def init_db():
    Base.metadata.create_all(
        bind=engine
    )