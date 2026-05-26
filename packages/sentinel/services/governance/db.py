import os
from contextlib import contextmanager
from datetime import datetime

from sqlalchemy import create_engine, Column, Integer, String, DateTime, Boolean, Text
from sqlalchemy.orm import sessionmaker, declarative_base

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///overwatch.db")

if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class Log(Base):
    __tablename__ = "logs"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    agent_id = Column(String(255), index=True)
    event_type = Column(String(100))
    prompt_snippet = Column(Text)
    risk_score = Column(Integer)
    alignment_score = Column(Integer, nullable=True)
    judge_reason = Column(Text, nullable=True)


class AgentStatus(Base):
    __tablename__ = "agent_status"

    agent_id = Column(String(255), primary_key=True)
    is_killed = Column(Boolean, default=False)
    killed_at = Column(DateTime, nullable=True)
    killed_by = Column(String(255), nullable=True)
    kill_reason = Column(Text, nullable=True)
    revived_at = Column(DateTime, nullable=True)


class KillAudit(Base):
    __tablename__ = "kill_audit"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    agent_id = Column(String(255), index=True)
    action = Column(String(50))
    actor = Column(String(255))
    reason = Column(Text)


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(String(255), primary_key=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    severity = Column(String(50))
    event_type = Column(String(100))
    agent_id = Column(String(255), index=True)
    title = Column(String(500))
    message = Column(Text)
    details = Column(Text)
    channel = Column(String(100))


def init_db():
    Base.metadata.create_all(bind=engine)


@contextmanager
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
