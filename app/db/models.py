from __future__ import annotations
from datetime import datetime, timezone
from sqlalchemy import String, Integer, Boolean, DateTime, ForeignKey, UniqueConstraint, Index
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship
from shared_kernel.session import Base


class Domain(Base):
    """ Tabla/Modelo de dominio monitorizado por un usuario, con estado y etiquetas de clasificación. """

    __tablename__ = "domains"

    id: Mapped[str] = mapped_column(String(80), primary_key=True)
    user_id: Mapped[str] = mapped_column(String(80), index=True)
    domain_name: Mapped[str] = mapped_column(String(255), index=True)
    status: Mapped[str] = mapped_column(String(20), default="active")
    tags: Mapped[list[str]] = mapped_column(JSONB, default=list)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    __table_args__ = (
        UniqueConstraint("user_id", "domain_name", name="uq_user_domain_name"),
        Index("idx_domains_user_status", "user_id", "status"),
    )


class AlertRule(Base):
    """Regla de alerta configurable (lógica + schedule) asociada a un usuario y a un conjunto de dominios objetivo."""

    __tablename__ = "alert_rules"

    id: Mapped[str] = mapped_column(String(80), primary_key=True)        
    user_id: Mapped[str] = mapped_column(String(80), index=True)

    name: Mapped[str] = mapped_column(String(80))
    rule_type: Mapped[str] = mapped_column(String(30))                  
    severity: Mapped[str] = mapped_column(String(20), default="medium")
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True)

    version: Mapped[int] = mapped_column(Integer, default=1)
    logic_json: Mapped[dict] = mapped_column(JSONB)
    schedule_json: Mapped[dict] = mapped_column(JSONB)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.now(timezone.utc), onupdate=datetime.now(timezone.utc))

    targets: Mapped[list["AlertRuleTarget"]] = relationship(
        back_populates="rule", cascade="all, delete-orphan"
    )

    __table_args__ = (
        Index("idx_rules_user_enabled", "user_id", "is_enabled"),
        Index("idx_rules_user_type", "user_id", "rule_type"),
    )


class AlertRuleTarget(Base):
    """ Relación entre una regla de alerta y los dominios a los que aplica. """

    __tablename__ = "alert_rule_targets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    rule_id: Mapped[str] = mapped_column(String(80), ForeignKey("alert_rules.id", ondelete="CASCADE"), index=True)
    domain_id: Mapped[str] = mapped_column(String(80), ForeignKey("domains.id"), index=True)

    rule: Mapped["AlertRule"] = relationship(back_populates="targets")

    __table_args__ = (
        UniqueConstraint("rule_id", "domain_id", name="uq_rule_domain"),
    )


class ScheduleJob(Base):
    """ Job de ejecución programada de una regla, con estado y próxima ejecución. """

    __tablename__ = "schedules"

    id: Mapped[str] = mapped_column(String(80), primary_key=True)
    user_id: Mapped[str] = mapped_column(String(80), index=True)
    rule_id: Mapped[str] = mapped_column(String(80), ForeignKey("alert_rules.id", ondelete="CASCADE"), index=True)

    schedule_json: Mapped[dict] = mapped_column(JSONB)
    status: Mapped[str] = mapped_column(String(20), default="active")

    next_run_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    __table_args__ = (
        Index("idx_sched_user_status", "user_id", "status"),
    )
