from datetime import date, datetime, timezone
from decimal import Decimal

from sqlalchemy import (Boolean, Date, DateTime, ForeignKey, Numeric, String,
                        Text, UniqueConstraint)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .db import Base

Money = Numeric(14, 2)


def _now():
    return datetime.now(timezone.utc)


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(50), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(20), default="accounts")  # admin | accounts
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class Client(Base):
    __tablename__ = "clients"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(200), unique=True, index=True)
    gstin: Mapped[str | None] = mapped_column(String(20), nullable=True)
    contact_person: Mapped[str | None] = mapped_column(String(120), nullable=True)
    email: Mapped[str | None] = mapped_column(String(200), nullable=True)
    phone: Mapped[str | None] = mapped_column(String(40), nullable=True)
    address: Mapped[str | None] = mapped_column(Text, nullable=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    invoices: Mapped[list["Invoice"]] = relationship(back_populates="client")


class Invoice(Base):
    __tablename__ = "invoices"
    __table_args__ = (UniqueConstraint("number", "financial_year", name="uq_invoice_number_fy"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    number: Mapped[str] = mapped_column(String(60), index=True)
    financial_year: Mapped[str] = mapped_column(String(7), index=True)  # e.g. 2026-27
    client_id: Mapped[int] = mapped_column(ForeignKey("clients.id"))
    invoice_date: Mapped[date] = mapped_column(Date)
    due_date: Mapped[date | None] = mapped_column(Date, nullable=True)
    gross: Mapped[Decimal] = mapped_column(Money)
    gst: Mapped[Decimal] = mapped_column(Money, default=0)
    rcm: Mapped[bool] = mapped_column(Boolean, default=False)  # Reverse Charge: GST not billed to client
    tds: Mapped[Decimal] = mapped_column(Money, default=0)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_by: Mapped[str | None] = mapped_column(String(50), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    client: Mapped[Client] = relationship(back_populates="invoices")
    payments: Mapped[list["Payment"]] = relationship(
        back_populates="invoice", cascade="all, delete-orphan", order_by="Payment.payment_date"
    )


class Payment(Base):
    __tablename__ = "payments"
    id: Mapped[int] = mapped_column(primary_key=True)
    invoice_id: Mapped[int] = mapped_column(ForeignKey("invoices.id"), index=True)
    payment_date: Mapped[date] = mapped_column(Date)
    amount: Mapped[Decimal] = mapped_column(Money)
    mode: Mapped[str | None] = mapped_column(String(40), nullable=True)
    reference: Mapped[str | None] = mapped_column(String(120), nullable=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_by: Mapped[str | None] = mapped_column(String(50), nullable=True)
    invoice: Mapped[Invoice] = relationship(back_populates="payments")
