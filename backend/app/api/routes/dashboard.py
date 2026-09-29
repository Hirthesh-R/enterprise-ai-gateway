"""Observability dashboard API: KPIs, charts, audit log, live stream."""

from __future__ import annotations

import asyncio
import json
import math
import random
from collections import Counter, defaultdict
from datetime import date, datetime, timedelta
from typing import Literal

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import StreamingResponse
from sqlalchemy import Select, and_, case, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.routes.gateway import client_ip
from app.database import get_session
from app.errors import GatewayError
from app.models.api_key import ApiKey
from app.models.threat_event import ThreatEvent
from app.models.transaction import Transaction
from app.schemas.dashboard import (
    ApiKeyInfo,
    AuditItem,
    AuditPage,
    ChartsResponse,
    Distribution,
    KPIResponse,
    ModelUsage,
    ThreatEventItem,
    TimeSeries,
)
from app.schemas.gateway import SUPPORTED_MODELS, ChatRequest
from app.services.container import ServiceContainer, get_container
from app.services.demo_data import CLEAN_PROMPTS, INJECTION_PROMPTS, LOW_RISK_PROMPTS, PII_PROMPTS
from app.services.telemetry_service import serialize_transaction
from app.utils.timeutils import to_iso, utcnow

router = APIRouter(prefix="/api/v1/dashboard", tags=["Dashboard"])

PII_TYPES = ["EMAIL", "PHONE", "CREDIT_CARD", "SSN"]
THREAT_TYPES = [
    "PROMPT_INJECTION", "SYSTEM_PROMPT_EXFILTRATION", "CREDENTIAL_EXFILTRATION", "POLICY_BYPASS",
    "RATE_LIMIT_EXCEEDED", "UNAUTHORIZED_ACCESS", "REVOKED_KEY_USAGE",
]
STATUSES = ["allowed", "blocked", "rate_limited", "unauthorized", "forbidden", "error"]


def _percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    idx = max(0, min(len(ordered) - 1, math.ceil(pct / 100 * len(ordered)) - 1))
    return round(ordered[idx], 2)


# --------------------------------------------------------------------- KPIs
@router.get("/kpis", response_model=KPIResponse, summary="Headline security & performance KPIs")
async def kpis(session: AsyncSession = Depends(get_session)) -> KPIResponse:
    t = Transaction
    row = (await session.execute(select(
        func.count(t.id),
        func.sum(case((t.status == "allowed", 1), else_=0)),
        func.sum(case((t.status == "blocked", 1), else_=0)),
        func.coalesce(func.sum(t.redaction_count), 0),
        func.sum(case((t.pii_detected.is_(True), 1), else_=0)),
        func.avg(case((t.status == "allowed", t.processing_time_ms), else_=None)),
        func.coalesce(func.sum(t.total_tokens), 0),
        func.sum(case((t.status == "rate_limited", 1), else_=0)),
        func.sum(case((t.status.in_(["unauthorized", "forbidden"]), 1), else_=0)),
        func.sum(case((t.timestamp >= utcnow() - timedelta(hours=1), 1), else_=0)),
    ))).one()
    total = int(row[0] or 0)
    blocked = int(row[2] or 0)
    latencies = (await session.execute(
        select(t.processing_time_ms).where(t.status == "allowed").order_by(t.timestamp.desc()).limit(1000)
    )).scalars().all()
    return KPIResponse(
        total_requests=total,
        allowed_requests=int(row[1] or 0),
        blocked_attacks=blocked,
        pii_redactions=int(row[3] or 0),
        pii_requests=int(row[4] or 0),
        avg_response_time_ms=round(float(row[5] or 0.0), 2),
        p95_response_time_ms=_percentile(list(latencies), 95),
        total_tokens=int(row[6] or 0),
        rate_limit_violations=int(row[7] or 0),
        unauthorized_requests=int(row[8] or 0),
        block_rate_pct=round(blocked / total * 100, 2) if total else 0.0,
        requests_last_hour=int(row[9] or 0),
        generated_at=to_iso(utcnow()),
    )


# ------------------------------------------------------------------- charts
@router.get("/charts", response_model=ChartsResponse, summary="Time-series and distribution data for charts")
async def charts(
    window_minutes: int = Query(60, description="Look-back window in minutes: 15 | 60 | 360 | 1440"),
    session: AsyncSession = Depends(get_session),
) -> ChartsResponse:
    if window_minutes not in (15, 60, 360, 1440):
        raise GatewayError(400, "Validation error",
                           detail=[{"field": "window_minutes", "message": "must be one of 15, 60, 360, 1440"}])
    bucket = 1 if window_minutes <= 60 else (5 if window_minutes <= 360 else 30)
    now = utcnow().replace(second=0, microsecond=0)
    end = now + timedelta(minutes=1)
    start = end - timedelta(minutes=window_minutes)
    t = Transaction

    rows = (await session.execute(
        select(t.timestamp, t.status, t.processing_time_ms, t.target_model, t.pii_types)
        .where(t.timestamp >= start)
    )).all()

    n_buckets = math.ceil(window_minutes / bucket)
    bucket_starts = [start + timedelta(minutes=i * bucket) for i in range(n_buckets)]
    counts = {k: [0] * n_buckets for k in ("total", "allowed", "blocked", "throttled")}
    lat: dict[int, list[float]] = defaultdict(list)
    model_allowed: Counter[str] = Counter()
    model_blocked: Counter[str] = Counter()
    model_lat: dict[str, list[float]] = defaultdict(list)
    pii_counter: Counter[str] = Counter()

    for ts, status, ptime, model, pii_types in rows:
        idx = int((ts - start).total_seconds() // (bucket * 60))
        if 0 <= idx < n_buckets:
            counts["total"][idx] += 1
            if status == "allowed":
                counts["allowed"][idx] += 1
                lat[idx].append(ptime or 0.0)
            elif status == "blocked":
                counts["blocked"][idx] += 1
            else:
                counts["throttled"][idx] += 1
        if status == "allowed":
            model_allowed[model] += 1
            model_lat[model].append(ptime or 0.0)
        else:
            model_blocked[model] += 1
        for p in (pii_types or "").split(","):
            if p:
                pii_counter[p] += 1

    per_min = (lambda v: round(v / bucket, 2)) if bucket > 1 else float
    labels = [to_iso(b) for b in bucket_starts]
    rpm = TimeSeries(labels=labels, datasets={k: [per_min(v) for v in vals] for k, vals in counts.items()})
    latency = TimeSeries(labels=labels, datasets={
        "avg": [round(sum(lat[i]) / len(lat[i]), 2) if lat.get(i) else None for i in range(n_buckets)],
        "p95": [_percentile(lat[i], 95) if lat.get(i) else None for i in range(n_buckets)],
    })

    threat_rows = (await session.execute(
        select(ThreatEvent.threat_type, func.count(ThreatEvent.id))
        .where(ThreatEvent.timestamp >= start).group_by(ThreatEvent.threat_type)
    )).all()
    threat_counts = dict(threat_rows)
    threat_labels = [tt for tt in THREAT_TYPES if threat_counts.get(tt)] + \
        [tt for tt in threat_counts if tt not in THREAT_TYPES]

    models = list(SUPPORTED_MODELS)
    return ChartsResponse(
        window_minutes=window_minutes,
        bucket_minutes=bucket,
        requests_per_minute=rpm,
        response_latency=latency,
        threat_distribution=Distribution(labels=threat_labels, values=[int(threat_counts[x]) for x in threat_labels]),
        model_usage=ModelUsage(
            labels=[SUPPORTED_MODELS[m] for m in models],
            allowed=[model_allowed[m] for m in models],
            blocked=[model_blocked[m] for m in models],
            avg_latency_ms=[round(sum(model_lat[m]) / len(model_lat[m]), 2) if model_lat[m] else 0.0 for m in models],
        ),
        pii_type_distribution=Distribution(labels=PII_TYPES, values=[pii_counter[p] for p in PII_TYPES]),
        generated_at=to_iso(utcnow()),
    )


# ---------------------------------------------------------------- audit log
def _parse_date(value: str | None, *, end: bool = False) -> datetime | None:
    if not value:
        return None
    try:
        if len(value) == 10:
            d = date.fromisoformat(value)
            dt = datetime(d.year, d.month, d.day)
            return dt + timedelta(days=1) if end else dt
        return datetime.fromisoformat(value.replace("Z", "+00:00")).replace(tzinfo=None)
    except ValueError as exc:
        raise GatewayError(400, "Validation error", detail=[{"field": "date", "message": f"invalid date: {value}"}]) from exc


def _audit_filters(stmt: Select, *, search: str | None, status: str | None, model: str | None,
                   threat_type: str | None, date_from: str | None, date_to: str | None,
                   pii: bool | None, injection: bool | None) -> Select:
    t = Transaction
    conds = []
    if search:
        like = f"%{search.strip()}%"
        conds.append(or_(t.transaction_id.ilike(like), t.masked_api_key.ilike(like), t.target_model.ilike(like),
                         t.threat_type.ilike(like), t.masked_ip.ilike(like), t.status.ilike(like),
                         t.pii_types.ilike(like), t.prompt_preview.ilike(like)))
    if status:
        conds.append(t.status == status)
    if model:
        conds.append(t.target_model == model)
    if threat_type:
        conds.append(t.threat_type == threat_type if threat_type != "NONE" else t.threat_type.is_(None))
    if (start := _parse_date(date_from)) is not None:
        conds.append(t.timestamp >= start)
    if (stop := _parse_date(date_to, end=True)) is not None:
        conds.append(t.timestamp < stop)
    if pii is not None:
        conds.append(t.pii_detected.is_(pii))
    if injection is not None:
        conds.append(t.injection_detected.is_(injection))
    return stmt.where(and_(*conds)) if conds else stmt


@router.get("/audit", response_model=AuditPage, summary="Searchable, filterable audit log")
async def audit_log(
    search: str | None = Query(None, max_length=100, description="Free-text search (txn id, key, model, IP…)"),
    status: str | None = Query(None, description="|".join(STATUSES)),
    model: str | None = Query(None, description="gpt-4 | gemini-pro | claude | llama"),
    threat_type: str | None = Query(None, description="Threat type or NONE"),
    date_from: str | None = Query(None, description="YYYY-MM-DD or ISO datetime (UTC)"),
    date_to: str | None = Query(None, description="YYYY-MM-DD or ISO datetime (UTC)"),
    pii: bool | None = Query(None, description="Filter by PII detected"),
    injection: bool | None = Query(None, description="Filter by injection detected"),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    session: AsyncSession = Depends(get_session),
) -> AuditPage:
    """Only sanitised fields are returned — raw prompts are never stored or displayed."""
    filters = dict(search=search, status=status, model=model, threat_type=threat_type,
                   date_from=date_from, date_to=date_to, pii=pii, injection=injection)
    total = (await session.execute(_audit_filters(select(func.count(Transaction.id)), **filters))).scalar_one()
    rows = (await session.execute(
        _audit_filters(select(Transaction), **filters)
        .order_by(Transaction.timestamp.desc(), Transaction.id.desc())
        .offset((page - 1) * page_size).limit(page_size)
    )).scalars().all()
    return AuditPage(items=[AuditItem(**serialize_transaction(r)) for r in rows], total=total, page=page,
                     page_size=page_size, pages=max(1, math.ceil(total / page_size)))


@router.get("/threats", response_model=list[ThreatEventItem], summary="Most recent security events")
async def recent_threats(limit: int = Query(20, ge=1, le=200),
                         session: AsyncSession = Depends(get_session)) -> list[ThreatEventItem]:
    rows = (await session.execute(
        select(ThreatEvent).order_by(ThreatEvent.timestamp.desc(), ThreatEvent.id.desc()).limit(limit)
    )).scalars().all()
    return [ThreatEventItem(transaction_id=r.transaction_id, timestamp=to_iso(r.timestamp), threat_type=r.threat_type,
                            risk_level=r.risk_level, action=r.action, masked_ip=r.masked_ip,
                            masked_api_key=r.masked_api_key,
                            matched_rules=[m for m in r.matched_rules.split(",") if m]) for r in rows]


@router.get("/api-keys", response_model=list[ApiKeyInfo], summary="Registered API keys (masked)")
async def api_keys(session: AsyncSession = Depends(get_session)) -> list[ApiKeyInfo]:
    rows = (await session.execute(select(ApiKey).order_by(ApiKey.id))).scalars().all()
    return [ApiKeyInfo(key_name=r.key_name, masked_key=r.masked_key, status=r.status, rate_limit=r.rate_limit,
                       created_at=to_iso(r.created_at), last_used_at=to_iso(r.last_used_at)) for r in rows]


# ------------------------------------------------------------ live stream
@router.get("/stream", summary="Server-Sent Events stream of new transactions")
async def stream(request: Request, container: ServiceContainer = Depends(get_container)) -> StreamingResponse:
    """Emits ``transaction`` events as they happen plus a heartbeat every 15 s."""
    broadcaster = container.broadcaster
    queue = broadcaster.subscribe()

    async def event_source():
        try:
            yield f"event: hello\ndata: {json.dumps({'subscribers': broadcaster.subscriber_count})}\n\n"
            while True:
                if await request.is_disconnected():
                    break
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=15)
                except asyncio.TimeoutError:
                    yield ": heartbeat\n\n"
                    continue
                yield f"event: {event['type']}\ndata: {json.dumps(event['data'])}\n\n"
        finally:
            broadcaster.unsubscribe(queue)

    return StreamingResponse(event_source(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no", "Connection": "keep-alive"})


# ---------------------------------------------------------- traffic simulator
@router.post("/simulate", summary="Generate live demo traffic through the real pipeline")
async def simulate(request: Request, count: int = Query(10, ge=1, le=50),
                   container: ServiceContainer = Depends(get_container)) -> dict:
    """Sends ``count`` sample prompts (clean, PII, injection) through the full gateway pipeline."""
    pool = CLEAN_PROMPTS * 3 + PII_PROMPTS * 2 + INJECTION_PROMPTS + LOW_RISK_PROMPTS
    keys = ["demo-key-001", "demo-key-002", "enterprise-demo-key", "enterprise-demo-key"]
    ip = client_ip(request, container.settings.trust_proxy_headers)

    async def one() -> str:
        req = ChatRequest(prompt=random.choice(pool), api_key=random.choice(keys),
                          target_model=random.choice(list(SUPPORTED_MODELS)))
        try:
            return (await container.engine.process(req, ip)).body["status"]
        except GatewayError as exc:
            return {401: "unauthorized", 403: "forbidden", 429: "rate_limited"}.get(exc.status_code, "error")

    results = await asyncio.gather(*(one() for _ in range(count)))
    return {"simulated": count, "results": dict(Counter(results))}
