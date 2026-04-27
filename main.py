from __future__ import annotations

import asyncio
import copy
import csv
import hashlib
import ipaddress
import io
import json
import os
import re
import socket
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, quote, unquote, urlparse
from uuid import uuid4

import httpx
import phonenumbers
import uvicorn
from bs4 import BeautifulSoup
from fastapi import FastAPI, File, HTTPException, Query, UploadFile
from fastapi.responses import HTMLResponse, Response
from fastapi.staticfiles import StaticFiles
from PIL import Image
from PIL.ExifTags import GPSTAGS, TAGS
from phonenumbers import PhoneNumberType, carrier, geocoder, timezone
from pydantic import BaseModel
from osint_graph.bootstrap import load_local_env
from osint_graph.curated_sources import (
    domain_manual_sources,
    email_manual_sources,
    phone_manual_sources,
    username_manual_sources,
)
from osint_graph.external_tools import (
    active_censys_mode,
    search_domain_with_censys,
    search_email_with_holehe,
    search_image_with_search4faces,
    search_username_with_maigret,
    search_username_with_sherlock,
    spiderfoot_handoff_url,
    tool_availability,
)
from osint_graph.storage import SQLiteStorage

load_local_env()

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
WMN_CACHE_PATH = BASE_DIR / "wmn-data.json"
WMN_DB_URL = "https://raw.githubusercontent.com/WebBreacher/WhatsMyName/main/wmn-data.json"
_db_path_value = Path(os.getenv("OSINT_DB_PATH", "osint_graph_app.db"))
SQLITE_DB_PATH = _db_path_value if _db_path_value.is_absolute() else (BASE_DIR / _db_path_value).resolve()

REQUEST_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/135.0 Safari/537.36"
    )
}

MAX_CONCURRENT_REQUESTS = 30
REQUEST_TIMEOUT = 6.0
SEARCH_TIMEOUT = 8.0
USERNAME_RESULT_LIMIT = 80
PHONE_MENTION_LIMIT = 5
CACHE_TTL_SECONDS = 600
VERIFY_SSL = os.getenv("OSINT_VERIFY_SSL", "false").lower() in {"1", "true", "yes"}

TELEGRAM_HOSTS = {
    "t.me",
    "telegram.me",
    "www.t.me",
    "www.telegram.me",
}

STATUS_BUCKETS = {
    "found": "confirmed",
    "mention": "context",
    "info": "intel",
    "alert": "risk",
}

MALTEGO_ROOT_TYPES = {
    "username": "maltego.Alias",
    "email": "maltego.EmailAddress",
    "phone": "maltego.PhoneNumber",
    "domain": "maltego.Domain",
    "image": "maltego.Phrase",
}

app = FastAPI(title="Blue Static OSINT")
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

semaphore = asyncio.Semaphore(MAX_CONCURRENT_REQUESTS)
cached_db: list[dict[str, Any]] = []
storage = SQLiteStorage(SQLITE_DB_PATH)
storage.initialize()


@dataclass(slots=True)
class ProbeAssessment:
    matched: bool
    confidence: int
    reason: str
    score: int


@dataclass(slots=True)
class SearchResult:
    site: str
    url: str
    status: str
    score: int = 0
    confidence: int = 0
    category: str = "misc"
    reason: str = ""
    node_kind: str = "evidence"
    weight: int = 1

    def to_dict(self) -> dict[str, Any]:
        return {
            "site": self.site,
            "url": self.url,
            "status": self.status,
            "score": self.score,
            "confidence": self.confidence,
            "category": self.category,
            "reason": self.reason,
            "node_kind": self.node_kind,
            "weight": self.weight,
            "bucket": STATUS_BUCKETS.get(self.status, "intel"),
        }


@dataclass(slots=True)
class SearchJobState:
    job_id: str
    target: str
    search_type: str
    status: str = "queued"
    progress: int = 0
    total_steps: int = 0
    completed_steps: int = 0
    logs: list[dict[str, Any]] | None = None
    results: list[dict[str, Any]] | None = None
    error: str | None = None
    started_at: float = 0.0
    finished_at: float | None = None

    def __post_init__(self) -> None:
        if self.logs is None:
            self.logs = []
        if self.results is None:
            self.results = []

    def snapshot(self) -> dict[str, Any]:
        return {
            "job_id": self.job_id,
            "target": self.target,
            "type": self.search_type,
            "status": self.status,
            "progress": self.progress,
            "total_steps": self.total_steps,
            "completed_steps": self.completed_steps,
            "logs": self.logs[-12:],
            "results": self.results,
            "error": self.error,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
        }


class SearchJobRequest(BaseModel):
    target: str
    type: str


def clamp(value: int, lower: int, upper: int) -> int:
    return max(lower, min(value, upper))


def result(
    site: str,
    url: str,
    status: str,
    score: int = 0,
    confidence: int | None = None,
    category: str = "misc",
    reason: str = "",
    node_kind: str = "evidence",
    weight: int | None = None,
) -> SearchResult:
    confidence_value = clamp(confidence if confidence is not None else score, 0, 100)
    weight_value = clamp(weight if weight is not None else max(1, confidence_value // 10), 1, 12)
    return SearchResult(
        site=site,
        url=url,
        status=status,
        score=score,
        confidence=confidence_value,
        category=category,
        reason=reason,
        node_kind=node_kind,
        weight=weight_value,
    )


def hydrate_result(payload: dict[str, Any]) -> SearchResult:
    return result(
        site=str(payload["site"]),
        url=str(payload["url"]),
        status=str(payload.get("status", "info")),
        score=int(payload.get("score", payload.get("confidence", 0))),
        confidence=int(payload.get("confidence", payload.get("score", 0))),
        category=str(payload.get("category", "misc")),
        reason=str(payload.get("reason", "")),
        node_kind=str(payload.get("node_kind", "evidence")),
        weight=int(payload.get("weight", 0) or max(1, int(payload.get("confidence", 0) or payload.get("score", 0)) // 10 or 1)),
    )


def dedupe_and_sort(results: list[SearchResult]) -> list[dict[str, Any]]:
    unique: dict[tuple[str, str, str], SearchResult] = {}
    for item in results:
        key = (item.site, item.url, item.status)
        if key not in unique or item.score > unique[key].score:
            unique[key] = item

    bucket_priority = {"intel": 0, "confirmed": 1, "context": 2, "risk": 3}
    kind_priority = {"summary": 0, "hub": 1, "evidence": 2}
    ordered = sorted(
        unique.values(),
        key=lambda item: (
            kind_priority.get(item.node_kind, 5),
            bucket_priority.get(STATUS_BUCKETS.get(item.status, "intel"), 9),
            -item.confidence,
            item.site.lower(),
            item.url.lower(),
        ),
    )
    return [item.to_dict() for item in ordered]


def normalize_whitespace(value: str) -> str:
    return re.sub(r"\s+", " ", value).strip()


def make_cache_key(search_type: str, raw_target: str) -> str:
    return f"{search_type}:{normalize_whitespace(raw_target).lower()}"


def get_cached_result(search_type: str, raw_target: str) -> list[dict[str, Any]] | None:
    cache_key = make_cache_key(search_type, raw_target)
    cached = storage.get_cached_result(cache_key)
    return copy.deepcopy(cached) if cached is not None else None


def store_cached_result(search_type: str, raw_target: str, payload: list[dict[str, Any]]) -> None:
    storage.store_cached_result(
        cache_key=make_cache_key(search_type, raw_target),
        search_type=search_type,
        raw_target=raw_target,
        normalized_target=normalize_whitespace(raw_target).lower(),
        payload=copy.deepcopy(payload),
        ttl_seconds=CACHE_TTL_SECONDS,
    )


def normalize_export_target(raw_target: str, search_type: str) -> str:
    if search_type == "username":
        return extract_username_from_text(raw_target)
    if search_type == "email":
        return normalize_email(raw_target)
    if search_type == "phone":
        parsed = normalize_phone(raw_target)
        return phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
    if search_type == "domain":
        return normalize_domain(raw_target)
    return normalize_whitespace(raw_target)


def infer_maltego_entity_type(value: str, fallback: str = "maltego.Phrase") -> str:
    normalized = normalize_whitespace(value)
    if not normalized:
        return fallback
    if normalized.startswith(("http://", "https://")):
        return "maltego.URL"
    try:
        ip_obj = ipaddress.ip_address(normalized)
    except ValueError:
        ip_obj = None
    if ip_obj is not None:
        return "maltego.IPv6Address" if ip_obj.version == 6 else "maltego.IPv4Address"
    if re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", normalized):
        return "maltego.EmailAddress"
    if re.fullmatch(r"\+?[0-9][0-9\s().-]{5,}", normalized):
        return "maltego.PhoneNumber"
    if re.fullmatch(r"[A-Za-z0-9.-]+\.[A-Za-z]{2,}", normalized):
        return "maltego.Domain"
    return fallback


def build_maltego_csv_payload(search_type: str, raw_target: str, results: list[dict[str, Any]]) -> str:
    buffer = io.StringIO(newline="")
    fieldnames = [
        "source_maltego_type",
        "source_value",
        "target_maltego_type",
        "target_value",
        "target_label",
        "target_url",
        "status",
        "bucket",
        "confidence",
        "category",
        "reason",
    ]
    writer = csv.DictWriter(buffer, fieldnames=fieldnames)
    writer.writeheader()

    source_value = normalize_export_target(raw_target, search_type)
    source_type = MALTEGO_ROOT_TYPES.get(search_type, "maltego.Phrase")

    for item in results:
        if str(item.get("node_kind", "evidence")) == "summary":
            continue

        target_value = normalize_whitespace(str(item.get("url", "")).strip()) or normalize_whitespace(str(item.get("site", "")).strip())
        if not target_value:
            continue

        writer.writerow(
            {
                "source_maltego_type": source_type,
                "source_value": source_value,
                "target_maltego_type": infer_maltego_entity_type(target_value),
                "target_value": target_value,
                "target_label": str(item.get("site", "")),
                "target_url": str(item.get("url", "")),
                "status": str(item.get("status", "")),
                "bucket": str(item.get("bucket", STATUS_BUCKETS.get(str(item.get("status", "")), "intel"))),
                "confidence": str(item.get("confidence", item.get("score", ""))),
                "category": str(item.get("category", "")),
                "reason": str(item.get("reason", "")),
            }
        )

    return "\ufeff" + buffer.getvalue()


def safe_export_filename(search_type: str, raw_target: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "-", normalize_whitespace(raw_target)).strip("-")
    cleaned = cleaned[:60] or "target"
    return f'maltego-{search_type}-{cleaned}.csv'


async def update_job(
    job: SearchJobState | None,
    message: str,
    *,
    increment: int = 0,
    total: int | None = None,
    status: str | None = None,
) -> None:
    if job is None:
        return

    if total is not None:
        job.total_steps = total
    if increment:
        job.completed_steps += increment
    if status is not None:
        job.status = status
    if job.total_steps > 0:
        job.progress = clamp(round(job.completed_steps / job.total_steps * 100), 0, 100)
    timestamp = time.strftime("%H:%M:%S")
    job.logs.append(
        {
            "timestamp": timestamp,
            "message": message,
            "progress": job.progress,
        }
    )
    job.logs = job.logs[-80:]
    storage.update_job_state(job.snapshot())
    storage.append_job_log(job.job_id, timestamp, message, job.progress)


def extract_username_from_text(raw_target: str) -> str:
    value = normalize_whitespace(raw_target.strip())
    if not value:
        raise HTTPException(status_code=400, detail="Пустая цель")

    if value.startswith("@"):
        value = value[1:]

    candidate = value
    parsed = urlparse(value if "://" in value else f"https://{value}")
    if parsed.netloc:
        hostname = parsed.netloc.lower()
        parts = [part for part in parsed.path.split("/") if part]
        if hostname in TELEGRAM_HOSTS and parts:
            if parts[0] in {"s", "joinchat", "share"} and len(parts) > 1:
                candidate = parts[1]
            else:
                candidate = parts[0]
        elif parts:
            candidate = parts[-1]

    candidate = candidate.strip().lstrip("@")
    if not re.fullmatch(r"[A-Za-z0-9_.-]{2,64}", candidate):
        raise HTTPException(status_code=400, detail="Ник содержит неподдерживаемые символы")
    return candidate


def normalize_email(raw_target: str) -> str:
    value = normalize_whitespace(raw_target).lower()
    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", value):
        raise HTTPException(status_code=400, detail="Неверный формат email")
    return value


def normalize_domain(raw_target: str) -> str:
    value = normalize_whitespace(raw_target.lower())
    parsed = urlparse(value if "://" in value else f"https://{value}")
    domain = parsed.netloc or parsed.path
    domain = domain.split("/")[0].split(":")[0].strip(".")
    if not re.fullmatch(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}", domain):
        raise HTTPException(status_code=400, detail="Неверный формат домена")
    return domain


def normalize_phone(raw_target: str) -> phonenumbers.PhoneNumber:
    value = normalize_whitespace(raw_target)
    default_region = None if value.startswith("+") else "RU"
    try:
        parsed = phonenumbers.parse(value, default_region)
    except phonenumbers.NumberParseException as exc:
        raise HTTPException(status_code=400, detail=f"Неверный телефон: {exc}") from exc

    if not phonenumbers.is_valid_number(parsed):
        raise HTTPException(status_code=400, detail="Телефон не прошёл валидацию")
    return parsed


def apply_strip_bad_char(username: str, site_data: dict[str, Any]) -> str:
    bad_chars = site_data.get("strip_bad_char")
    if not bad_chars:
        return username

    normalized = username
    for bad_char in bad_chars:
        normalized = normalized.replace(bad_char, "")
    return normalized


def build_probe_payload(template: str, username: str) -> str:
    return template.replace("{account}", username)


def build_result_url(site_data: dict[str, Any], username: str) -> str:
    template = site_data.get("uri_pretty") or site_data["uri_check"]
    return build_probe_payload(template, username)


def normalize_signal(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip().lower()


def assess_probe(site_data: dict[str, Any], status_code: int, body: str, negative_confirmed: bool | None) -> ProbeAssessment:
    body_lc = body.lower()
    e_code = int(site_data.get("e_code", 200))
    m_code = int(site_data.get("m_code", 404))
    e_string = normalize_signal(site_data.get("e_string"))
    m_string = normalize_signal(site_data.get("m_string"))

    positive_code = status_code == e_code
    positive_text = bool(e_string and e_string in body_lc)
    negative_code = status_code == m_code
    negative_text = bool(m_string and m_string in body_lc)

    matched = positive_code and (positive_text or not e_string) and not (negative_code and negative_text and not positive_text)
    if not matched:
        return ProbeAssessment(False, 0, "источник не дал подтверждающего сигнала", 0)

    confidence = 30
    reasons = [f"код {status_code} совпал с ожидаемым {e_code}"]

    if e_string:
        if positive_text:
            confidence += 24
            reasons.append("обнаружен positive marker")
        else:
            confidence -= 20
    else:
        confidence += 10
        reasons.append("источник не требует text-marker")

    if m_string:
        if not negative_text:
            confidence += 14
            reasons.append("negative marker отсутствует")
        else:
            confidence -= 24
    elif status_code != m_code:
        confidence += 10
        reasons.append("missing-code не сработал")

    if site_data.get("post_body"):
        confidence += 5
        reasons.append("использовался API-style POST probe")

    if site_data.get("headers"):
        confidence += 3
        reasons.append("источник требует кастомные заголовки")

    if negative_confirmed is True:
        confidence += 14
        reasons.append("negative control не подтвердил фальшивый логин")
    elif negative_confirmed is False:
        return ProbeAssessment(False, 0, "negative control тоже сработал, источник шумный", 0)
    else:
        confidence -= 8
        reasons.append("negative control недоступен")

    confidence = clamp(confidence, 20, 97)
    score = confidence + (6 if site_data.get("known") else 0)
    return ProbeAssessment(True, confidence, "; ".join(reasons), score)


async def load_wmn_db() -> None:
    global cached_db

    try:
        async with httpx.AsyncClient(timeout=15.0, headers=REQUEST_HEADERS, verify=VERIFY_SSL) as client:
            response = await client.get(WMN_DB_URL)
            response.raise_for_status()
            data = response.json()
            WMN_CACHE_PATH.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
            cached_db = data.get("sites", [])
            return
    except Exception:
        pass

    if WMN_CACHE_PATH.exists():
        cached_db = json.loads(WMN_CACHE_PATH.read_text(encoding="utf-8")).get("sites", [])


@app.on_event("startup")
async def startup_event() -> None:
    storage.initialize()
    storage.mark_incomplete_runs_interrupted()
    storage.purge_expired_cache()
    await load_wmn_db()


@app.get("/", response_class=HTMLResponse)
async def read_root() -> str:
    return (STATIC_DIR / "index.html").read_text(encoding="utf-8")


async def probe_username_site(client: httpx.AsyncClient, site_data: dict[str, Any], username: str) -> SearchResult | None:
    normalized_username = apply_strip_bad_char(username, site_data)
    if not normalized_username:
        return None

    request_headers = dict(REQUEST_HEADERS)
    request_headers.update(site_data.get("headers", {}))
    body_template = site_data.get("post_body")

    async def send_probe(account_name: str) -> httpx.Response | None:
        probe_url = build_probe_payload(site_data["uri_check"], account_name)
        try:
            async with semaphore:
                if body_template:
                    payload = build_probe_payload(body_template, account_name)
                    return await client.post(
                        probe_url,
                        content=payload.encode("utf-8"),
                        headers=request_headers,
                    )
                return await client.get(probe_url, headers=request_headers)
        except Exception:
            return None

    response = await send_probe(normalized_username)
    if response is None:
        return None

    negative_control = f"zz_codex_probe_{hashlib.md5(normalized_username.encode('utf-8')).hexdigest()[:10]}"
    negative_response = await send_probe(negative_control)
    negative_confirmed: bool | None
    if negative_response is None:
        negative_confirmed = None
    else:
        negative_assessment = assess_probe(site_data, negative_response.status_code, negative_response.text, None)
        negative_confirmed = not negative_assessment.matched

    assessment = assess_probe(site_data, response.status_code, response.text, negative_confirmed)
    if not assessment.matched:
        return None

    category = site_data.get("cat", "misc")
    result_url = build_result_url(site_data, normalized_username)
    return result(
        site=f"✅ {site_data['name']} [{category}]",
        url=result_url,
        status="found",
        score=assessment.score,
        confidence=assessment.confidence,
        category=category,
        reason=assessment.reason,
        node_kind="evidence",
    )


def build_aggregate_results(target_label: str, target_type: str, evidence: list[SearchResult], checked_sources: int | None = None) -> list[SearchResult]:
    found_count = sum(1 for item in evidence if item.status == "found")
    mention_count = sum(1 for item in evidence if item.status == "mention")
    alert_count = sum(1 for item in evidence if item.status == "alert")
    avg_confidence = round(sum(item.confidence for item in evidence) / len(evidence)) if evidence else 0

    category_counts: dict[str, int] = {}
    for item in evidence:
        category_counts[item.category] = category_counts.get(item.category, 0) + 1

    top_categories = ", ".join(
        f"{name}:{count}"
        for name, count in sorted(category_counts.items(), key=lambda item: (-item[1], item[0]))[:4]
    ) or "без категорий"

    summary = [
        result(
            site="ℹ️ Нормализованная цель",
            url=target_label,
            status="info",
            score=100,
            confidence=100,
            category=target_type,
            reason="цель очищена и подготовлена к поиску",
            node_kind="summary",
        ),
        result(
            site="📊 Доверительный профиль",
            url=f"Средняя уверенность: {avg_confidence}/100 | Подтверждений: {found_count} | Контекста: {mention_count} | Рисков: {alert_count}",
            status="info",
            score=98,
            confidence=max(40, avg_confidence),
            category="analytics",
            reason="агрегат по всем найденным узлам",
            node_kind="summary",
        ),
        result(
            site="🧠 Категории графа",
            url=top_categories,
            status="info",
            score=97,
            confidence=max(35, avg_confidence),
            category="analytics",
            reason="распределение результатов по типам источников",
            node_kind="summary",
        ),
    ]

    if checked_sources is not None:
        summary.append(
            result(
                site="🌐 Охват проверки",
                url=f"Проверено источников: {checked_sources}",
                status="info",
                score=96,
                confidence=92,
                category="analytics",
                reason="масштаб текущего прохода по базе",
                node_kind="summary",
            )
        )
    return summary


async def search_username(target: str, job: SearchJobState | None = None) -> list[SearchResult]:
    username = extract_username_from_text(target)
    search_results: list[SearchResult] = []
    await update_job(job, f"Нормализация username: {username}", total=max(len(cached_db), 1) + 4, status="running")

    if not cached_db:
        search_results.append(
            result(
                site="⚠️ Источники недоступны",
                url="База WhatsMyName не загрузилась",
                status="alert",
                score=94,
                confidence=94,
                category="system",
                reason="без базы сайтов нельзя корректно выполнить массовую верификацию",
                node_kind="summary",
            )
        )
        return build_aggregate_results(username, "username", search_results)

    raw_results: list[SearchResult | None] = []
    chunk_size = 25
    async with httpx.AsyncClient(
        timeout=REQUEST_TIMEOUT,
        headers=REQUEST_HEADERS,
        follow_redirects=True,
        verify=VERIFY_SSL,
    ) as client:
        for start in range(0, len(cached_db), chunk_size):
            chunk = cached_db[start : start + chunk_size]
            await update_job(
                job,
                f"Проверка источников {start + 1}-{start + len(chunk)} из {len(cached_db)}",
            )
            chunk_results = await asyncio.gather(*[probe_username_site(client, site, username) for site in chunk])
            raw_results.extend(chunk_results)
            await update_job(job, f"Завершён блок {start + 1}-{start + len(chunk)}", increment=len(chunk))

    hits = [item for item in raw_results if item is not None]
    await update_job(job, "Запуск внешних username-движков")
    external_batches = await asyncio.gather(
        search_username_with_sherlock(username),
        search_username_with_maigret(username),
    )
    for batch in external_batches:
        hits.extend(hydrate_result(item) for item in batch)
    await update_job(job, "Внешние username-движки обработаны", increment=2)
    await update_job(job, "Добавление ручных RU/global источников")
    hits.extend(hydrate_result(item) for item in username_manual_sources(username))
    await update_job(job, "Ручные источники добавлены", increment=2)
    hits = sorted(hits, key=lambda item: (-item.confidence, item.site.lower()))[:USERNAME_RESULT_LIMIT]
    search_results.extend(build_aggregate_results(username, "username", hits, checked_sources=len(cached_db)))
    search_results.extend(hits)
    return search_results


def phone_type_to_label(number_type: PhoneNumberType) -> str:
    mapping = {
        PhoneNumberType.MOBILE: "Мобильный",
        PhoneNumberType.FIXED_LINE: "Стационарный",
        PhoneNumberType.FIXED_LINE_OR_MOBILE: "Смешанный",
        PhoneNumberType.TOLL_FREE: "Бесплатный",
        PhoneNumberType.PREMIUM_RATE: "Премиум",
        PhoneNumberType.VOIP: "VoIP",
        PhoneNumberType.PERSONAL_NUMBER: "Персональный",
        PhoneNumberType.PAGER: "Пейджер",
        PhoneNumberType.UAN: "UAN",
        PhoneNumberType.VOICEMAIL: "Голосовая почта",
        PhoneNumberType.SHARED_COST: "Разделяемая стоимость",
        PhoneNumberType.UNKNOWN: "Неизвестно",
    }
    return mapping.get(number_type, "Неизвестно")


def extract_search_result_url(raw_href: str) -> str:
    if not raw_href:
        return ""

    parsed = urlparse(raw_href)
    if parsed.netloc.endswith("duckduckgo.com") and parsed.path.startswith("/l/"):
        actual = parse_qs(parsed.query).get("uddg", [""])[0]
        return unquote(actual)
    return raw_href


async def search_phone_mentions(client: httpx.AsyncClient, parsed_phone: phonenumbers.PhoneNumber) -> list[SearchResult]:
    results: list[SearchResult] = []
    e164 = phonenumbers.format_number(parsed_phone, phonenumbers.PhoneNumberFormat.E164)
    international = phonenumbers.format_number(parsed_phone, phonenumbers.PhoneNumberFormat.INTERNATIONAL)
    national = phonenumbers.format_number(parsed_phone, phonenumbers.PhoneNumberFormat.NATIONAL)

    queries = []
    for variant in {e164, international, national, re.sub(r"\D", "", e164)}:
        if variant:
            queries.append(f"\"{variant}\"")

    for query in queries[:3]:
        try:
            response = await client.get(
                "https://html.duckduckgo.com/html/",
                params={"q": query},
                timeout=SEARCH_TIMEOUT,
            )
        except Exception:
            continue

        soup = BeautifulSoup(response.text, "html.parser")
        for link in soup.select("a.result__a")[:PHONE_MENTION_LIMIT]:
            href = extract_search_result_url(link.get("href", ""))
            title = normalize_whitespace(link.get_text(" ", strip=True))
            if href.startswith("http"):
                results.append(
                    result(
                        site=f"🔎 Упоминание номера: {title[:48]}",
                        url=href,
                        status="mention",
                        score=62,
                        confidence=62,
                        category="phone-osint",
                        reason="номер появился в выдаче поисковой системы, нужен ручной просмотр страницы",
                    )
                )
    return results


async def analyze_phone(target: str, job: SearchJobState | None = None) -> list[SearchResult]:
    parsed = normalize_phone(target)
    e164 = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
    await update_job(job, f"Нормализация телефона: {e164}", total=5, status="running")
    country = geocoder.description_for_number(parsed, "ru")
    operator = carrier.name_for_number(parsed, "ru")
    timezones = ", ".join(timezone.time_zones_for_number(parsed))
    number_type = phone_type_to_label(phonenumbers.number_type(parsed))
    country_code = parsed.country_code
    national_number = str(parsed.national_number)

    evidence = [
        result("🌍 Страна/регион", country or "Не определено", "info", 90, 90, "phone-meta", "геоданные из плана нумерации"),
        result("📡 Оператор", operator or "Не определён", "info", 84, 84, "phone-meta", "оператор из плана нумерации"),
        result("🕒 Часовые пояса", timezones or "Не определены", "info", 80, 80, "phone-meta", "часовые пояса номера"),
        result("📱 Тип номера", number_type, "info", 82, 82, "phone-meta", "тип линии по phonenumbers"),
        result(
            "🔗 WhatsApp handoff",
            f"https://wa.me/{country_code}{national_number}",
            "info",
            68,
            68,
            "handoff",
            "ссылка для ручной проверки, не доказательство существования аккаунта",
        ),
        result(
            "🔗 Viber handoff",
            f"viber://chat?number={quote(e164)}",
            "info",
            66,
            66,
            "handoff",
            "ссылка для ручной проверки, не доказательство существования аккаунта",
        ),
    ]
    await update_job(job, "Извлечены метаданные номера", increment=1)

    async with httpx.AsyncClient(headers=REQUEST_HEADERS, follow_redirects=True, verify=VERIFY_SSL) as client:
        await update_job(job, "Поиск веб-упоминаний номера")
        evidence.extend(await search_phone_mentions(client, parsed))
    await update_job(job, "Поиск веб-упоминаний завершён", increment=2)
    await update_job(job, "Добавление ручных телефонных источников")
    evidence.extend(hydrate_result(item) for item in phone_manual_sources(e164))
    await update_job(job, "Ручные телефонные источники добавлены", increment=2)

    return build_aggregate_results(e164, "phone", evidence) + evidence


async def dns_resolve(client: httpx.AsyncClient, hostname: str, record_type: str) -> list[str]:
    try:
        response = await client.get(
            "https://dns.google/resolve",
            params={"name": hostname, "type": record_type},
            timeout=SEARCH_TIMEOUT,
        )
        data = response.json()
    except Exception:
        return []

    answers = data.get("Answer") or []
    return [str(answer.get("data", "")).rstrip(".") for answer in answers if answer.get("data")]


async def check_gravatar(client: httpx.AsyncClient, email: str) -> list[SearchResult]:
    email_hash = hashlib.md5(email.encode("utf-8")).hexdigest()
    profile_url = f"https://www.gravatar.com/{email_hash}.json"

    try:
        response = await client.get(profile_url, timeout=SEARCH_TIMEOUT)
    except Exception:
        return []

    if response.status_code != 200:
        return []

    try:
        payload = response.json()
    except ValueError:
        return []

    entries = payload.get("entry") or []
    if not entries:
        return []

    entry = entries[0]
    results = [
        result(
            "🖼️ Gravatar профиль",
            profile_url,
            "mention",
            72,
            72,
            "public-profile",
            "найдён публичный профиль, связанный с хешем email",
        ),
    ]

    display_name = normalize_whitespace(entry.get("displayName", ""))
    profile_url_value = entry.get("profileUrl")
    about = normalize_whitespace(entry.get("aboutMe", ""))

    if display_name:
        results.append(result("👤 Публичное имя", display_name, "info", 76, 76, "public-profile", "имя указано в публичном профиле"))
    if profile_url_value:
        results.append(result("🌐 Публичный профиль", str(profile_url_value), "mention", 74, 74, "public-profile", "страница профиля доступна публично"))
    if about:
        results.append(result("📝 About", about[:180], "info", 64, 64, "public-profile", "публичный текст профиля"))
    return results


async def analyze_email(target: str, job: SearchJobState | None = None) -> list[SearchResult]:
    email = normalize_email(target)
    local_part, domain = email.split("@", 1)
    await update_job(job, f"Нормализация email: {email}", total=6, status="running")

    evidence = [
        result("🏷️ Локальная часть", local_part, "info", 85, 85, "email-meta", "левая часть адреса"),
        result("🌐 Домен", domain, "info", 85, 85, "email-meta", "домен адреса"),
    ]
    await update_job(job, "Базовые email-атрибуты собраны", increment=1)

    async with httpx.AsyncClient(headers=REQUEST_HEADERS, follow_redirects=True, verify=VERIFY_SSL) as client:
        await update_job(job, "Проверка MX/TXT записей домена")
        mx_records = await dns_resolve(client, domain, "MX")
        txt_records = await dns_resolve(client, domain, "TXT")
        evidence.append(
            result(
                "📬 MX записи",
                ", ".join(mx_records[:5]) if mx_records else "Не найдены",
                "info",
                82,
                82,
                "email-dns",
                "проверка почтовой инфраструктуры домена",
            )
        )

        spf_records = [item for item in txt_records if "v=spf1" in item.lower()]
        if spf_records:
            evidence.append(
                result(
                    "🛡️ SPF",
                    spf_records[0][:180],
                    "info",
                    78,
                    78,
                    "email-dns",
                    "найдена политика отправки почты",
                )
            )

        evidence.extend(await check_gravatar(client, email))
    await update_job(job, "DNS и публичный профиль проверены", increment=2)

    await update_job(job, "Добавление ручных email-источников")
    evidence.extend(hydrate_result(item) for item in email_manual_sources(email))
    await update_job(job, "Ручные email-источники добавлены", increment=1)
    await update_job(job, "Запуск holehe, если доступен")
    evidence.extend(hydrate_result(item) for item in await search_email_with_holehe(email))
    await update_job(job, "Holehe обработан", increment=2)
    return build_aggregate_results(email, "email", evidence) + evidence


async def enumerate_subdomains(target: str, job: SearchJobState | None = None) -> list[SearchResult]:
    domain = normalize_domain(target)
    evidence: list[SearchResult] = []
    await update_job(job, f"Нормализация домена: {domain}", total=6, status="running")

    try:
        ip_addresses = sorted({item[4][0] for item in socket.getaddrinfo(domain, None)})
    except socket.gaierror:
        ip_addresses = []

    if ip_addresses:
        evidence.append(
            result(
                "🌍 IP адреса",
                ", ".join(ip_addresses[:5]),
                "info",
                84,
                84,
                "domain-dns",
                "результат локального DNS-resolve",
            )
        )
    await update_job(job, "DNS-resolve завершён", increment=1)

    async with httpx.AsyncClient(headers=REQUEST_HEADERS, verify=VERIFY_SSL) as client:
        await update_job(job, "Запрос crt.sh для поддоменов")
        try:
            response = await client.get(
                "https://crt.sh/",
                params={"q": f"%.{domain}", "output": "json"},
                timeout=15.0,
            )
            entries = response.json() if response.status_code == 200 else []
        except Exception:
            entries = []
    await update_job(job, "crt.sh обработан", increment=2)

    subdomains: set[str] = set()
    for entry in entries:
        for name in str(entry.get("name_value", "")).splitlines():
            clean_name = name.replace("*.", "").strip().lower()
            if clean_name and clean_name != domain and clean_name.endswith(f".{domain}"):
                subdomains.add(clean_name)

    for subdomain in sorted(subdomains)[:40]:
        evidence.append(
            result(
                "🌐 Поддомен",
                f"https://{subdomain}",
                "mention",
                70,
                70,
                "domain-certs",
                "найден в сертификатах crt.sh",
            )
        )
    await update_job(job, "Поддомены собраны", increment=1)

    await update_job(job, f"Проверка Censys ({active_censys_mode()} mode), если ключи доступны")
    evidence.extend(hydrate_result(item) for item in await search_domain_with_censys(domain))
    await update_job(job, "Censys обработан", increment=1)

    await update_job(job, "Добавление ручных domain-источников")
    evidence.extend(hydrate_result(item) for item in domain_manual_sources(domain, spiderfoot_handoff_url()))
    await update_job(job, "Ручные domain-источники добавлены", increment=1)

    return build_aggregate_results(domain, "domain", evidence) + evidence


def format_gps_coordinate(coord: tuple[tuple[int, int], tuple[int, int], tuple[int, int]], ref: str) -> float:
    degrees = coord[0][0] / coord[0][1]
    minutes = coord[1][0] / coord[1][1]
    seconds = coord[2][0] / coord[2][1]
    value = degrees + (minutes / 60) + (seconds / 3600)
    return -value if ref in {"S", "W"} else value


def decode_exif_value(tag_name: str, value: Any) -> str:
    if tag_name == "GPSInfo" and isinstance(value, dict):
        gps = {GPSTAGS.get(key, key): item for key, item in value.items()}
        lat = gps.get("GPSLatitude")
        lat_ref = gps.get("GPSLatitudeRef")
        lon = gps.get("GPSLongitude")
        lon_ref = gps.get("GPSLongitudeRef")
        if lat and lat_ref and lon and lon_ref:
            latitude = format_gps_coordinate(lat, lat_ref)
            longitude = format_gps_coordinate(lon, lon_ref)
            return f"{latitude:.6f}, {longitude:.6f}"
        return json.dumps(gps, ensure_ascii=False)

    if isinstance(value, bytes):
        return value.decode("utf-8", errors="ignore")
    return str(value)


@app.get("/api/health")
async def healthcheck() -> dict[str, Any]:
    availability = tool_availability()
    return {
        "status": "ok",
        "wmn_sites": len(cached_db),
        "cache_entries": storage.cache_count(),
        "verify_ssl": VERIFY_SSL,
        "sqlite_db_path": str(SQLITE_DB_PATH),
        "external_tools": availability,
        "censys_legacy": availability.get("censys_legacy", False),
        "censys_platform": availability.get("censys_platform", False),
        "active_censys_mode": active_censys_mode(),
        "export_formats": ["maltego-csv"],
        "active_jobs": storage.active_run_count(),
    }


async def perform_search_internal(
    target: str,
    search_type: str,
    *,
    job: SearchJobState | None = None,
) -> list[dict[str, Any]]:
    cached = get_cached_result(search_type, target)
    if cached is not None:
        await update_job(job, "Результат взят из локального кэша", total=1, increment=1, status="completed")
        return cached

    if search_type == "username":
        results = await search_username(target, job=job)
    elif search_type == "email":
        results = await analyze_email(target, job=job)
    elif search_type == "phone":
        results = await analyze_phone(target, job=job)
    else:
        results = await enumerate_subdomains(target, job=job)

    payload = dedupe_and_sort(results)
    store_cached_result(search_type, target, payload)
    return payload


async def run_search_job(job: SearchJobState) -> None:
    job.started_at = time.time()
    job.status = "running"
    storage.update_job_state(job.snapshot())
    await update_job(job, "Задача поставлена в обработку")
    try:
        job.results = await perform_search_internal(job.target, job.search_type, job=job)
        storage.replace_job_results(job.job_id, job.results)
        job.status = "completed"
        job.progress = 100
        job.finished_at = time.time()
        storage.update_job_state(job.snapshot())
        await update_job(job, "Поиск завершён", status="completed")
    except HTTPException as exc:
        job.status = "failed"
        job.error = str(exc.detail)
        job.finished_at = time.time()
        storage.update_job_state(job.snapshot())
        await update_job(job, f"Ошибка: {job.error}", status="failed")
    except Exception as exc:
        job.status = "failed"
        job.error = str(exc)
        job.finished_at = time.time()
        storage.update_job_state(job.snapshot())
        await update_job(job, f"Внутренняя ошибка: {job.error}", status="failed")


@app.post("/api/search/jobs")
async def create_search_job(request: SearchJobRequest) -> dict[str, Any]:
    search_type = request.type.strip().lower()
    if search_type not in {"username", "email", "phone", "domain"}:
        raise HTTPException(status_code=400, detail="Неподдерживаемый тип поиска")

    job = SearchJobState(
        job_id=uuid4().hex,
        target=request.target,
        search_type=search_type,
    )
    storage.create_job(job.snapshot())
    asyncio.create_task(run_search_job(job))
    return job.snapshot()


@app.get("/api/search/jobs/{job_id}")
async def get_search_job(job_id: str) -> dict[str, Any]:
    snapshot = storage.get_job_snapshot(job_id)
    if snapshot is None:
        raise HTTPException(status_code=404, detail="Задача не найдена")
    return snapshot


@app.get("/api/search/jobs")
async def list_search_jobs(limit: int = Query(20, ge=1, le=100)) -> list[dict[str, Any]]:
    return storage.list_recent_jobs(limit=limit)


@app.get("/api/search")
async def perform_search(
    target: str = Query(..., min_length=1),
    type: str = Query(..., pattern="^(username|email|phone|domain)$"),
) -> list[dict[str, Any]]:
    return await perform_search_internal(target, type)


@app.get("/api/export/maltego")
async def export_maltego(
    target: str = Query(..., min_length=1),
    type: str = Query(..., pattern="^(username|email|phone|domain)$"),
) -> Response:
    results = await perform_search_internal(target, type)
    payload = build_maltego_csv_payload(type, target, results)
    file_name = safe_export_filename(type, target)
    storage.store_export("maltego-csv", type, target, file_name, payload)
    return Response(
        content=payload,
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{file_name}"'},
    )


@app.post("/api/metadata")
async def analyze_metadata(file: UploadFile = File(...)) -> list[dict[str, Any]]:
    try:
        payload = await file.read()
        image = Image.open(io.BytesIO(payload))
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Файл не является поддерживаемым изображением") from exc

    evidence = [
        result("📐 Размер", f"{image.width}x{image.height}", "info", 88, 88, "image-meta", "базовые свойства изображения"),
        result("🧾 Формат", image.format or "Не определён", "info", 86, 86, "image-meta", "формат изображения"),
    ]

    exif = image.getexif()
    if not exif:
        evidence.append(result("ℹ️ EXIF", "Метаданные не найдены", "info", 78, 78, "image-meta", "EXIF-блок отсутствует"))
    else:
        interesting_tags = {"Make", "Model", "Software", "DateTime", "GPSInfo", "Artist", "Copyright"}
        for tag, value in exif.items():
            tag_name = TAGS.get(tag, str(tag))
            if tag_name not in interesting_tags:
                continue
            decoded = decode_exif_value(tag_name, value)
            if tag_name == "GPSInfo":
                evidence.append(
                    result(
                        "EXIF: GPSInfo",
                        decoded[:200],
                        "alert",
                        94,
                        94,
                        "image-exif",
                        "в изображении есть координаты, это потенциально критично",
                    )
                )
            else:
                evidence.append(
                    result(
                        f"EXIF: {tag_name}",
                        decoded[:200],
                        "info",
                        80,
                        80,
                        "image-exif",
                        "извлечённый EXIF-тег",
                    )
                )

    evidence.extend(hydrate_result(item) for item in await search_image_with_search4faces(payload))

    return dedupe_and_sort(build_aggregate_results(file.filename or "upload", "image", evidence) + evidence)


if __name__ == "__main__":
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
