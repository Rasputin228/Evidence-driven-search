from __future__ import annotations

import asyncio
import base64
import os
import re
import shutil
from typing import Any
from urllib.parse import quote

import httpx
from osint_graph.bootstrap import load_local_env

load_local_env()

ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
URL_RE = re.compile(r"https?://[^\s<>()\"']+")
SEARCH4FACES_API_URL = "https://search4faces.com/api/json-rpc/v1"
CENSYS_LEGACY_API_URL = "https://search.censys.io/api/v2"
CENSYS_PLATFORM_API_URL = "https://api.platform.censys.io/v3"
SPIDERFOOT_WEBUI_URL = os.getenv("SPIDERFOOT_WEBUI_URL", "").strip().rstrip("/")
VERIFY_SSL = os.getenv("OSINT_VERIFY_SSL", "false").lower() in {"1", "true", "yes"}


def _censys_platform_pat() -> str:
    return os.getenv("CENSYS_PLATFORM_PAT", "").strip()


def _censys_legacy_credentials() -> tuple[str, str]:
    return os.getenv("CENSYS_API_ID", "").strip(), os.getenv("CENSYS_API_SECRET", "").strip()


def censys_platform_available() -> bool:
    return bool(_censys_platform_pat())


def censys_legacy_available() -> bool:
    api_id, api_secret = _censys_legacy_credentials()
    return bool(api_id and api_secret)


def active_censys_mode() -> str:
    if censys_platform_available():
        return "platform"
    if censys_legacy_available():
        return "legacy"
    return "disabled"


def tool_availability() -> dict[str, bool]:
    return {
        "sherlock": shutil.which("sherlock") is not None,
        "maigret": shutil.which("maigret") is not None,
        "holehe": shutil.which("holehe") is not None,
        "censys": active_censys_mode() != "disabled",
        "censys_legacy": censys_legacy_available(),
        "censys_platform": censys_platform_available(),
        "search4faces": bool(os.getenv("SEARCH4FACES_API_KEY")),
        "spiderfoot_handoff": bool(SPIDERFOOT_WEBUI_URL),
    }


def _clean_output(text: str) -> str:
    return ANSI_RE.sub("", text)


async def _run_command(command: list[str], timeout: float = 45.0) -> str:
    process = await asyncio.create_subprocess_exec(
        *command,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        process.kill()
        await process.communicate()
        return ""

    merged = (stdout or b"").decode("utf-8", errors="ignore") + "\n" + (stderr or b"").decode("utf-8", errors="ignore")
    return _clean_output(merged)


def _url_results(site: str, urls: set[str], category: str, reason: str, confidence: int) -> list[dict[str, Any]]:
    return [
        {
            "site": site,
            "url": url,
            "status": "found",
            "score": confidence,
            "confidence": confidence,
            "category": category,
            "reason": reason,
        }
        for url in sorted(urls)
    ]


def spiderfoot_handoff_url() -> str | None:
    return SPIDERFOOT_WEBUI_URL or None


async def search_username_with_sherlock(username: str) -> list[dict[str, Any]]:
    if shutil.which("sherlock") is None:
        return []

    output = await _run_command(
        ["sherlock", username, "--print-found", "--no-color", "--no-txt"],
        timeout=60.0,
    )
    urls = {match.rstrip(".,") for match in URL_RE.findall(output)}
    return _url_results(
        "🧰 Sherlock engine",
        urls,
        "external-sherlock",
        "совпадение получено внешним CLI-движком Sherlock",
        78,
    )


async def search_username_with_maigret(username: str) -> list[dict[str, Any]]:
    if shutil.which("maigret") is None:
        return []

    output = await _run_command(["maigret", username], timeout=70.0)
    urls = {match.rstrip(".,") for match in URL_RE.findall(output)}
    return _url_results(
        "🧰 Maigret engine",
        urls,
        "external-maigret",
        "совпадение получено внешним CLI-движком Maigret",
        76,
    )


async def search_email_with_holehe(email: str) -> list[dict[str, Any]]:
    if shutil.which("holehe") is None:
        return []

    output = await _run_command(["holehe", email, "--only-used"], timeout=70.0)
    results: list[dict[str, Any]] = []
    seen: set[str] = set()
    for raw_line in output.splitlines():
        line = raw_line.strip().lstrip("+").strip()
        if not line:
            continue
        if any(token in line.lower() for token in ("rate limit", "error", "usage:", "for help")):
            continue
        site_name = line.split(":", 1)[0].strip("[] ")
        if not site_name or site_name.lower() in seen:
            continue
        seen.add(site_name.lower())
        results.append(
            {
                "site": f"🧰 Holehe: {site_name}",
                "url": "Аккаунт/регистрация вероятно существуют",
                "status": "mention",
                "score": 74,
                "confidence": 74,
                "category": "external-holehe",
                "reason": "совпадение получено внешним CLI-движком Holehe",
            }
        )
    return results


async def search_domain_with_censys(domain: str) -> list[dict[str, Any]]:
    mode = active_censys_mode()
    if mode == "platform":
        results = await _search_domain_with_censys_platform(domain)
        if results:
            return results
        if censys_legacy_available():
            return await _search_domain_with_censys_legacy(domain)
        return []
    if mode == "legacy":
        return await _search_domain_with_censys_legacy(domain)
    return []


def _normalize_string_list(value: Any) -> list[str]:
    if isinstance(value, str):
        stripped = value.strip()
        return [stripped] if stripped else []
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    return []


def _lookup_field(payload: dict[str, Any], dotted_path: str) -> Any:
    if dotted_path in payload:
        return payload[dotted_path]

    current: Any = payload
    for part in dotted_path.split("."):
        if not isinstance(current, dict):
            return None
        current = current.get(part)
    return current


def _looks_like_platform_record(payload: dict[str, Any]) -> bool:
    if any(key in payload for key in ("host", "cert", "web", "matched_services", "asset_type")):
        return True
    return any(str(key).startswith(("host.", "cert.", "web.")) for key in payload)


def _collect_platform_records(node: Any) -> list[dict[str, Any]]:
    if isinstance(node, list):
        records: list[dict[str, Any]] = []
        for item in node:
            records.extend(_collect_platform_records(item))
        return records

    if not isinstance(node, dict):
        return []

    if _looks_like_platform_record(node):
        return [node]

    records: list[dict[str, Any]] = []
    for key in ("result", "results", "hits", "items", "records", "documents", "document", "data"):
        child = node.get(key)
        if child is not None:
            records.extend(_collect_platform_records(child))
    return records


def _platform_record_type(record: dict[str, Any]) -> str | None:
    asset_type = str(record.get("asset_type") or record.get("type") or "").strip().lower()
    if asset_type in {"host", "cert", "certificate", "web", "webproperty", "web_property"}:
        return "cert" if asset_type == "certificate" else ("web" if asset_type in {"webproperty", "web_property"} else asset_type)
    if "host" in record or any(key.startswith("host.") for key in record):
        return "host"
    if "cert" in record or any(key.startswith("cert.") for key in record):
        return "cert"
    if "web" in record or any(key.startswith("web.") for key in record):
        return "web"
    return None


def _platform_search_url(query: str) -> str:
    return "https://platform.censys.io"


def _platform_host_results(record: dict[str, Any]) -> list[dict[str, Any]]:
    ip_address = str(_lookup_field(record, "host.ip") or "").strip()
    if not ip_address:
        return []

    names = _normalize_string_list(_lookup_field(record, "host.names"))
    country = str(_lookup_field(record, "host.location.country") or "").strip()
    as_name = str(
        _lookup_field(record, "host.autonomous_system.description")
        or _lookup_field(record, "host.autonomous_system.name")
        or ""
    ).strip()
    services = _lookup_field(record, "matched_services") or _lookup_field(record, "host.services") or []
    ports = sorted(
        {
            str(service.get("port"))
            for service in services
            if isinstance(service, dict) and service.get("port") is not None
        }
    )
    hostname = names[0] if names else ip_address
    details = ", ".join(
        part
        for part in [
            hostname if hostname != ip_address else "",
            country,
            f"AS: {as_name}" if as_name else "",
            f"ports: {', '.join(ports[:4])}" if ports else "",
        ]
        if part
    )
    return [
        {
            "site": f"🌐 Censys Platform host: {hostname}",
            "url": f"{CENSYS_PLATFORM_API_URL}/global/asset/host/{ip_address}",
            "status": "found",
            "score": 86,
            "confidence": 86,
            "category": "external-censys-platform",
            "reason": f"host evidence найден через Censys Platform unified search; {details}" if details else "host evidence найден через Censys Platform unified search",
        }
    ]


def _platform_certificate_results(record: dict[str, Any]) -> list[dict[str, Any]]:
    fingerprint = str(_lookup_field(record, "cert.fingerprint_sha256") or "").strip()
    if not fingerprint:
        return []

    names = _normalize_string_list(_lookup_field(record, "cert.names"))
    subject_dn = str(_lookup_field(record, "cert.parsed.subject_dn") or "").strip()
    issuer_dn = str(_lookup_field(record, "cert.parsed.issuer_dn") or "").strip()
    summary = ", ".join(
        part
        for part in [
            subject_dn[:120] if subject_dn else "",
            f"SAN: {', '.join(names[:3])}" if names else "",
            f"issuer: {issuer_dn[:80]}" if issuer_dn else "",
        ]
        if part
    )
    return [
        {
            "site": "🔐 Censys Platform certificate",
            "url": f"{CENSYS_PLATFORM_API_URL}/global/asset/certificate/{fingerprint}",
            "status": "mention",
            "score": 80,
            "confidence": 80,
            "category": "external-censys-platform",
            "reason": f"certificate evidence найден через Censys Platform unified search; {summary}" if summary else "certificate evidence найден через Censys Platform unified search",
        }
    ]


def _platform_web_results(record: dict[str, Any]) -> list[dict[str, Any]]:
    hostname = str(_lookup_field(record, "web.hostname") or "").strip()
    port = _lookup_field(record, "web.port")
    if not hostname or port in (None, ""):
        return []

    webproperty_id = f"{hostname}:{port}"
    paths = _normalize_string_list(_lookup_field(record, "web.endpoints.path"))
    title = str(_lookup_field(record, "web.endpoints.http.html_title") or _lookup_field(record, "web.http.response.html_title") or "").strip()
    details = ", ".join(
        part
        for part in [
            f"port {port}",
            f"title: {title}" if title else "",
            f"paths: {', '.join(paths[:2])}" if paths else "",
        ]
        if part
    )
    return [
        {
            "site": f"🕸️ Censys Platform web property: {hostname}",
            "url": f"{CENSYS_PLATFORM_API_URL}/global/asset/webproperty/{quote(webproperty_id, safe='')}",
            "status": "found",
            "score": 84,
            "confidence": 84,
            "category": "external-censys-platform",
            "reason": f"web property evidence найден через Censys Platform unified search; {details}" if details else "web property evidence найден через Censys Platform unified search",
        }
    ]


async def _search_domain_with_censys_platform(domain: str) -> list[dict[str, Any]]:
    pat = _censys_platform_pat()
    if not pat:
        return []

    query = f"\"{domain}\""
    headers = {
        "Authorization": f"Bearer {pat}",
        "Accept": "application/json",
        "User-Agent": "OSINT Graph App",
    }
    try:
        async with httpx.AsyncClient(
            base_url=CENSYS_PLATFORM_API_URL,
            headers=headers,
            timeout=20.0,
            verify=VERIFY_SSL,
        ) as client:
            response = await client.post(
                "/global/search/query",
                json={
                    "query": query,
                    "page_size": 12,
                },
            )
            payload = response.json() if response.status_code == 200 else {}
    except Exception:
        return []

    results: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for record in _collect_platform_records(payload):
        record_type = _platform_record_type(record)
        if record_type == "host":
            candidates = _platform_host_results(record)
        elif record_type == "cert":
            candidates = _platform_certificate_results(record)
        elif record_type == "web":
            candidates = _platform_web_results(record)
        else:
            candidates = []

        for item in candidates:
            key = (item["site"], item["url"])
            if key in seen:
                continue
            seen.add(key)
            results.append(item)

    if results:
        return results[:8]

    return [
        {
            "site": "🛰️ Censys Platform search",
            "url": _platform_search_url(query),
            "status": "info",
            "score": 68,
            "confidence": 68,
            "category": "external-censys-platform",
            "reason": "Censys Platform доступен, но API search не вернул компактные asset records для автоматического разбора; открыт прямой search handoff",
        }
    ]


async def _search_domain_with_censys_legacy(domain: str) -> list[dict[str, Any]]:
    api_id, api_secret = _censys_legacy_credentials()
    if not api_id or not api_secret:
        return []

    auth = (api_id, api_secret)
    query = f"\"{domain}\""
    results: list[dict[str, Any]] = []

    async with httpx.AsyncClient(
        base_url=CENSYS_LEGACY_API_URL,
        auth=auth,
        headers={"User-Agent": "OSINT Graph App"},
        timeout=20.0,
        verify=VERIFY_SSL,
    ) as client:
        try:
            hosts_response = await client.get(
                "/hosts/search",
                params={
                    "q": query,
                    "per_page": 5,
                    "virtual_hosts": "INCLUDE",
                },
            )
            hosts_payload = hosts_response.json() if hosts_response.status_code == 200 else {}
        except Exception:
            hosts_payload = {}

        try:
            certs_response = await client.post(
                "/certificates/search",
                json={
                    "query": f"parsed.names: {domain}",
                    "page": 1,
                    "fields": [
                        "parsed.fingerprint_sha256",
                        "parsed.names",
                        "parsed.subject.common_name",
                        "parsed.validity_period.not_after",
                    ],
                    "flatten": True,
                },
            )
            certs_payload = certs_response.json() if certs_response.status_code == 200 else {}
        except Exception:
            certs_payload = {}

    host_hits = ((hosts_payload.get("result") or {}).get("hits") or [])[:5]
    for hit in host_hits:
        ip_address = str(hit.get("ip", "")).strip()
        hostname = str(hit.get("name") or domain).strip()
        if not ip_address:
            continue

        location = hit.get("location") or {}
        country = str(location.get("country") or "").strip()
        autonomous_system = hit.get("autonomous_system") or {}
        as_name = str(autonomous_system.get("description") or autonomous_system.get("name") or "").strip()
        matched_services = hit.get("matched_services") or hit.get("services") or []
        ports = sorted(
            {
                str(service.get("port"))
                for service in matched_services
                if isinstance(service, dict) and service.get("port") is not None
            }
        )
        details = ", ".join(part for part in [hostname, country, f"AS: {as_name}" if as_name else "", f"ports: {', '.join(ports[:4])}" if ports else ""] if part)
        results.append(
            {
                "site": f"🌐 Censys Legacy host: {hostname or ip_address}",
                "url": f"https://search.censys.io/hosts/{ip_address}",
                "status": "found",
                "score": 83,
                "confidence": 83,
                "category": "external-censys-legacy",
                "reason": f"host evidence найден через Censys Legacy Search; {details}" if details else "host evidence найден через Censys Legacy Search",
            }
        )

    cert_hits = (certs_payload.get("results") or [])[:5]
    for hit in cert_hits:
        fingerprint = str(hit.get("parsed.fingerprint_sha256") or "").strip()
        if not fingerprint:
            continue
        raw_names = hit.get("parsed.names") or []
        if isinstance(raw_names, str):
            names = [raw_names]
        else:
            names = [str(item).strip() for item in raw_names if str(item).strip()]
        common_name = hit.get("parsed.subject.common_name")
        if isinstance(common_name, list):
            common_name = ", ".join(str(item).strip() for item in common_name[:2] if str(item).strip())
        valid_until = str(hit.get("parsed.validity_period.not_after") or "").strip()
        summary = ", ".join(
            part for part in [str(common_name or "").strip(), f"SAN: {', '.join(names[:3])}" if names else "", f"valid until: {valid_until}" if valid_until else ""] if part
        )
        results.append(
            {
                "site": "🔐 Censys Legacy certificate",
                "url": f"https://search.censys.io/certificates/{fingerprint}",
                "status": "mention",
                "score": 79,
                "confidence": 79,
                "category": "external-censys-legacy",
                "reason": f"certificate evidence найден через Censys Legacy Search; {summary}" if summary else "certificate evidence найден через Censys Legacy Search",
            }
        )

    return results


async def search_image_with_search4faces(image_bytes: bytes) -> list[dict[str, Any]]:
    api_key = os.getenv("SEARCH4FACES_API_KEY", "").strip()
    if not api_key or not image_bytes:
        return []

    encoded_image = base64.b64encode(image_bytes).decode("ascii")
    headers = {
        "Content-Type": "application/json",
        "x-authorization-token": api_key,
        "User-Agent": "OSINT Graph App",
    }

    async with httpx.AsyncClient(timeout=45.0, headers=headers, verify=VERIFY_SSL) as client:
        try:
            detect_response = await client.post(
                SEARCH4FACES_API_URL,
                json={
                    "jsonrpc": "2.0",
                    "method": "detectFaces",
                    "id": "detect-faces",
                    "params": {"image": encoded_image},
                },
            )
            detect_payload = detect_response.json()
        except Exception:
            return []

        detect_result = detect_payload.get("result") or {}
        faces = detect_result.get("faces") or []
        image_token = str(detect_result.get("image") or "").strip()
        if not faces or not image_token:
            return []

        primary_face = faces[0]
        try:
            search_response = await client.post(
                SEARCH4FACES_API_URL,
                json={
                    "jsonrpc": "2.0",
                    "method": "searchFace",
                    "id": "search-face",
                    "params": {
                        "image": image_token,
                        "face": primary_face,
                        "source": "vk_wall",
                        "hidden": True,
                        "results": 8,
                        "lang": "ru",
                    },
                },
            )
            search_payload = search_response.json()
        except Exception:
            return [
                {
                    "site": "🧠 Search4Faces",
                    "url": "Лицо найдено, но поиск похожих профилей не завершился",
                    "status": "alert",
                    "score": 70,
                    "confidence": 70,
                    "category": "external-search4faces",
                    "reason": "API Search4Faces вернул частичный результат: лицо обнаружено, но профили не получены",
                }
            ]

    profiles = (search_payload.get("result") or {}).get("profiles") or []
    results = [
        {
            "site": "🧠 Search4Faces: face detected",
            "url": f"Обнаружено лиц: {len(faces)}",
            "status": "info",
            "score": 82,
            "confidence": 82,
            "category": "external-search4faces",
            "reason": "Search4Faces успешно распознал лицо на загруженном изображении",
        }
    ]

    for profile in profiles[:8]:
        profile_url = str(profile.get("profile") or "").strip()
        if not profile_url:
            continue
        score_raw = str(profile.get("score") or "0").strip()
        try:
            similarity = int(float(score_raw))
        except ValueError:
            similarity = 70

        subject = " ".join(
            part
            for part in [
                str(profile.get("first_name") or "").strip(),
                str(profile.get("last_name") or "").strip(),
            ]
            if part
        ).strip() or "Profile match"
        city = str(profile.get("city") or "").strip()
        country = str(profile.get("country") or "").strip()
        age = profile.get("age")
        detail_parts = [subject]
        if city or country:
            detail_parts.append(", ".join(part for part in [city, country] if part))
        if age not in (None, ""):
            detail_parts.append(f"возраст: {age}")

        results.append(
            {
                "site": f"🧠 Search4Faces: {subject}",
                "url": profile_url,
                "status": "found",
                "score": similarity,
                "confidence": similarity,
                "category": "external-search4faces",
                "reason": f"похожий профиль найден через Search4Faces; {' | '.join(detail_parts)}",
            }
        )

    return results
