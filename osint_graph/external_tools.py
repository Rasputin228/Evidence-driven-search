from __future__ import annotations

import asyncio
import re
import shutil
from typing import Any


ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
URL_RE = re.compile(r"https?://[^\s<>()\"']+")


def tool_availability() -> dict[str, bool]:
    return {
        "sherlock": shutil.which("sherlock") is not None,
        "maigret": shutil.which("maigret") is not None,
        "holehe": shutil.which("holehe") is not None,
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
