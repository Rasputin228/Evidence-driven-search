from __future__ import annotations

import re
from urllib.parse import quote_plus


def _engine_url(base: str, query: str) -> str:
    return f"{base}{quote_plus(query)}"


def username_manual_sources(username: str) -> list[dict[str, str | int]]:
    exact_query = f"\"{username}\""
    return [
        {
            "site": "🛰️ Telegram direct",
            "url": f"https://t.me/{username}",
            "status": "mention",
            "score": 71,
            "confidence": 71,
            "category": "manual-telegram",
            "reason": "прямая ручная проверка Telegram-username",
        },
        {
            "site": "🔎 Yandex: общий поиск",
            "url": _engine_url("https://yandex.ru/search/?text=", exact_query),
            "status": "mention",
            "score": 67,
            "confidence": 67,
            "category": "manual-search",
            "reason": "ручной поиск точного ника в Яндексе",
        },
        {
            "site": "🔎 Google: общий поиск",
            "url": _engine_url("https://www.google.com/search?q=", exact_query),
            "status": "mention",
            "score": 67,
            "confidence": 67,
            "category": "manual-search",
            "reason": "ручной поиск точного ника в Google",
        },
        {
            "site": "🇷🇺 Yandex: VK traces",
            "url": _engine_url("https://yandex.ru/search/?text=", f"site:vk.com {exact_query}"),
            "status": "mention",
            "score": 69,
            "confidence": 69,
            "category": "ru-osint",
            "reason": "поиск следов ника во VK через Яндекс",
        },
        {
            "site": "🇷🇺 Yandex: OK traces",
            "url": _engine_url("https://yandex.ru/search/?text=", f"site:ok.ru {exact_query}"),
            "status": "mention",
            "score": 68,
            "confidence": 68,
            "category": "ru-osint",
            "reason": "поиск следов ника в Одноклассниках через Яндекс",
        },
        {
            "site": "🇷🇺 Yandex: Avito traces",
            "url": _engine_url("https://yandex.ru/search/?text=", f"site:avito.ru {exact_query}"),
            "status": "mention",
            "score": 66,
            "confidence": 66,
            "category": "ru-osint",
            "reason": "поиск объявлений и следов на Авито",
        },
        {
            "site": "🌍 GitHub direct",
            "url": f"https://github.com/{username}",
            "status": "mention",
            "score": 64,
            "confidence": 64,
            "category": "manual-dev",
            "reason": "ручная проверка профиля GitHub",
        },
        {
            "site": "🌍 GitLab direct",
            "url": f"https://gitlab.com/{username}",
            "status": "mention",
            "score": 63,
            "confidence": 63,
            "category": "manual-dev",
            "reason": "ручная проверка профиля GitLab",
        },
    ]


def phone_manual_sources(phone_e164: str) -> list[dict[str, str | int]]:
    digits = re.sub(r"\D", "", phone_e164)
    return [
        {
            "site": "🔎 Yandex: телефон",
            "url": _engine_url("https://yandex.ru/search/?text=", f"\"{phone_e164}\""),
            "status": "mention",
            "score": 67,
            "confidence": 67,
            "category": "phone-manual",
            "reason": "поиск точного номера в Яндексе",
        },
        {
            "site": "🔎 Google: телефон",
            "url": _engine_url("https://www.google.com/search?q=", f"\"{phone_e164}\""),
            "status": "mention",
            "score": 67,
            "confidence": 67,
            "category": "phone-manual",
            "reason": "поиск точного номера в Google",
        },
        {
            "site": "🇷🇺 Yandex: Авито по номеру",
            "url": _engine_url("https://yandex.ru/search/?text=", f"site:avito.ru \"{digits}\""),
            "status": "mention",
            "score": 65,
            "confidence": 65,
            "category": "ru-osint",
            "reason": "поиск объявлений по номеру на Авито через Яндекс",
        },
        {
            "site": "🇷🇺 Yandex: VK по номеру",
            "url": _engine_url("https://yandex.ru/search/?text=", f"site:vk.com \"{digits}\""),
            "status": "mention",
            "score": 64,
            "confidence": 64,
            "category": "ru-osint",
            "reason": "поиск индексации номера во VK через Яндекс",
        },
    ]


def email_manual_sources(email: str) -> list[dict[str, str | int]]:
    return [
        {
            "site": "🔎 Yandex: email",
            "url": _engine_url("https://yandex.ru/search/?text=", f"\"{email}\""),
            "status": "mention",
            "score": 66,
            "confidence": 66,
            "category": "email-manual",
            "reason": "поиск точного email в Яндексе",
        },
        {
            "site": "🔎 Google: email",
            "url": _engine_url("https://www.google.com/search?q=", f"\"{email}\""),
            "status": "mention",
            "score": 66,
            "confidence": 66,
            "category": "email-manual",
            "reason": "поиск точного email в Google",
        },
        {
            "site": "🇷🇺 Yandex: VK email traces",
            "url": _engine_url("https://yandex.ru/search/?text=", f"site:vk.com \"{email}\""),
            "status": "mention",
            "score": 63,
            "confidence": 63,
            "category": "ru-osint",
            "reason": "поиск следов email во VK через Яндекс",
        },
    ]
