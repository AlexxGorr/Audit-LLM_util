"""Проверка репутации репозитория на HuggingFace."""
import time
from dataclasses import dataclass, field
from datetime import datetime

import requests

HF_API = "https://huggingface.co/api/models"

OFFICIAL_AUTHORS = {
    "meta-llama", "mistralai", "google", "microsoft", "openai",
    "qwen", "01-ai", "tiiuae", "anthropic", "facebook",
    "deepseek-ai", "stabilityai", "EleutherAI", "bigscience",
    "HuggingFaceH4", "allenai", "cohere", "xai-org",
}


@dataclass
class TrustResult:
    """Результат trust-проверки."""
    repo_id: str
    exists: bool = False
    author: str = ""
    author_official: bool = False
    downloads: int = 0
    likes: int = 0
    created_at: str = ""
    last_modified: str = ""
    license: str = ""
    has_model_card: bool = False
    files_count: int = 0
    trust_score: int = 0
    reasons: list[dict] = field(default_factory=list)
    error: str = ""
    duration_ms: int = 0
    gated: str = ''


def check_trust(repo_id: str, timeout: int = 5) -> TrustResult:
    """Проверяет репутацию репозитория на HuggingFace.

    Args:
        repo_id: например, "meta-llama/Llama-2-7b"
        timeout: таймаут HTTP-запроса в секундах

    Returns:
        TrustResult с score и reasons.
    """
    start = time.monotonic()
    result = TrustResult(repo_id=repo_id)

    # 1. HTTP-запрос
    try:
        url = f"{HF_API}/{repo_id}"
        response = requests.get(url, timeout=timeout)
    except requests.RequestException as e:
        result.error = f"Request failed: {e}"
        result.duration_ms = int((time.monotonic() - start) * 1000)
        return result

    # 2. 404 → repo не существует
    if response.status_code in (401, 403, 404):
        result.exists = False
        result.error = f"Repository not found or inaccessible: {repo_id} (HTTP {response.status_code})"
        result.duration_ms = int((time.monotonic() - start) * 1000)
        return result

    if response.status_code != 200:
        result.error = f"HTTP {response.status_code}"
        result.duration_ms = int((time.monotonic() - start) * 1000)
        return result

    # 3. Парсинг
    try:
        data = response.json()
    except ValueError as e:
        result.error = f"Invalid JSON: {e}"
        result.duration_ms = int((time.monotonic() - start) * 1000)
        return result

    result.exists = True
    result.author = data.get("author", "")
    result.downloads = data.get("downloads", 0) or 0
    result.likes = data.get("likes", 0) or 0
    result.created_at = data.get("createdAt", "")
    result.last_modified = data.get("lastModified", "")
    result.license = (data.get("cardData") or {}).get("license", "")
    result.gated = data.get("gated", "") or ""

    siblings = data.get("siblings", [])
    result.files_count = len(siblings)
    filenames = {s.get("rfilename", "") for s in siblings}
    result.has_model_card = "README.md" in filenames

    # 4. Score
    _compute_score(result)

    result.duration_ms = int((time.monotonic() - start) * 1000)
    return result


def _compute_score(result: TrustResult) -> None:
    """Вычисляет trust_score и заполняет reasons."""
    score = 0

    # Автор
    result.author_official = result.author in OFFICIAL_AUTHORS
    if result.author_official:
        score += 40
        result.reasons.append({"text": f"Official author: {result.author}", "sign": "+"})
    elif result.author:
        # Не штрафуем, но и не хвалим — просто отмечаем
        result.reasons.append({"text": f"Unofficial author: {result.author}", "sign": "0"})

    # Downloads
    if result.gated:
        result.reasons.append({
            "text": f"Gated model ({result.gated}) — downloads may be hidden",
            "sign": "0",
        })
    elif result.downloads >= 100_000:
        score += 20
        result.reasons.append({"text": f"High downloads: {result.downloads:,}", "sign": "+"})
    elif result.downloads >= 10_000:
        score += 15
        result.reasons.append({"text": f"Good downloads: {result.downloads:,}", "sign": "+"})
    elif result.downloads >= 1_000:
        score += 10
        result.reasons.append({"text": f"Moderate downloads: {result.downloads:,}", "sign": "0"})
    elif result.downloads >= 100:
        score += 5
        result.reasons.append({"text": f"Low downloads: {result.downloads:,}", "sign": "0"})
    else:
        result.reasons.append({"text": f"Very low downloads: {result.downloads}", "sign": "0"})

    # Likes
    if result.likes >= 1_000:
        score += 15
        result.reasons.append({"text": f"High likes: {result.likes:,}", "sign": "+"})
    elif result.likes >= 100:
        score += 10
        result.reasons.append({"text": f"Moderate likes: {result.likes:,}", "sign": "+"})
    elif result.likes >= 10:
        score += 5
        result.reasons.append({"text": f"Some likes: {result.likes}", "sign": "0"})

    # Model card
    if result.has_model_card:
        score += 10
        result.reasons.append({"text": "Model card present", "sign": "+"})
    else:
        result.reasons.append({"text": "No model card", "sign": "0"})

    # License
    if result.license:
        score += 5
        result.reasons.append({"text": f"License: {result.license}", "sign": "+"})
    else:
        result.reasons.append({"text": "No license specified", "sign": "0"})

    # Свежесть
    if result.last_modified:
        try:
            dt = datetime.fromisoformat(result.last_modified.replace("Z", "+00:00"))
            now = datetime.now(dt.tzinfo)
            age_days = (now - dt).days
            if age_days < 365:
                score += 10
                result.reasons.append({"text": f"Updated {age_days} days ago", "sign": "+"})
            elif age_days < 730:
                score += 5
                result.reasons.append({"text": f"Updated {age_days} days ago", "sign": "+"})
            elif age_days < 1825:  # 5 лет
                result.reasons.append({"text": f"Updated {age_days} days ago", "sign": "0"})
            else:
                result.reasons.append({"text": f"Outdated ({age_days} days)", "sign": "0"})
        except ValueError:
            pass

    result.trust_score = min(score, 100)


def status_from_score(score: int) -> str:
    """Возвращает статус по score."""
    if score >= 70:
        return "pass"
    if score >= 40:
        return "warn"
    return "fail"











