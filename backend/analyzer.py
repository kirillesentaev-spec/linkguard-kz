from urllib.parse import urlparse
import ipaddress
import tldextract


SUSPICIOUS_WORDS = [
    "login",
    "signin",
    "verify",
    "verification",
    "secure",
    "account",
    "update",
    "password",
    "wallet",
    "bank",
    "confirm",
    "bonus",
    "free",
    "gift",
]


def analyze_url(url: str):
    score = 0
    reasons = []

    parsed = urlparse(url)

    # Проверяем протокол
    if parsed.scheme not in ["http", "https"]:
        return {
            "score": 100,
            "level": "dangerous",
            "reasons": ["Неверный протокол URL"]
        }

    # HTTP менее безопасен, чем HTTPS
    if parsed.scheme == "http":
        score += 10
        reasons.append("Используется HTTP вместо HTTPS")

    hostname = parsed.hostname

    if not hostname:
        return {
            "score": 100,
            "level": "dangerous",
            "reasons": ["Не удалось определить домен"]
        }

    hostname = hostname.lower()

    # Проверяем, является ли адрес IP
    try:
        ipaddress.ip_address(hostname)

        score += 25
        reasons.append("Вместо домена используется IP-адрес")

    except ValueError:
        pass

    # Очень длинный URL
    if len(url) > 200:
        score += 10
        reasons.append("Очень длинный URL")

    if len(url) > 400:
        score += 10
        reasons.append("URL необычно длинный")

    # Символ @ может использоваться для маскировки адреса
    if "@" in url:
        score += 25
        reasons.append("URL содержит символ @")

    # Проверяем поддомены
    extracted = tldextract.extract(hostname)
    subdomain = extracted.subdomain

    if subdomain:
        subdomain_count = len(subdomain.split("."))

        if subdomain_count >= 3:
            score += 15
            reasons.append("Слишком много поддоменов")

    # Подозрительные слова
    lower_url = url.lower()

    found_words = []

    for word in SUSPICIOUS_WORDS:
        if word in lower_url:
            found_words.append(word)

    if found_words:
        score += min(len(found_words) * 5, 20)

        reasons.append(
            "Найдены подозрительные слова: "
            + ", ".join(found_words)
        )

    # Punycode
    if "xn--" in hostname:
        score += 20
        reasons.append("Домен использует punycode")

    # Много дефисов
    if hostname.count("-") >= 3:
        score += 10
        reasons.append("В домене много дефисов")

    # Много цифр
    digit_count = sum(
        character.isdigit()
        for character in hostname
    )

    if digit_count >= 5:
        score += 10
        reasons.append("В домене необычно много цифр")

    # Ограничиваем максимум
    score = min(score, 100)

    # Определяем уровень риска
    if score >= 70:
        level = "dangerous"

    elif score >= 35:
        level = "suspicious"

    else:
        level = "safe"

    return {
        "score": score,
        "level": level,
        "domain": hostname,
        "reasons": reasons
    }