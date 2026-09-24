from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from analyzer import analyze_url
from virustotal import get_url_report
from google_safe_browsing import check_google
from database import init_database, save_scan, get_history


app = FastAPI(
    title="LinkGuard KZ",
    version="1.0"
)


# Инициализация базы данных
init_database()


# CORS
app.add_middleware(
    CORSMiddleware,
   allow_origins=[
    "http://127.0.0.1:5500",
    "http://localhost:5500",
    "https://linkguard-kz-1.onrender.com"
],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


class URLRequest(BaseModel):
    url: str


@app.get("/")
def home():
    return {
        "project": "LinkGuard KZ",
        "status": "running"
    }


@app.post("/check")
def check_url(request: URLRequest):

    url = request.url.strip()

    # Если пользователь не написал http/https,
    # автоматически добавляем HTTPS
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    # --------------------------------
    # 1. Локальный анализ
    # --------------------------------

    local = analyze_url(url)

    # --------------------------------
    # 2. VirusTotal
    # --------------------------------

    virustotal = get_url_report(url)

    # --------------------------------
    # 3. Google Safe Browsing
    # --------------------------------

    google = check_google(url)

    # --------------------------------
    # 4. Начальный Risk Score
    # --------------------------------

    score = local["score"]
    reasons = list(local.get("reasons", []))

    # --------------------------------
    # 5. Анализ VirusTotal
    # --------------------------------

    stats = virustotal.get("stats", {})

    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)

    if malicious > 0:
        score = max(score, 90)

        reasons.append(
            f"VirusTotal обнаружил {malicious} malicious detection"
        )

    elif suspicious > 0:
        score = max(score, 60)

        reasons.append(
            f"VirusTotal обнаружил {suspicious} suspicious detection"
        )

    # --------------------------------
    # 6. Анализ Google Safe Browsing
    # --------------------------------

    if google.get("found"):
        score = max(score, 90)

        reasons.append(
            "Google Safe Browsing обнаружил угрозу"
        )

    # --------------------------------
    # 7. Ограничиваем Score 0–100
    # --------------------------------

    score = min(score, 100)

    # --------------------------------
    # 8. Определяем уровень риска
    # --------------------------------

    if score >= 70:
        level = "dangerous"

    elif score >= 35:
        level = "suspicious"

    else:
        level = "safe"

    # --------------------------------
    # 9. Сохраняем проверку в SQLite
    # --------------------------------

    save_scan(
        url=url,
        domain=local.get("domain"),
        score=score,
        level=level,
        reasons=reasons,
        virustotal_malicious=malicious,
        virustotal_suspicious=suspicious,
        google_found=google.get("found", False)
    )

    # --------------------------------
    # 10. Возвращаем результат
    # --------------------------------

    return {
        "url": url,

        "risk": {
            "score": score,
            "level": level
        },

        "domain": local.get("domain"),

        "reasons": reasons,

        "local_analysis": local,

        "virustotal": virustotal,

        "google_safe_browsing": google
    }


# --------------------------------
# История проверок
# --------------------------------

@app.get("/history")
def history():

    return {
        "count": len(get_history()),
        "items": get_history()
    }