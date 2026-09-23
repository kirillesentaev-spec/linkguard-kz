from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from analyzer import analyze_url
from virustotal import get_url_report
from google_safe_browsing import check_google


app = FastAPI(
    title="LinkGuard KZ",
    version="1.0"
)



app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://127.0.0.1:5500",
        "http://localhost:5500"
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

    # Добавляем HTTPS, если пользователь написал только домен
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    # ==========================================
    # 1. ЛОКАЛЬНЫЙ АНАЛИЗ
    # ==========================================

    local = analyze_url(url)


    # ==========================================
    # 2. VIRUSTOTAL
    # ==========================================

    virustotal = get_url_report(url)


    # ==========================================
    # 3. GOOGLE SAFE BROWSING
    # ==========================================

    google = check_google(url)


    # ==========================================
    # НАЧАЛЬНЫЙ RISK SCORE
    # ==========================================

    score = local["score"]

    reasons = list(
        local.get("reasons", [])
    )


    # ==========================================
    # АНАЛИЗ VIRUSTOTAL
    # ==========================================

    stats = virustotal.get(
        "stats",
        {}
    )

    malicious = stats.get(
        "malicious",
        0
    )

    suspicious = stats.get(
        "suspicious",
        0
    )


    # Если VirusTotal обнаружил угрозу
    if malicious > 0:

        score = max(
            score,
            90
        )

        reasons.append(
            f"VirusTotal обнаружил "
            f"{malicious} malicious detection"
        )


    # Если есть подозрительные срабатывания
    elif suspicious > 0:

        score = max(
            score,
            60
        )

        reasons.append(
            f"VirusTotal обнаружил "
            f"{suspicious} suspicious detection"
        )


    # ==========================================
    # АНАЛИЗ GOOGLE SAFE BROWSING
    # ==========================================

    if google.get("found"):

        score = max(
            score,
            90
        )

        reasons.append(
            "Google Safe Browsing обнаружил угрозу"
        )


    # ==========================================
    # ОГРАНИЧИВАЕМ SCORE ОТ 0 ДО 100
    # ==========================================

    score = min(
        score,
        100
    )


    # ==========================================
    # ОПРЕДЕЛЯЕМ УРОВЕНЬ РИСКА
    # ==========================================

    if score >= 70:

        level = "dangerous"

    elif score >= 35:

        level = "suspicious"

    else:

        level = "safe"


    # ==========================================
    # ОТВЕТ API
    # ==========================================

    return {

        "url": url,

        "risk": {
            "score": score,
            "level": level
        },

        "domain": local.get(
            "domain"
        ),

        "reasons": reasons,

        "local_analysis": local,

        "virustotal": virustotal,

        "google_safe_browsing": google
    }