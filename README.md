\# 🛡️ LinkGuard KZ



LinkGuard KZ — это веб-приложение для анализа подозрительных и потенциально вредоносных URL-адресов.



Проект позволяет проверить ссылку \*\*до перехода по ней\*\*, используя локальный анализ URL, VirusTotal и Google Safe Browsing.



\## 🚀 Возможности



\- 🔍 Анализ структуры URL

\- 🧠 Локальный анализ подозрительных признаков

\- 🦠 Проверка через VirusTotal

\- 🛡️ Проверка через Google Safe Browsing

\- 📊 Risk Score от 0 до 100

\- 🟢 SAFE

\- 🟡 SUSPICIOUS

\- 🔴 DANGEROUS

\- 📋 Отображение причин риска

\- 🌐 Веб-интерфейс в стиле cybersecurity dashboard



\## 🏗️ Архитектура



```text

User

&#x20; ↓

Frontend

HTML / CSS / JavaScript

&#x20; ↓

FastAPI Backend

&#x20; ↓

┌───────────────────────┐

│ Local URL Analyzer    │

│ VirusTotal            │

│ Google Safe Browsing  │

└───────────────────────┘

&#x20; ↓

Risk Score

&#x20; ↓

SAFE / SUSPICIOUS / DANGEROUS
🛠️ Технологии
Frontend
HTML
CSS
JavaScript
Backend
Python
FastAPI
Requests
Pydantic
Security APIs
VirusTotal API
Google Safe Browsing API
Дополнительно
python-dotenv
tldextract
Git / GitHub
📁 Структура проекта
linkguard-kz/
│
├── backend/
│   ├── analyzer.py
│   ├── google_safe_browsing.py
│   ├── main.py
│   └── virustotal.py
│
├── frontend/
│   ├── index.html
│   ├── script.js
│   └── style.css
│
├── .gitignore
├── README.md
└── requirements.txt
⚙️ Установка

Клонировать репозиторий:

git clone https://github.com/kirillesentaev-spec/linkguard-kz.git

Перейти в проект:

cd linkguard-kz

Создать виртуальное окружение:

python -m venv .venv

Активировать его в PowerShell:

.\.venv\Scripts\Activate.ps1

Установить зависимости:

pip install -r requirements.txt
🔐 API Keys

Создайте файл .env в корне проекта:

VIRUSTOTAL_API_KEY=your_api_key
GOOGLE_SAFE_BROWSING_KEY=your_api_key

Никогда не публикуйте API-ключи в GitHub.

Файл .env уже добавлен в .gitignore.

▶️ Запуск Backend
cd backend
uvicorn main:app --reload

Backend будет доступен по адресу:

http://127.0.0.1:8000
▶️ Запуск Frontend

В отдельном PowerShell:

python -m http.server 5500 --directory frontend

Откройте:

http://127.0.0.1:5500
🧪 Пример безопасного тестирования

Для теста можно использовать:

https://example.com

Также можно использовать синтетические URL для проверки локального анализатора, не переходя по ним:

http://192.0.2.10/login/verify/account/password
📊 Как работает Risk Score

Система анализирует различные признаки URL:

использование HTTP вместо HTTPS;
IP вместо доменного имени;
слишком длинный URL;
символ @;
большое количество поддоменов;
подозрительные слова;
punycode;
большое количество дефисов;
необычное количество цифр;
результаты VirusTotal;
результаты Google Safe Browsing.

На основе этих данных формируется итоговый Risk Score.

🔮 Будущие улучшения
URLhaus
IP reputation
Domain reputation
SQLite / PostgreSQL
История проверок
Dashboard для SOC
Machine Learning модель
Browser Extension
Docker
GitHub Actions
Система уведомлений
Расширенный анализ домена и DNS
🎯 Цель проекта

LinkGuard KZ создан как defensive cybersecurity prototype для предварительной оценки безопасности URL-адресов.

Проект не открывает проверяемую ссылку и не является заменой полноценным корпоративным системам информационной безопасности.

👨‍💻 Автор

Есентаев Нуркерей

AI & Data Analytics
KRU named after Akhmet Baitursynuly

