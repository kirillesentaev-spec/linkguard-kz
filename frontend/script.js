async function checkURL() {

    // Получаем элементы со страницы
    const input = document.getElementById("url");
    const result = document.getElementById("result");
    const loading = document.getElementById("loading");

    // Получаем URL из поля
    const url = input.value.trim();


    // ==========================================
    // ПРОВЕРЯЕМ, ВВЁЛ ЛИ ПОЛЬЗОВАТЕЛЬ URL
    // ==========================================

    if (!url) {

        alert("Введите URL");

        return;
    }


    // ==========================================
    // ПОКАЗЫВАЕМ ЗАГРУЗКУ
    // ==========================================

    result.classList.add("hidden");

    loading.classList.remove("hidden");


    try {

        // ==========================================
        // ОТПРАВЛЯЕМ URL НА BACKEND
        // ==========================================

        const response = await fetch(
            "https://linkguard-kz.onrender.com/check",
            {
                method: "POST",

                headers: {
                    "Content-Type": "application/json"
                },

                body: JSON.stringify({
                    url: url
                })
            }
        );


        // ==========================================
        // ПОЛУЧАЕМ ОТВЕТ
        // ==========================================

        const data = await response.json();


        // ==========================================
        // СКРЫВАЕМ ЗАГРУЗКУ
        // ==========================================

        loading.classList.add("hidden");

        result.classList.remove("hidden");


        // ==========================================
        // RISK SCORE
        // ==========================================

        document.getElementById("score").textContent =
            data.risk.score;


        // ==========================================
        // STATUS
        // ==========================================

        const status =
            document.getElementById("status");


        if (data.risk.level === "safe") {

            status.textContent = "🟢 SAFE";

            status.style.color = "#22c55e";

        }

        else if (data.risk.level === "suspicious") {

            status.textContent = "🟡 SUSPICIOUS";

            status.style.color = "#f59e0b";

        }

        else {

            status.textContent = "🔴 DANGEROUS";

            status.style.color = "#ef4444";

        }


        // ==========================================
        // ПОКАЗЫВАЕМ ПРОВЕРЕННЫЙ URL
        // ==========================================

        document.getElementById(
            "checked-url"
        ).textContent = data.url;


        // ==========================================
        // LOCAL ANALYZER
        // ==========================================

        document.getElementById(
            "local-status"
        ).textContent =
            data.local_analysis.level.toUpperCase()
            + " — Score "
            + data.local_analysis.score
            + "/100";


        // ==========================================
        // VIRUSTOTAL
        // ==========================================

        const vt = data.virustotal;


        if (!vt.enabled) {

            document.getElementById(
                "vt-status"
            ).textContent =
                "API не настроен";

        }

        else if (vt.error) {

            document.getElementById(
                "vt-status"
            ).textContent =
                vt.error;

        }

        else if (vt.stats) {

            document.getElementById(
                "vt-status"
            ).textContent =
                "Malicious: "
                + (vt.stats.malicious || 0)
                + " • Suspicious: "
                + (vt.stats.suspicious || 0);

        }

        else {

            document.getElementById(
                "vt-status"
            ).textContent =
                "Проверено";
        }


        // ==========================================
        // GOOGLE SAFE BROWSING
        // ==========================================

        const google =
            data.google_safe_browsing;


        if (!google.enabled) {

            document.getElementById(
                "google-status"
            ).textContent =
                "API не настроен";

        }

        else if (google.error) {

            document.getElementById(
                "google-status"
            ).textContent =
                google.error;

        }

        else if (google.found) {

            document.getElementById(
                "google-status"
            ).textContent =
                "⚠️ Обнаружена угроза";

        }

        else {

            document.getElementById(
                "google-status"
            ).textContent =
                "✓ Угроз не обнаружено";
        }


        // ==========================================
        // ПРИЧИНЫ
        // ==========================================

        const reasons =
            document.getElementById("reasons");


        // Очищаем старые причины

        reasons.innerHTML = "";


        // Если причин нет

        if (data.reasons.length === 0) {

            const li =
                document.createElement("li");

            li.textContent =
                "✓ Подозрительных признаков не обнаружено";

            reasons.appendChild(li);

        }

        // Если причины есть

        else {

            data.reasons.forEach(
                function(reason) {

                    const li =
                        document.createElement("li");

                    li.textContent =
                        "⚠️ " + reason;

                    reasons.appendChild(li);

                }
            );
        }


    }

    // ==========================================
    // ЕСЛИ ПРОИЗОШЛА ОШИБКА
    // ==========================================

    catch (error) {

        loading.classList.add("hidden");

        result.classList.remove("hidden");


        document.getElementById(
            "status"
        ).textContent =
            "❌ ERROR";


        document.getElementById(
            "status"
        ).style.color =
            "#ef4444";


        document.getElementById(
            "checked-url"
        ).textContent =
            "Не удалось соединиться с сервером";


        console.error(error);
    }
}