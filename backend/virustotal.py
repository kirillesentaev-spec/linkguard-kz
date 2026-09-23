import os
import base64
import requests
from dotenv import load_dotenv


load_dotenv()

API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

BASE_URL = "https://www.virustotal.com/api/v3"


def encode_url(url: str):
    encoded = base64.urlsafe_b64encode(
        url.encode()
    ).decode()

    return encoded.rstrip("=")


def get_url_report(url: str):

    if not API_KEY:
        return {
            "enabled": False,
            "found": False,
            "error": "VirusTotal API key не настроен"
        }

    headers = {
        "x-apikey": API_KEY
    }

    url_id = encode_url(url)

    endpoint = f"{BASE_URL}/urls/{url_id}"

    try:

        response = requests.get(
            endpoint,
            headers=headers,
            timeout=15
        )

        if response.status_code == 200:

            data = response.json()

            attributes = data["data"]["attributes"]

            stats = attributes.get(
                "last_analysis_stats",
                {}
            )

            return {
                "enabled": True,
                "found": True,
                "stats": stats
            }

        if response.status_code == 404:

            return {
                "enabled": True,
                "found": False,
                "error": "URL отсутствует в базе VirusTotal"
            }

        return {
            "enabled": True,
            "found": False,
            "error": f"HTTP {response.status_code}"
        }

    except requests.RequestException as error:

        return {
            "enabled": True,
            "found": False,
            "error": str(error)
        }