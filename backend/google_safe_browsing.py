import os
import requests
from dotenv import load_dotenv


load_dotenv()

API_KEY = os.getenv("GOOGLE_SAFE_BROWSING_KEY")

URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"


def check_google(url: str):

    if not API_KEY:
        return {
            "enabled": False,
            "found": False,
            "error": "Google Safe Browsing API key не настроен"
        }

    params = {
        "key": API_KEY
    }

    payload = {
        "client": {
            "clientId": "linkguard-kz",
            "clientVersion": "1.0"
        },

        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION"
            ],

            "platformTypes": [
                "ANY_PLATFORM"
            ],

            "threatEntryTypes": [
                "URL"
            ],

            "threatEntries": [
                {
                    "url": url
                }
            ]
        }
    }

    try:

        response = requests.post(
            URL,
            params=params,
            json=payload,
            timeout=10
        )

        response.raise_for_status()

        data = response.json()

        matches = data.get(
            "matches",
            []
        )

        if matches:

            return {
                "enabled": True,
                "found": True,
                "matches": matches
            }

        return {
            "enabled": True,
            "found": False,
            "matches": []
        }

    except requests.RequestException as error:

        return {
            "enabled": True,
            "found": False,
            "error": str(error)
        }