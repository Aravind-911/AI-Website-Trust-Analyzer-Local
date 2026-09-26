import requests
import time

API_KEY = "73ac53542b558ec0458428aafa9a2608328352631d2998e818b196c6cd231e2c"
def check_virustotal(url):
    headers = {
        "x-apikey": API_KEY
    }

    # Submit URL for analysis
    response = requests.post(
        "https://www.virustotal.com/api/v3/urls",
        headers=headers,
        data={"url": url}
    )

    if response.status_code != 200:
        return {"error": response.text}

    analysis_id = response.json()["data"]["id"]

    # Wait for VirusTotal to finish scanning
    time.sleep(3)

    # Get analysis result
    result = requests.get(
        f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
        headers=headers
    )

    if result.status_code != 200:
        return {"error": result.text}

    stats = result.json()["data"]["attributes"]["stats"]

    return stats