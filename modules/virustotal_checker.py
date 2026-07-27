import requests

API_KEY = "73ac53542b558ec0458428aafa9a2608328352631d2998e818b196c6cd231e2c"

def check_virustotal(url):
    api_url = "https://www.virustotal.com/api/v3/urls"

    headers = {
        "x-apikey": API_KEY
    }

    response = requests.post(
        api_url,
        headers=headers,
        data={"url": url}
    )

    if response.status_code == 200:
        return response.json()
    else:
        return {
            "error": response.text
        }