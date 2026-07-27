import requests

def check_blacklist(url):
    try:
        response = requests.get(
            f"https://openphish.com/feed.txt",
            timeout=10
        )

        phishing_urls = response.text.splitlines()

        if url in phishing_urls:
            return True
        else:
            return False

    except Exception as e:
        print(e)
        return None