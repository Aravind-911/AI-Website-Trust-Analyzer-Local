from urllib.parse import urlparse

def check_https(url):
    parsed_url = urlparse(url)

    if parsed_url.scheme == "https":
        return True
    else:
        return False