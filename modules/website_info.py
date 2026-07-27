import whois

def get_website_info(url):
    try:
        domain = url.replace("https://", "").replace("http://", "").split("/")[0]

        info = whois.whois(domain)

        return {
            "registrar": info.registrar,
            "creation_date": info.creation_date,
            "expiration_date": info.expiration_date,
            "name_servers": info.name_servers
        }

    except Exception as e:
        print(e)
        return None