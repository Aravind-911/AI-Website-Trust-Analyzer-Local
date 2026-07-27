import whois
from datetime import datetime

def get_domain_age(url):
    try:
        domain = url.replace("https://", "").replace("http://", "").split("/")[0]

        info = whois.whois(domain)

        creation_date = info.creation_date

        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        creation_date = creation_date.replace(tzinfo=None)
        
        age = (datetime.now() - creation_date).days // 365

        return age

    except Exception as e:
        print(e)
        return None