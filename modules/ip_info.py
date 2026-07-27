import socket
import requests

def get_ip_info(url):
    try:
        domain = url.replace("https://", "").replace("http://", "").split("/")[0]

        ip_address = socket.gethostbyname(domain)

        response = requests.get(f"http://ip-api.com/json/{ip_address}")
        data = response.json()

        return {
            "ip": ip_address,
            "country": data.get("country"),
            "city": data.get("city"),
            "isp": data.get("isp")
        }

    except Exception as e:
        print(e)
        return None