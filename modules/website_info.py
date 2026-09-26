import whois
from datetime import datetime


def format_date(date_value):
    """
    Convert WHOIS date values into a clean readable date.
    WHOIS sometimes returns a single datetime and sometimes a list.
    """

    if date_value is None:
        return "Unknown"

    # Some WHOIS servers return multiple dates
    if isinstance(date_value, list):
        if len(date_value) == 0:
            return "Unknown"

        date_value = date_value[0]

    # Format datetime
    if isinstance(date_value, datetime):
        return date_value.strftime("%d %B %Y")

    return str(date_value)


def format_name_servers(name_servers):
    """
    Clean and format WHOIS name servers.
    """

    if not name_servers:
        return "Unknown"

    # Convert single value into list
    if not isinstance(name_servers, (list, tuple, set)):
        name_servers = [name_servers]

    # Remove duplicates and clean values
    cleaned_servers = sorted(
        set(
            str(server).lower().strip()
            for server in name_servers
            if server
        )
    )

    if not cleaned_servers:
        return "Unknown"

    # Display each server on a separate line
    return "\n".join(
        f"• {server}"
        for server in cleaned_servers
    )


def get_website_info(url):
    try:

        # Extract domain from URL
        domain = (
            url.replace("https://", "")
            .replace("http://", "")
            .split("/")[0]
            .split(":")[0]
        )

        # WHOIS lookup
        info = whois.whois(domain)

        registrar = info.registrar

        if isinstance(registrar, list):
            registrar = registrar[0] if registrar else "Unknown"

        if not registrar:
            registrar = "Unknown"

        return {
            "registrar": registrar,

            "creation_date": format_date(
                info.creation_date
            ),

            "expiration_date": format_date(
                info.expiration_date
            ),

            "name_servers": format_name_servers(
                info.name_servers
            )
        }

    except Exception as e:
        print(f"WHOIS Error: {e}")
        return None