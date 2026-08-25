"""
geolocation.py
--------------
Week 3: takes the originating IP guessed by header_parser.py and looks up
its approximate country / city / ISP using a free geolocation API.

Uses ip-api.com's free tier (no key needed, ~45 requests/min limit —
plenty for a hackathon demo). Swap in ipapi.co or ipinfo.io similarly
if you hit rate limits during testing.

Requires:
    pip install requests
"""

import requests


def lookup_ip(ip: str) -> dict:
    """Returns geolocation info for a public IP, or an error dict for
    private/invalid IPs (which can't be geolocated)."""
    if not ip:
        return {"error": "No IP provided"}

    try:
        resp = requests.get(
            f"http://ip-api.com/json/{ip}",
            params={"fields": "status,message,country,regionName,city,isp,org,lat,lon,query"},
            timeout=5,
        )
        data = resp.json()
    except requests.RequestException as e:
        return {"error": f"Geolocation lookup failed: {e}"}

    if data.get("status") != "success":
        return {"error": data.get("message", "Unknown geolocation error")}

    return {
        "ip": data.get("query"),
        "country": data.get("country"),
        "region": data.get("regionName"),
        "city": data.get("city"),
        "isp": data.get("isp"),
        "org": data.get("org"),
        "lat": data.get("lat"),
        "lon": data.get("lon"),
    }


if __name__ == "__main__":
    # Quick manual test with Google's public DNS IP as a placeholder
    print(lookup_ip("8.8.8.8"))
