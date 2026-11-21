"""Download DB-IP's free IP-to-Country Lite database (CC BY 4.0): this month's file, else last month's."""
import datetime as dt
import sys
import urllib.request

today = dt.date.today()
for month in (today, today.replace(day=1) - dt.timedelta(days=1)):
    url = f"https://download.db-ip.com/free/dbip-country-lite-{month:%Y-%m}.csv.gz"
    try:
        # DB-IP answers 403 to Python's default User-Agent
        req = urllib.request.Request(url, headers={"User-Agent": "honeypot-geo-fetch"})
        with urllib.request.urlopen(req, timeout=60) as r, open(sys.argv[1], "wb") as f:
            f.write(r.read())
        print("country database:", url)
        break
    except OSError as e:
        print("not available:", url, e)
else:
    sys.exit("could not download the DB-IP country database")
