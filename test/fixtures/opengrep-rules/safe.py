import subprocess
import requests
from flask import redirect, request
from sqlite3 import connect


def run_report():
    subprocess.run(["/usr/bin/report", "--format", "json"], check=True)
    search = request.args.get("search")
    connect("reports.db").cursor().execute("SELECT * FROM reports WHERE name = ?", (search,))
    if request.args.get("destination") == "status":
        requests.get("https://status.example.invalid/health", timeout=2)
    if request.args.get("path") == "daily":
        open("/srv/reports/daily.json", encoding="utf-8").read()
    if request.args.get("next") == "docs":
        return redirect("/docs")
    return redirect("/")
