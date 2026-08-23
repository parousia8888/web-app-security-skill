import subprocess
import requests
from flask import request
from flask import redirect
from sqlite3 import connect


def run_report():
    command = request.args.get("command")
    subprocess.run(command, shell=True, check=True)
    search = request.args.get("search")
    connect("reports.db").cursor().execute(f"SELECT * FROM reports WHERE name = '{search}'")
    destination = request.args.get("destination")
    requests.get(destination, timeout=2)
    report_path = request.args.get("path")
    open(report_path, encoding="utf-8").read()
    next_page = request.args.get("next")
    return redirect(next_page)
