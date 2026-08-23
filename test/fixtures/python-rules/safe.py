import ast
import json
import os
import requests
import yaml
from flask import Flask
from flask_wtf.csrf import CSRFProtect
from starlette.middleware.cors import CORSMiddleware
from subprocess import run

app = Flask(__name__)
app.secret_key = os.environ["FLASK_SECRET_KEY"]
app.config["SESSION_COOKIE_SECURE"] = True
app.config["WTF_CSRF_ENABLED"] = True
csrf = CSRFProtect(app)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://app.example"],
    allow_credentials=True,
)


def safer(payload, blob, url):
    """eval(payload); requests.get(url, verify=False)"""
    # run(payload, shell=True)
    ast.literal_eval(payload)
    run(["/usr/bin/tool", payload], shell=False, check=True)
    json.loads(blob)
    yaml.safe_load(payload)
    requests.get(url, verify="/etc/ssl/certs/internal-ca.pem")
    app.run(debug=False)
