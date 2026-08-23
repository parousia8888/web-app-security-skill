import os as operating_system
import pickle as serializer
import requests as http
import yaml as yaml_parser
from flask import Flask as WebApplication
from flask_wtf.csrf import CSRFProtect
from starlette.middleware.cors import CORSMiddleware as CorsMiddleware
from subprocess import run as run_process

app = WebApplication(__name__)
app.secret_key = "fixture-python-secret-never-deploy"
app.config["SESSION_COOKIE_SECURE"] = False
app.config["WTF_CSRF_ENABLED"] = False
csrf = CSRFProtect(app)
app.add_middleware(
    CorsMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
)


@csrf.exempt
def unsafe(payload, blob, url):
    eval(payload)
    run_process(
        payload,
        shell=True,
    )
    operating_system.system(payload)
    serializer.loads(blob)
    yaml_parser.load(payload, Loader=yaml_parser.UnsafeLoader)
    http.get(url, verify=False)
    app.run(debug=True)
