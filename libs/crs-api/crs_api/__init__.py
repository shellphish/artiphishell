import os

from flask import Flask, jsonify
from flask_httpauth import HTTPTokenAuth, HTTPBasicAuth, MultiAuth
from werkzeug.security import generate_password_hash, check_password_hash
from crs_telemetry.utils import init_otel

from opentelemetry.instrumentation.flask import FlaskInstrumentor

init_otel("crs-api", "ingest", "ingest_tasks")

app = Flask(__name__)
FlaskInstrumentor().instrument_app(app)

token_auth = HTTPTokenAuth(scheme="Bearer")
basic_auth = HTTPBasicAuth()
shellphish_basic_auth = MultiAuth(basic_auth, token_auth)

ARTIPHISHELL_API_USERNAME = os.environ.get("ARTIPHISHELL_API_USERNAME", "shellphish")
ARTIPHISHELL_API_PASSWORD = os.environ.get(
    "ARTIPHISHELL_API_PASSWORD", "!!!shellphish!!!"
)

users = {
    ARTIPHISHELL_API_USERNAME: generate_password_hash(ARTIPHISHELL_API_PASSWORD),
}

tokens = {
    ARTIPHISHELL_API_USERNAME: ARTIPHISHELL_API_PASSWORD,
}


@basic_auth.verify_password
def verify_password(username, password):
    if username in users and check_password_hash(users.get(username), password):
        return username
    return None


@token_auth.verify_token
def verify_token(token):
    if token in tokens:
        return tokens[token]
    return None


@basic_auth.error_handler
def unauthorized():
    return jsonify({"message": "Unauthorized access"}), 401


@token_auth.error_handler
def unauthorized2():
    return jsonify({"message": "Unauthorized access"}), 401


@app.route("/api/v1/health/")
def health():
    return jsonify({"message": "OK"}), 200
