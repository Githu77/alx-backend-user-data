#!/usr/bin/env python3
"""
Route module for API
"""
from os import getenv
from api.v1.views import app_views
from api.v1.auth.auth import Auth
from api.v1.auth.session_auth import SessionAuth
from api.v1.auth.basic_auth import BasicAuth
from flask import Flask, jsonify, abort, request
from flask_cors import (CORS, cross_origin)
import os


app = Flask(__name__)
app.register_blueprint(app_views)
CORS(app, resources={r"/api/v1/*": {"origins": "*"}})
auth = None

if getenv("AUTH_TYPE") == "auth":
    auth = Auth()
elif getenv("AUTH_TYPE") == "basic_auth":
    auth = BasicAuth()
elif getenv("AUTH_TYPE") == "session_auth":
    auth = SessionAuth()


@app.errorhandler(404)
def not_found(error) -> str:
    """ if not found
    """
    return jsonify({"error": "Not found"}), 404


@app.errorhandler(401)
def unauthorized(error) -> str:
    """
    For unauthorized handler.
    """
    return jsonify({"error": "Unauthorized"}), 401


@app.errorhandler(403)
def unauthorized(error) -> str:
    """
    if forbidden handler.
    """
    return jsonify({"error": "Forbidden"}), 403


@app.before_request
def before_request():
    """
    the handler before_request
    """
    authorized_list = ['/api/v1/status/',
                       '/api/v1/unauthorized/', '/api/v1/forbidden/',
                       '/api/v1/auth_session/login/']

    if auth and auth.require_auth(request.path, authorized_list):
        if not auth.authorization_header(request):
            abort(401)
        if (auth.authorization_header(request) and
            not auth.session_cookie(request)):
            abort(401)
        request.current_user = auth.current_user(request)
        if not auth.current_user(request):
            abort(403)


if __name__ == "__main__":
    host = getenv("API_HOST", "0.0.0.0")
    port = getenv("API_PORT", "5000")
    app.run(host=host, port=port)
