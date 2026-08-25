#!/usr/bin/env python3
"""
Password Strength + Breach Checker — Web App

Run with:
    python app.py
Then open http://127.0.0.1:5000
"""

from flask import Flask, request, jsonify, render_template

from checker import (
    check_password_strength,
    check_breach,
    strength_label,
    crack_time_estimate,
)

app = Flask(__name__)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/check", methods=["POST"])
def api_check():
    data = request.get_json(silent=True) or {}
    password = data.get("password", "")

    if not password:
        return jsonify({"error": "No password provided"}), 400

    score, max_score, entropy, feedback = check_password_strength(password)
    breach_count, breach_error = check_breach(password)

    return jsonify({
        "score": score,
        "max_score": max_score,
        "label": strength_label(score, max_score),
        "entropy": round(entropy, 1),
        "crack_time": crack_time_estimate(entropy),
        "feedback": feedback,
        "breach_count": breach_count,
        "breach_error": breach_error,
    })


if __name__ == "__main__":
    app.run(debug=True)
