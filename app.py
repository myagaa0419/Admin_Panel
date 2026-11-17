import logging
import os
import secrets
from functools import lru_cache
from pathlib import Path

import bcrypt
import httpx
from dotenv import load_dotenv
from flask import Flask, flash, redirect, render_template, request, session, url_for
from postgrest.exceptions import APIError
from supabase import Client, create_client

load_dotenv(Path(__file__).with_name(".env"))

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY") or secrets.token_hex(32)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
)
logging.basicConfig(level=logging.INFO)


@lru_cache(maxsize=1)
def get_supabase() -> Client:
    url = os.getenv("SUPABASE_URL")
    key = os.getenv("SUPABASE_SECRET_KEY")
    if not url or not key:
        raise RuntimeError("SUPABASE_URL болон SUPABASE_SECRET_KEY тохируулаагүй байна.")
    return create_client(url, key)


def load_drafts() -> list[dict]:
    response = (
        get_supabase()
        .table("content_drafts")
        .select("id, title, content, status, created_at")
        .order("created_at", desc=True)
        .execute()
    )
    return response.data


@app.route("/", methods=["GET", "POST"])
def login():
    if session.get("user_email"):
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        if not email or not password:
            flash("И-мэйл болон нууц үгээ оруулна уу.", "error")
            return render_template("login.html")

        try:
            result = (
                get_supabase()
                .table("users")
                .select("email, password_hash")
                .eq("email", email)
                .limit(1)
                .execute()
            )
        except (APIError, httpx.HTTPError, RuntimeError, ValueError):
            app.logger.exception("Could not retrieve the user from Supabase")
            flash("Өгөгдлийн сантай холбогдоход алдаа гарлаа.", "error")
            return render_template("login.html")

        user = result.data[0] if result.data else None
        if user is None:
            flash("И-мэйл эсвэл нууц үг буруу байна.", "error")
            return render_template("login.html")

        try:
            password_matches = bcrypt.checkpw(
                password.encode("utf-8"),
                user["password_hash"].encode("utf-8"),
            )
        except (KeyError, ValueError, TypeError):
            app.logger.exception("The stored password hash could not be verified")
            flash("Хэрэглэгчийн нууц үгийн мэдээллийг шалгаж чадсангүй.", "error")
            return render_template("login.html")

        if not password_matches:
            flash("И-мэйл эсвэл нууц үг буруу байна.", "error")
            return render_template("login.html")

        session.clear()
        session["user_email"] = user["email"]
        return redirect(url_for("dashboard"))

    return render_template("login.html")


@app.get("/dashboard")
def dashboard():
    user_email = session.get("user_email")
    if not user_email:
        return redirect(url_for("login"))

    try:
        drafts = load_drafts()
        error = None
    except (APIError, httpx.HTTPError, RuntimeError, ValueError):
        app.logger.exception("Could not retrieve content drafts from Supabase")
        drafts = []
        error = "Нооргуудыг ачаалж чадсангүй. Холболтын тохиргоогоо шалгана уу."

    return render_template(
        "dashboard.html",
        drafts=drafts,
        error=error,
        user_email=user_email,
    )


@app.post("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
