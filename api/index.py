from flask import Flask, render_template, request, redirect, url_for, session
import psycopg2  
import base64
import hashlib 
import secrets
from datetime import datetime
import os

DATABASE_URL = os.getenv("POSTGRES_URL")

app = Flask(__name__, template_folder="templates", static_folder="static")
app.secret_key = os.getenv("SECRET_KEY", "default-secret-key")

def get_data_db():
    return psycopg2.connect(DATABASE_URL)  


HASH_ALGORITHM = "pbkdf2_sha256"

def hash_password(password, salt=None, iterations=310000):
    if salt is None:
        salt = secrets.token_hex(16)
    pw_hash = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), iterations)
    b64_hash = base64.b64encode(pw_hash).decode("ascii").strip()
    return f"{HASH_ALGORITHM}${iterations}${salt}${b64_hash}"

def verify_password(password, password_hash):
    if (password_hash or "").count("$") != 3:
        return False
    algorithm, iterations, salt, _ = password_hash.split("$", 3)
    assert algorithm == HASH_ALGORITHM
    compare_hash = hash_password(password, salt, int(iterations))
    return secrets.compare_digest(password_hash, compare_hash)

@app.route("/logout")
def logout():
    session.pop("user_id", None)
    return redirect(url_for("index"))

@app.route("/login", methods=["GET"])
def login_form():
    return render_template("login.html")

@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username")
    password_input = request.form.get("password")

    if not username or not password_input:
        return render_template("login.html", error_login=True)

    try:
        with get_data_db() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT id, username, password FROM users WHERE username = %s", (username,))
                row = cur.fetchone()
                if row and verify_password(password_input, row[2]):
                    session["user_id"] = row[0]
                    return redirect(url_for("index"))
                else:
                    return render_template("login.html", error_login=True)
    except Exception as ex:
        print(f"ログインエラー: {ex}")
        return render_template("login.html", error_db=True)

@app.route("/register", methods=["GET"])
def register_form():
    return render_template("register.html")

@app.route("/register", methods=["POST"])
def register():
    username = request.form.get("username")
    password_input = request.form.get("password")
    password_confirmation = request.form.get("password_confirmation")

    if not username or len(username) < 3:
        return render_template("register.html", error_user=True, form=request.form)
    if not password_input or password_input != password_confirmation:
        return render_template("register.html", error_password=True, form=request.form)

    try:
        with get_data_db() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT 1 FROM users WHERE username = %s", (username,))
                if cur.fetchone():
                    return render_template("register.html", error_unique=True, form=request.form)

                password_hash = hash_password(password_input)
                cur.execute("INSERT INTO users (username, password) VALUES (%s, %s)", (username, password_hash))
                conn.commit()
    except Exception as ex:
        print(f"登録エラー: {ex}")
        return render_template("register.html", error_db=True)

    return redirect(url_for("login_form"))

@app.route('/')
def index():
    if "user_id" not in session:
        return redirect("/login")

    user_id = session["user_id"]
    events = []

    try:
        with get_data_db() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT id, when_self_cut, why_self_cut, when_od, what_dose, many_dose, why_od
                    FROM data WHERE user_id = %s
                """, (user_id,))
                rows = cur.fetchall()
                for row in rows:
                    id, when_self_cut, why_self_cut, when_od, what_dose, many_dose, why_od = row

                    if when_self_cut:
                        events.append({
                            "title": "自傷",
                            "start": when_self_cut.isoformat(),
                            "color": "red",
                            "description": f"理由: {why_self_cut or ''}<br>時刻: {when_self_cut.strftime('%H:%M')}"
                        })
                    if when_od:
                        events.append({
                            "title": "OD",
                            "start": when_od.isoformat(),
                            "color": "blue",
                            "description": (
                                f"薬: {what_dose or ''}<br>"
                                f"錠数: {many_dose or ''}<br>"
                                f"理由: {why_od or ''}<br>"
                                f"時刻: {when_od.strftime('%H:%M')}"
                            )
                        })
    except Exception as ex:
        print(f"データ取得エラー: {ex}")

    return render_template("index.html", events=events)

@app.route("/settings", methods=["GET"])
def settings():
    if "user_id" not in session:
        return redirect("/login")
    return render_template("settings.html")

@app.route("/create", methods=["POST"])
def create():
    app.logger.info("createルートに入りました")
    if "user_id" not in session:
        app.logger.info("未ログインのためリダイレクト")
        return redirect("/login")

    user_id = session["user_id"]
    app.logger.info(f"user_id: {user_id}")

    when_self_cut = request.form.get("when_self_cut") or None
    why_self_cut = request.form.get("why_self_cut") or None
    when_od = request.form.get("when_od") or None
    what_dose = request.form.get("what_dose") or None
    many_dose = request.form.get("many_dose") or None
    why_od = request.form.get("why_od") or None


    try:
        with get_data_db() as conn:
            with conn.cursor() as cur:
                app.logger.info("DB接続成功、INSERT実行前")
                cur.execute("""
                    INSERT INTO data (user_id, when_self_cut, why_self_cut, when_od, what_dose, many_dose, why_od)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                """, (user_id, when_self_cut, why_self_cut, when_od, what_dose, many_dose, why_od))
                conn.commit()
                app.logger.info("INSERT成功")
    except Exception as ex:
        app.logger.error(f"データ挿入エラー: {ex}")

    return redirect(url_for("index"))


@app.route("/list", methods=["GET"])
def list_records():
    if "user_id" not in session:
        return redirect("/login")

    user_id = session["user_id"]
    records = []

    try:
        with get_data_db() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT id, when_self_cut, why_self_cut, when_od, why_od, what_dose, many_dose
                    FROM data
                    WHERE user_id = %s
                    ORDER BY id DESC
                """, (user_id,))
                rows = cur.fetchall()

                for row in rows:
                    record_id, when_self_cut, why_self_cut, when_od, why_od, what_dose, many_dose = row

                    if when_self_cut:
                        records.append({
                            "id": record_id,
                            "type": "自傷",
                            "when": when_self_cut,
                            "why": why_self_cut,
                            "what_dose": "",
                            "many_dose": ""
                        })

                    if when_od:
                        records.append({
                            "id": record_id,
                            "type": "OD",
                            "when": when_od,
                            "why": why_od,
                            "what_dose": what_dose or "",
                            "many_dose": many_dose or ""
                        })

    except Exception as ex:
        print(f"一覧取得エラー: {ex}")

    return render_template("list.html", records=records)





@app.route("/delete/<int:record_id>", methods=["POST"])
def delete_record(record_id):
    if "user_id" not in session:
        return redirect("/login")

    user_id = session["user_id"]
    try:
        with get_data_db() as conn:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM data WHERE id = %s AND user_id = %s", (record_id, user_id))
                conn.commit()
    except Exception as ex:
        print(f"削除エラー: {ex}")

    return redirect(url_for("index"))

@app.route("/update/<int:record_id>", methods=["POST"])
def update_record(record_id):
    if "user_id" not in session:
        return redirect("/login")

    user_id = session["user_id"]


    when_str = request.form.get("when")
    when = None
    if when_str:
        try:
            when = datetime.strptime(when_str, "%Y-%m-%dT%H:%M")
        except ValueError:
            print("日時の形式が正しくありません")

    why_self_cut = request.form.get("why_self_cut")
    why_od = request.form.get("why_od")
    what_dose = request.form.get("what_dose")
    many_dose = request.form.get("many_dose")

    try:
        with get_data_db() as conn:
            with conn.cursor() as cur:
                if why_self_cut is not None:
                    cur.execute("""
                        UPDATE data
                        SET why_self_cut = %s, when_self_cut = %s
                        WHERE id = %s AND user_id = %s
                    """, (why_self_cut, when, record_id, user_id))

                elif why_od is not None:
                    cur.execute("""
                        UPDATE data
                        SET why_od = %s, what_dose = %s, many_dose = %s, when_od = %s
                        WHERE id = %s AND user_id = %s
                    """, (why_od, what_dose, many_dose, when, record_id, user_id))

                conn.commit()
    except Exception as ex:
        print(f"更新エラー: {ex}")

    return redirect(url_for("index"))

# v0.2

