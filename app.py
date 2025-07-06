from flask import Flask, render_template, request, session, redirect
import psycopg2, smtplib, random, string, bcrypt
from email.mime.text import MIMEText

app = Flask(__name__)
app.secret_key = 'super-secret-key'

# PostgreSQL connection
DATABASE_URL = "postgresql://sanjay_iq52_user:iC8iXxvvi5D0tUFE25ejon5dOKgV3w60@dpg-d1bpn4re5dus73erefm0-a.singapore-postgres.render.com/sanjay_iq52"
conn = psycopg2.connect(DATABASE_URL, sslmode='require')
cur = conn.cursor()

# Table creation
cur.execute("""
    CREATE TABLE IF NOT EXISTS vineet1 (
        id SERIAL PRIMARY KEY,
        first_name TEXT NOT NULL,
        last_name TEXT NOT NULL,
        phone TEXT NOT NULL,
        dob DATE NOT NULL,
        email TEXT NOT NULL UNIQUE,
        password TEXT
    );
""")
conn.commit()

def send_otp(email, otp):
    sender_email = "skt13953@gmail.com"
    sender_password = "csqmsqhcrjczfxou"
    msg = MIMEText(f"Your OTP is: {otp}")
    msg["Subject"] = "Your OTP for Registration"
    msg["From"] = sender_email
    msg["To"] = email

    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(sender_email, sender_password)
            server.send_message(msg)
    except Exception as e:
        print("Email sending failed:", e)

@app.route('/')
def index():
    return render_template("form1.html")

@app.route('/submit', methods=["POST"])
def submit():
    session.clear()
    first = request.form.get("first_name", "").strip()
    last = request.form.get("last_name", "").strip()
    phone = request.form.get("phone", "").strip()
    dob = request.form.get("dob", "").strip()
    email = request.form.get("email", "").strip()

    import re
    valid_first = re.fullmatch(r"[A-Za-z ]+", first)
    valid_last = re.fullmatch(r"[A-Za-z ]+", last)
    valid_phone = phone.isdigit() and len(phone) == 10
    valid_email = re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email)
    valid_dob = bool(dob)

    if not (valid_first and valid_last and valid_phone and valid_email and valid_dob):
        return render_template("form1.html", message="\u274c Invalid data", color="error",
                               first_name=first, last_name=last, phone=phone, dob=dob, email=email)

    cur.execute("SELECT 1 FROM vineet1 WHERE email = %s", (email,))
    if cur.fetchone():
        return render_template("form1.html", message="\u26a0\ufe0f Email already registered.", color="error",
                               first_name=first, last_name=last, phone=phone, dob=dob, email=email)

    otp = ''.join(random.choices(string.digits, k=6))
    session['user'] = {'first': first, 'last': last, 'phone': phone, 'dob': dob, 'email': email, 'otp': otp}
    send_otp(email, otp)

    return render_template("form1.html", otp_sent=True,
                           first_name=first, last_name=last, phone=phone, dob=dob, email=email)

@app.route('/verify', methods=["POST"])
def verify():
    entered_otp = request.form.get("otp", "")
    user = session.get("user", {})
    if entered_otp == user.get("otp"):
        return render_template("form1.html", otp_verified=True,
                               first_name=user.get('first'), last_name=user.get('last'),
                               phone=user.get('phone'), dob=user.get('dob'), email=user.get('email'))
    return render_template("form1.html", otp_sent=True, message="Incorrect OTP", color="error",
                           first_name=user.get('first'), last_name=user.get('last'),
                           phone=user.get('phone'), dob=user.get('dob'), email=user.get('email'))

@app.route('/register', methods=["POST"])
def register():
    password = request.form.get("password", "")
    confirm = request.form.get("confirm_password", "")
    import re

    if password != confirm or not re.fullmatch(r'(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@#$%^&+=!]).{8,}', password):
        user = session.get("user", {})
        return render_template("form1.html", otp_verified=True, message="\u274c Password rules not met", color="error",
                               first_name=user.get('first'), last_name=user.get('last'),
                               phone=user.get('phone'), dob=user.get('dob'), email=user.get('email'))

    user = session.get("user", {})
    email = user.get("email", "")
    cur.execute("SELECT 1 FROM vineet1 WHERE email = %s", (email,))
    if cur.fetchone():
        return render_template("form1.html", message="\u26a0\ufe0f Email already registered.", color="error",
                               first_name=user.get('first'), last_name=user.get('last'),
                               phone=user.get('phone'), dob=user.get('dob'), email=user.get('email'))

    hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    try:
        cur.execute("""
            INSERT INTO vineet1 (first_name, last_name, phone, dob, email, password)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (user['first'], user['last'], user['phone'], user['dob'], email, hashed))
        conn.commit()
        session.clear()
        return render_template("form1.html", message="\u2705 Registration successful!", color="success")
    except Exception as e:
        conn.rollback()
        return render_template("form1.html", message=str(e), color="error",
                               first_name=user.get('first'), last_name=user.get('last'),
                               phone=user.get('phone'), dob=user.get('dob'), email=user.get('email'))

@app.route('/login', methods=["POST"])
def login():
    email = request.form.get("email", "").strip()
    password = request.form.get("password", "").strip()

    cur.execute("SELECT first_name, last_name, phone, dob, password FROM vineet1 WHERE email = %s", (email,))
    user = cur.fetchone()

    if user and bcrypt.checkpw(password.encode('utf-8'), user[4].encode('utf-8')):
        session['logged_user'] = {
            'first_name': user[0],
            'last_name': user[1],
            'phone': user[2],
            'dob': user[3],
            'email': email
        }
        return redirect("/dashboard")
    else:
        return render_template("form1.html", login_error="Invalid email or password.")

@app.route('/dashboard')
def dashboard():
    user = session.get("logged_user")
    if not user:
        return redirect("/")
    return render_template("dashboard.html", user=user)
@app.route('/forgot')
def forgot():
    return render_template("forgot.html")
@app.route('/forgot', methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form.get("email", "").strip()
        cur.execute("SELECT 1 FROM vineet1 WHERE email = %s", (email,))
        if not cur.fetchone():
            return render_template("forgot.html", message="❌ Email not found", color="error")

        otp = ''.join(random.choices(string.digits, k=6))
        session['reset'] = {'email': email, 'otp': otp}
        send_otp(email, otp)
        return render_template("forgot.html", otp_sent=True, message="OTP sent", color="success")
    
    return render_template("forgot.html")
@app.route('/reset', methods=["POST"])
def reset_password():
    entered_otp = request.form.get("otp", "")
    new_pass = request.form.get("new_password", "")
    confirm_pass = request.form.get("confirm_password", "")
    user = session.get("reset", {})

    if entered_otp != user.get("otp"):
        return render_template("forgot.html", otp_sent=True, message="❌ Incorrect OTP", color="error")

    import re
    if new_pass != confirm_pass or not re.fullmatch(r'(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@#$%^&+=!]).{8,}', new_pass):
        return render_template("forgot.html", otp_sent=True, message="❌ Password rules not met", color="error")

    hashed = bcrypt.hashpw(new_pass.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    try:
        cur.execute("UPDATE vineet1 SET password = %s WHERE email = %s", (hashed, user['email']))
        conn.commit()
        session.clear()
        return render_template("form.html", message="✅ Password reset successful. Please login.", color="success")
    except Exception as e:
        conn.rollback()
        return render_template("forgot.html", otp_sent=True, message=str(e), color="error")


@app.route('/logout')
def logout():
    session.pop("logged_user", None)
    return redirect("/")

if __name__ == '__main__':
    app.run(debug=True)
