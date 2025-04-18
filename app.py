from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
from flask import flash, get_flashed_messages
from datetime import datetime
import bcrypt


app = Flask(__name__)
app.secret_key = "mysecretkey"

#login page 
from flask import Flask, render_template, request, redirect, flash, session, url_for
import sqlite3
import bcrypt

@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        # اتصال به دیتابیس و گرفتن اطلاعات کاربر
        conn = sqlite3.connect("security_dashboard.db")
        cursor = conn.cursor()
        cursor.execute("SELECT password FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        conn.close()

        if user:
            hashed_password = user[0]

            # بررسی صحت رمز عبور با استفاده از bcrypt
            if bcrypt.checkpw(password.encode('utf-8'), hashed_password):
                session["logged_in"] = True
                session["username"] = username
                return redirect(url_for("home"))
            else:
                flash("رمز عبور اشتباه است!", "error")
        else:
            flash("کاربری با این نام یافت نشد!", "error")

        return redirect(url_for("login"))

    return render_template("index.html")


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        fullname = request.form['fullname']
        personnel_number = request.form.get('personnel_number')
        username = request.form['username']
        password = request.form['password']
        extension = request.form.get('extension')
        unit = request.form.get('unit')
        created_at = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        # هش کردن رمز عبور
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        # ذخیره در دیتابیس
        conn = sqlite3.connect('security_dashboard.db')
        cursor = conn.cursor()

        try:
            cursor.execute('''
                INSERT INTO users (fullname, personnel_number, username, password, extension, unit, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (fullname, personnel_number, username, hashed_password, extension, unit, created_at))
            conn.commit()
            flash('ثبت‌ نام با موفقیت انجام شد.', 'success')
            return redirect('/')
        except sqlite3.IntegrityError:
            flash('نام کاربری قبلاً ثبت شده است.', 'error')
        finally:
            conn.close()

    return render_template('register.html')


#pages for home 
@app.route("/home")
def home():
    if not session.get("logged_in"):
        return redirect(url_for("login"))
    return render_template("home.html")


@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/submit', methods=['POST'])
def submit():
    name = request.form['name']
    email = request.form['email']
    return f'نام شما: {name} و ایمیل شما: {email} است.'

@app.route("/contact", methods=["GET", "POST"])
def contact():
    if request.method == "POST":
        name = request.form["name"]
        email = request.form["email"]
        message = request.form["message"]

        print(f"📨 فرم دریافت شد:\nنام: {name}\nایمیل: {email}\nپیام: {message}")

        return f"<h2>مرسی {name}، پیامت رسید!</h2><a href='/'>بازگشت به خانه</a>"

    # حالت GET برای نمایش فرم
    return render_template("contact.html")

@app.route("/block-ip", methods=["GET", "POST"])
def block_ip():
    if not session.get('logged_in'):
        return redirect('/')
    if request.method == 'POST':
        ip_address = request.form.get('ip_address')
        reason = request.form.get('reason')
        datetime_val = request.form.get('datetime')  # اسم متغیر تغییر داده شده چون datetime یک reserved word هست
        duration = request.form.get('duration')
        notes = request.form.get('notes')

        insert_blocked_ip(ip_address, reason, datetime_val, duration, notes)  # ذخیره در دیتابیس
        flash("IP address add to database successfully!")
        print("IP address blocked:", ip_address) #for debugging
        return redirect(url_for('block_ip'))

    return render_template("block_ip.html")


@app.route("/radar-report", methods=["GET", "POST"])
def radar_report():
    if not session.get('logged_in'):
        return redirect('/')
    return render_template("radar_report.html")


@app.route("/send-to-bale", methods=["GET", "POST"])
def send_to_bale():
    if not session.get('logged_in'):
        return redirect('/')
    return render_template("send_to_bale.html")


@app.route("/sending-shift", methods=["GET", "POST"])
def sending_shift():
    if not session.get('logged_in'):
        return redirect('/')
    return render_template("sending_shift.html")


def insert_blocked_ip(ip_address, reason, datetime, duration, notes):
    conn = sqlite3.connect('security_dashboard.db')  # اتصال به دیتابیس
    cursor = conn.cursor()  # ساختن cursor برای اجرای کوئری‌ها

    cursor.execute('''
        INSERT INTO blocked_ips (ip_address, reason, datetime, duration, notes)
        VALUES (?, ?, ?, ?, ?)
    ''', (ip_address, reason, datetime, duration, notes))  # اجرای کوئری و درج داده‌ها

    conn.commit()  # ذخیره تغییرات
    conn.close()   # بستن اتصال


if __name__ == '__main__':
    app.run(debug=True)
