from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask import flash, get_flashed_messages
from datetime import datetime
import bcrypt
from models import db, User, BlockedIP, ChatID



app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///security_dashboard.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db.init_app(app)

app.secret_key = "mysecretkey"




@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        # جستجوی کاربر با SQLAlchemy
        user = User.query.filter_by(username=username).first()

        if user:
            # بررسی رمز عبور
            if bcrypt.checkpw(password.encode('utf-8'), user.password):
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

        # بررسی تکراری نبودن نام کاربری
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('نام کاربری قبلاً ثبت شده است.', 'error')
            return redirect(url_for('register'))

        # ساختن شیء User و ذخیره در دیتابیس
        new_user = User(
            fullname=fullname,
            personnel_number=personnel_number,
            username=username,
            password=hashed_password,
            extension=extension,
            unit=unit,
            created_at=created_at
        )

        db.session.add(new_user)
        db.session.commit()

        flash('ثبت‌ نام با موفقیت انجام شد.', 'success')
        return redirect(url_for('login'))

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

        blocked = BlockedIP(
            ip_address=ip_address,
            reason=reason,
            datetime=datetime_val,
            duration=duration,
            notes=notes
        )

        db.session.add(blocked)
        db.session.commit()

        flash("✅ IP address saved successfully.")
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

@app.route('/show-chat-ids')
def show_chat_ids():
    with app.app_context():
        chat_list = ChatID.query.all()
        if not chat_list:
            return "<h3>No chat_ids found or table doesn't exist.</h3>"
        output = "<h3>Chat IDs:</h3><ul>"
        for chat in chat_list:
            output += f"<li>{chat.name} - {chat.chat_id}</li>"
        output += "</ul>"
        return output

@app.route('/list-tables')
def list_tables():
    conn = sqlite3.connect('security_dashboard.db')
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
    tables = cursor.fetchall()
    conn.close()

    return "<br>".join([table[0] for table in tables])

@app.route('/add-chat-id')
def add_chat_id():
    new_chat = ChatID(name="مدیر", chat_id="123456789")
    db.session.add(new_chat)
    db.session.commit()
    return "<h3>✅ Chat ID inserted successfully!</h3><a href='/show-chat-ids'>نمایش</a>"


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
    with app.app_context():
        # Create the database tables if they don't exist
        db.create_all()
        print("Tables created!")
    app.run(debug=True)




