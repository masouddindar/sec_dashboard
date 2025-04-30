from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask import flash, get_flashed_messages
from datetime import datetime, timedelta
import bcrypt
from models import db, User, BlockedIP, ChatID
import os
from models import SplunkAlert
import requests
from sqlalchemy import func
from flask import make_response
import requests
from models import IODEFDocument
import xml.etree.ElementTree as ET
from routes.iodef import iodef_bp
from routes.auth import auth_bp
from routes.incident_routes import incident_bp



app = Flask(__name__)
app.register_blueprint(iodef_bp)
app.register_blueprint(auth_bp)
app.register_blueprint(incident_bp)

basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'security_dashboard.db') 

#app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///security_dashboard.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db.init_app(app)

app.secret_key = "mysecretkey"



@app.route('/iodef/view/<int:incident_id>')
def view_iodef_document(incident_id):
    incident = IODEFDocument.query.get_or_404(incident_id)
    return render_template('show_incident.html', incident=incident)
    

# @app.route("/iodef-documents/edit/<int:doc_id>", methods=["GET", "POST"])
# def edit_iodef_document(doc_id):
#     doc = IODEFDocument.query.get_or_404(doc_id)

#     if request.method == "POST":
#         edited_xml = request.form["xml"]

#         #اضافه کردن اعتبارسنجی ساختار XML
#         try:
#             ET.fromstring(edited_xml)  # تلاش برای پارس کردن XML
#         except ET.ParseError as e:
#             flash(f"❌ ساختار XML اشتباه است: {str(e)}", "error")
#             return redirect(url_for("edit_iodef_document", doc_id=doc.id))

#         # اگر XML معتبر بود:
#         doc.raw_xml = edited_xml
#         db.session.commit()
#         flash("✅ XML با موفقیت ذخیره شد.", "success")
#         return redirect(url_for("view_iodef_document", incident_id=doc.id))

#     return render_template("edit_iodef.html", doc=doc)

@app.route("/iodef-documents/download/<int:doc_id>")
def download_iodef_document(doc_id):
    
    doc = IODEFDocument.query.get_or_404(doc_id)

    response = make_response(doc.raw_xml)
    response.headers["Content-Type"] = "application/xml"
    response.headers["Content-Disposition"] = f"attachment; filename={doc.incidentid}.xml"
    return response

# @app.route("/incident/resend/<int:doc_id>", methods=["POST"])
# def resend_iodef_document(doc_id):
    
#     incident = IODEFDocument.query.get_or_404(doc_id)

#     try:
#         response = requests.post("httpbin.org/post", data=incident.raw_xml,
#                                  headers={'Content-Type': 'application/xml'})
#         flash(f"📤 ارسال مجدد با موفقیت انجام شد. (Status: {response.status_code})", "success")
#     except Exception as e:
#         flash(f"خطا در ارسال مجدد: {str(e)}", "error")

#     return redirect(url_for("incident_detail", doc_id=doc_id))


# #detail  of page
# @app.route("/incident/<int:doc_id>")
# def incident_detail(doc_id):
#     incident = IODEFDocument.query.get_or_404(doc_id)
#     return render_template("incident_detail.html", incident=incident)



#latest incidents
@app.route("/latest-incidents")
def latest_incidents():
    incidents = IODEFDocument.query.order_by(IODEFDocument.created_at.desc()).limit(20).all()
    return render_template("latest_incidents.html", incidents=incidents)

@app.route("/iodef-documents/<int:doc_id>")
def show_iodef_documents(doc_id):
    
    doc = IODEFDocument.query.get_or_404(doc_id)
    return f"<h3>Incident ID: {doc.incidentid}</h3><pre style='background:#eee; padding:15px; direction:ltr'>{doc.raw_xml}</pre>"


#dashboard for radar
@app.route("/dashboard", methods=["GET", "POST"])
def dashboard():
    # مقادیر پیش‌فرض (هفت روز اخیر)
    end_date = datetime.utcnow().date()
    start_date = end_date - timedelta(days=7)

    if request.method == 'POST':
        start_str = request.form.get("start_date")
        end_str = request.form.get("end_date")
        if start_str and end_str:
            start_date = datetime.strptime(start_str, '%Y-%m-%d').date()
            end_date = datetime.strptime(end_str, '%Y-%m-%d').date()

    # فیلتر بازه زمانی
    alerts_in_range = SplunkAlert.query.filter(
        func.date(SplunkAlert.detecttime) >= start_date,
        func.date(SplunkAlert.detecttime) <= end_date
    )

    alerts_by_type = alerts_in_range.with_entities(
        SplunkAlert.iodeftype, func.count(SplunkAlert.id)
    ).group_by(SplunkAlert.iodeftype).all()

    top_src_ips = alerts_in_range.with_entities(
        SplunkAlert.src, func.count(SplunkAlert.id)
    ).group_by(SplunkAlert.src).order_by(func.count(SplunkAlert.id).desc()).limit(5).all()

    return render_template(
        "dashboard.html",
        alerts_by_type=alerts_by_type,
        top_src_ips=top_src_ips,
        start_date=start_date,
        end_date=end_date
    )




#show alerts
@app.route("/alerts")
def view_alerts():
    alerts = SplunkAlert.query.order_by(SplunkAlert.received_at.desc()).all()
    return render_template("alerts.html", alerts=alerts)





# @app.route("/", methods=["GET", "POST"])
# def login():
#     if request.method == "POST":
#         username = request.form["username"]
#         password = request.form["password"]

#         # جستجوی کاربر با SQLAlchemy
#         user = User.query.filter_by(username=username).first()

#         if user:
#             # بررسی رمز عبور
#             if bcrypt.checkpw(password.encode('utf-8'), user.password):
#                 session["logged_in"] = True
#                 session["username"] = username
#                 return redirect(url_for("home"))
#             else:
#                 flash("رمز عبور اشتباه است!", "error")
#         else:
#             flash("کاربری با این نام یافت نشد!", "error")

#         return redirect(url_for("login"))

#     return render_template("index.html")


# @app.route('/register', methods=['GET', 'POST'])
# def register():
#     if request.method == 'POST':
#         fullname = request.form['fullname']
#         personnel_number = request.form.get('personnel_number')
#         username = request.form['username']
#         password = request.form['password']
#         extension = request.form.get('extension')
#         unit = request.form.get('unit')
#         #created_at = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

#         # هش کردن رمز عبور
#         hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

#         # بررسی تکراری نبودن نام کاربری
#         existing_user = User.query.filter_by(username=username).first()
#         if existing_user:
#             flash('نام کاربری قبلاً ثبت شده است.', 'error')
#             return redirect(url_for('register'))

#         # ساختن شیء User و ذخیره در دیتابیس
#         new_user = User(
#             fullname=fullname,
#             personnel_number=personnel_number,
#             username=username,
#             password=hashed_password,
#             extension=extension,
#             unit=unit,
#             #created_at=created_at
#         )

#         db.session.add(new_user)
#         db.session.commit()

#         flash('ثبت‌ نام با موفقیت انجام شد.', 'success')
#         return redirect(url_for('login'))

#     return render_template('register.html')



# نمایش لیست گزارش‌های IODEF
@app.route("/iodef-documents")
def view_iodef_documents():
    documents = IODEFDocument.query.order_by(IODEFDocument.created_at.desc()).all()
    return render_template("view_iodef_documents.html", documents=documents)


#pages for home 
@app.route("/home")
def home():
    if not session.get("logged_in"):
        redirect(url_for("auth_bp.login"))

    
    today = datetime.utcnow().date()
    total_alerts = SplunkAlert.query.count()
    alerts_today = SplunkAlert.query.filter(
        func.date(SplunkAlert.detecttime) == today
    ).count()

    # 🆕 گرفتن آخرین ۵ incident
    latest_incidents = IODEFDocument.query.order_by(IODEFDocument.created_at.desc()).limit(5).all()

    return render_template(
        "home.html",
        total_alerts=total_alerts,
        alerts_today=alerts_today,
        latest_incidents=latest_incidents  # 👈 پاس دادن به قالب
    )


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

#sending to bale
@app.route("/send-to-bale", methods=["GET", "POST"])
def send_to_bale():
    if not session.get('logged_in'):
        return redirect('/')

    if request.method == "POST":
        action = request.form.get("action")

        if action == "send_message":
            chat_id = request.form.get("chat_id")
            message = request.form.get("message")
            print(f"🔹 پیام برای {chat_id}: {message}")
            flash("پیام با موفقیت ارسال شد.")

        elif action == "add_chat_id":
            name = request.form.get("name")
            chat_id = request.form.get("new_chat_id")

            # بررسی تکراری نبودن
            existing = ChatID.query.filter_by(chat_id=chat_id).first()
            if existing:
                flash("این chat_id قبلاً ثبت شده است.", "error")
            else:
                new_entry = ChatID(name=name, chat_id=chat_id)
                db.session.add(new_entry)
                db.session.commit()
                flash("chat_id جدید ثبت شد.", "success")

        return redirect(url_for("send_to_bale"))

    # حالت GET
    chat_ids = ChatID.query.all()
    return render_template("send_to_bale.html", chat_ids=chat_ids)



@app.route("/sending-shift", methods=["GET", "POST"])
def sending_shift():
    if not session.get('logged_in'):
        return redirect('/')
    return render_template("sending_shift.html")


#show saved chat ids
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



@app.route('/add-chat-id')
def add_chat_id():
    new_chat = ChatID(name="مدیر", chat_id="123456789")
    db.session.add(new_chat)
    db.session.commit()
    return "<h3>✅ Chat ID inserted successfully!</h3><a href='/show-chat-ids'>نمایش</a>"

#show users
@app.route('/debug-users')
def debug_users():
    users = User.query.all()
    if not users:
        return "<h3>هیچ کاربری پیدا نشد.</h3>"
    out = "<h3>کاربران موجود:</h3><ul>"
    for u in users:
        out += f"<li>{u.username}</li>"
    out += "</ul>"
    return out




if __name__ == '__main__':
    with app.app_context():
        # Create the database tables if they don't exist
        db.create_all()
        print("Tables created!")
    app.run(debug=True)




