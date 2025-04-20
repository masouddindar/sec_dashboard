from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()
#Table for storing alerts received from Splunk
class SplunkAlert(db.Model):
    __tablename__ = 'splunk_alerts'  # نام جدول در دیتابیس

    id = db.Column(db.Integer, primary_key=True)  # کلید اصلی، مقدار خودکار
    src = db.Column(db.String(100))  # آی‌پی مبدأ حمله
    dest = db.Column(db.String(100))  # آی‌پی مقصد
    counter = db.Column(db.Integer)  # تعداد تکرار یا دفعات حمله
    starttime = db.Column(db.String(50))  # زمان شروع حمله
    endtime = db.Column(db.String(50))  # زمان پایان حمله
    detecttime = db.Column(db.String(50))  # زمان شناسایی حمله
    reporttime = db.Column(db.String(50))  # زمان ارسال گزارش
    body = db.Column(db.Text)  # توضیحات یا محتوای اصلی هشدار
    incidentid = db.Column(db.String(100), unique=True)  # شناسه یکتا برای هر Incident

    # فیلدهایی که بعداً توسط منطق برنامه ساخته می‌شن
    iodefdescription = db.Column(db.Text)  # توضیح کامل‌تر بر اساس نوع حمله
    iodeftype = db.Column(db.String(100))  # نوع حمله مثل dos، scan و...

    received_at = db.Column(db.DateTime, default=datetime.utcnow)  # زمان دریافت هشدار در سیستم ما


#Table for saving XML files in the format IODEF
class IODEFDocument(db.Model):
    __tablename__ = 'iodef_documents'

    id = db.Column(db.Integer, primary_key=True)  # شناسه یکتا
    incidentid = db.Column(db.String(100), unique=True)  # شناسه یکتا برای Incident
    raw_xml = db.Column(db.Text)  # محتوای خام XML
    created_at = db.Column(db.DateTime, default=datetime.utcnow)  # تاریخ ساخت این رکورد


#table of Users
class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)  # شناسه یکتا
    fullname = db.Column(db.String(100), nullable=False)  # نام و نام خانوادگی
    personnel_number = db.Column(db.String(50))  # شماره پرسنلی کاربر
    username = db.Column(db.String(50), unique=True, nullable=False)  # نام کاربری (باید یکتا باشه)
    password = db.Column(db.String(200), nullable=False)  # رمز عبور هش‌شده (رمز خام ذخیره نمی‌شه!)
    extension = db.Column(db.String(20))  # شماره داخلی کاربر
    unit = db.Column(db.String(100))  # واحد سازمانی
    created_at = db.Column(db.DateTime, default=datetime.utcnow)  # زمان ثبت‌نام کاربر


#table for blocking IP
class BlockedIP(db.Model):
    __tablename__ = 'blocked_ips'

    id = db.Column(db.Integer, primary_key=True)  # شناسه یکتا
    ip_address = db.Column(db.String(100), nullable=False)  # آی‌پی مورد نظر برای بلاک شدن
    reason = db.Column(db.String(255), nullable=True)  # دلیل بلاک
    event_time = db.Column(db.String(100), nullable=True)  # زمان رخداد (می‌تونه DateTime باشه ولی به صورت string ذخیره شده)
    duration = db.Column(db.String(100), nullable=True)  # مدت زمان بلاک به دقیقه (یا ساعت)
    notes = db.Column(db.Text, nullable=True)  # توضیحات اضافی
    created_at = db.Column(db.DateTime, default=datetime.utcnow)  # زمان ثبت بلاک


# Table storing chat_ids of message recipients (for messengers Bale)
class ChatID(db.Model):
    __tablename__ = 'chat_ids'

    id = db.Column(db.Integer, primary_key=True)  # شناسه یکتا
    name = db.Column(db.String(100), nullable=False)  # نام فرد یا گروه مربوط به chat_id
    chat_id = db.Column(db.String(100), unique=True, nullable=False)  # شناسه چت (باید یکتا باشه)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)  # زمان ثبت chat_id

