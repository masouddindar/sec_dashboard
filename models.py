from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

class SplunkAlert(db.Model):
    __tablename__ = 'splunk_alerts'

    id = db.Column(db.Integer, primary_key=True)
    src = db.Column(db.String(100))
    dest = db.Column(db.String(100))
    counter = db.Column(db.Integer)
    starttime = db.Column(db.String(50))
    endtime = db.Column(db.String(50))
    detecttime = db.Column(db.String(50))
    reporttime = db.Column(db.String(50))
    body = db.Column(db.Text)
    incidentid = db.Column(db.String(100), unique=True)

    # فیلدهای تولید شده پس از پردازش
    iodefdescription = db.Column(db.Text)
    iodeftype = db.Column(db.String(100))

    received_at = db.Column(db.DateTime, default=datetime.utcnow)


class IODEFDocument(db.Model):
    __tablename__ = 'iodef_documents'

    id = db.Column(db.Integer, primary_key=True)
    incidentid = db.Column(db.String(100), unique=True)
    raw_xml = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    fullname = db.Column(db.String(100), nullable=False)
    personnel_number = db.Column(db.String(50))
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    extension = db.Column(db.String(20))
    unit = db.Column(db.String(100))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class BlockedIP(db.Model):
    __tablename__ = 'blocked_ips'

    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(100), nullable=False)
    reason = db.Column(db.String(255), nullable=True)
    event_time = db.Column(db.String(100), nullable=True)  # می‌تونی DateTime هم بزاری اگه تاریخ واقعی می‌خوای
    duration = db.Column(db.String(100), nullable=True)
    notes = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class ChatID(db.Model):
    __tablename__ = 'chat_ids'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    chat_id = db.Column(db.String(100), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
