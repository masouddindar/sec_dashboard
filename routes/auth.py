# routes/auth.py

from flask import Blueprint, render_template, request, redirect, url_for, session, flash
from models import db, User
import bcrypt

auth_bp = Blueprint("auth_bp", __name__)

@auth_bp.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        user = User.query.filter_by(username=username).first()

        if user and bcrypt.checkpw(password.encode("utf-8"), user.password):
            session["logged_in"] = True
            session["username"] = username
            return redirect(url_for("home"))
        else:
            flash("نام کاربری یا رمز عبور اشتباه است!", "error")
            return redirect(url_for("auth_bp.login"))

    return render_template("index.html")


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if request.method == 'POST':
        fullname = request.form['fullname']
        personnel_number = request.form.get('personnel_number')
        username = request.form['username']
        password = request.form['password']
        extension = request.form.get('extension')
        unit = request.form.get('unit')

        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('نام کاربری قبلاً ثبت شده است.', 'error')
            return redirect(url_for('auth_bp.register'))

        new_user = User(
            fullname=fullname,
            personnel_number=personnel_number,
            username=username,
            password=hashed_password,
            extension=extension,
            unit=unit
        )

        db.session.add(new_user)
        db.session.commit()

        flash('ثبت‌ نام با موفقیت انجام شد.', 'success')
        return redirect(url_for('auth_bp.login'))

    return render_template('register.html')
