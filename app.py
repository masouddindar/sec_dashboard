from flask import Flask, render_template, request, redirect, url_for, session, flash


app = Flask(__name__)
app.secret_key = "mysecretkey"

#login page 
@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        # اعتبارسنجی ساده
        if username == "admin" and password == "123":
            session["logged_in"] = True
            return redirect(url_for("home")) 
        else:
            flash("نام کاربری یا رمز عبور اشتباه است!")
            return redirect(url_for("login"))

    return render_template("index.html")

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
    elif request.method == 'POST':
        ip_address = request.form.get('ip_address')
        reason = request.form.get('reason')
        datetime = request.form.get('datetime')
        duration = request.form.get('duration')
        notes = request.form.get('notes')
        print("=====================================")
        print("=== receving data from ip block form  ===")
        print(f"IP Address: {ip_address}")
        print(f"Reason: {reason}")
        print(f"Datetime: {datetime}")
        print(f"Duration: {duration}")
        print(f"Notes: {notes}")
        print("=====================================")
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



if __name__ == '__main__':
    app.run(debug=True)
