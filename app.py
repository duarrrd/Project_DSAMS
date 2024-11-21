from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_bcrypt import Bcrypt
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length
import re
import requests
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
from datetime import datetime, timedelta
import pyotp
import qrcode
import os
from io import BytesIO
from base64 import b64encode
from flask_dance.contrib.google import make_google_blueprint, google
import secrets

# Configuration
app = Flask(__name__)
app.secret_key = "your_secret_key"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///users.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["RECAPTCHA_SITE_KEY"] = "6Le55YMqAAAAAJD5ijQu62xrGg1V5kn7PJl9cgv0"
app.config["RECAPTCHA_SECRET_KEY"] = "6Le55YMqAAAAAK4NQ5oAoQof0tv8plVgYeOXgwdK"

# Email configurations
app.config["MAIL_SERVER"] = "live.smtp.mailtrap.io"
app.config["MAIL_PORT"] = 587
app.config["MAIL_USE_TLS"] = True
app.config["MAIL_USERNAME"] = "smtp@mailtrap.io"
app.config["MAIL_PASSWORD"] = "78247d8b3b51a9f09b7c88d518aa682a"
app.config["MAIL_DEFAULT_SENDER"] = "hello@demomailtrap.com"

mail = Mail(app)
serializer = URLSafeTimedSerializer(app.secret_key)

# Initialize extensions
bcrypt = Bcrypt(app)
db = SQLAlchemy(app)

# User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=True)  # Optional for OAuth users
    is_active = db.Column(db.Boolean, default=False)
    failed_attempts = db.Column(db.Integer, default=0)
    is_2fa_enabled = db.Column(db.Boolean, default=False)  # 2FA enabled/disabled
    totp_secret = db.Column(db.String(16), nullable=True)  # TOTP secret
    login_method = db.Column(db.String(20), default="local")  # "local" or "oauth"

class LoginAttempt(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False)
    success = db.Column(db.Boolean, nullable=False)
    ip_address = db.Column(db.String(45), nullable=True)  # Store the IP address of the user

class PasswordResetToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    token = db.Column(db.String(128), unique=True, nullable=False)
    expiration = db.Column(db.DateTime, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship("User", backref="password_reset_tokens")

def generate_token():
    return secrets.token_urlsafe(32)

def generate_totp_secret():
    return pyotp.random_base32()

def verify_totp(secret, code):
    totp = pyotp.TOTP(secret)
    return totp.verify(code)

# Create database
with app.app_context():
    db.create_all()

def send_email(to, subject, body):
    msg = Message(subject, recipients=[to], body=body)
    mail.send(msg)

os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

# Configure Google OAuth
google_bp = make_google_blueprint(
    client_id="681985724104-tvk755n78sajt6osqm91bi16s3ajqi4f.apps.googleusercontent.com",
    client_secret="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",
    redirect_to="google_login"
)
app.register_blueprint(google_bp, url_prefix="/login")

# Password policy validation
def validate_password(password):
    if len(password) < 8:
        return "Password must be at least 8 characters long."
    if not re.search(r"[A-Z]", password):
        return "Password must contain an uppercase letter."
    if not re.search(r"[a-z]", password):
        return "Password must contain a lowercase letter."
    if not re.search(r"[0-9]", password):
        return "Password must contain a number."
    if not re.search(r"[\W_]", password):
        return "Password must contain a special character."
    return None

# Registration form with reCAPTCHA
class RegistrationForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired(), Length(min=8)])
    submit = SubmitField("Register")

@app.route("/")
def index():
    return render_template("login.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        # Validate reCAPTCHA
        recaptcha_response = request.form.get("g-recaptcha-response")
        recaptcha_data = {
            "secret": app.config["RECAPTCHA_SECRET_KEY"],
            "response": recaptcha_response,
        }
        recaptcha_verify = requests.post(
            "https://www.google.com/recaptcha/api/siteverify", data=recaptcha_data
        ).json()

        if not recaptcha_verify.get("success"):
            flash("Please complete the reCAPTCHA to continue.", "error")
            return render_template("register.html", form=form)

        # Check if user already exists
        if User.query.filter_by(username=username).first():
            flash("User already exists. Please log in.", "error")
            return redirect(url_for("index"))

        # Validate password policy
        validation_error = validate_password(password)
        if validation_error:
            flash(validation_error, "error")
            return render_template("register.html", form=form)

        # Hash the password and create a new user
        hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")
        new_user = User(username=username, password_hash=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        # Generate activation token
        token = serializer.dumps(username, salt="email-confirm")
        activation_link = url_for("activate_account", token=token, _external=True)

        # Send activation email
        msg = Message(
            "Activate Your Account",
            recipients=[username],  # Assuming username is the email
            body=f"Click the link to activate your account: {activation_link}",
        )
        mail.send(msg)

        flash("Registration successful! Check your email to activate your account.", "success")
        return redirect(url_for("index"))

    return render_template("register.html", form=form)

@app.route("/activate/<token>")
def activate_account(token):
    try:
        username = serializer.loads(token, salt="email-confirm", max_age=3600)  # 1-hour expiry
    except SignatureExpired:
        flash("The activation link has expired. Please register again.", "error")
        return redirect(url_for("register"))

    user = User.query.filter_by(username=username).first()
    if user:
        user.is_active = True
        db.session.commit()
        flash("Account activated successfully! You can now log in.", "success")
        return redirect(url_for("index"))
    else:
        flash("Invalid activation link.", "error")
        return redirect(url_for("register"))


MAX_FAILED_ATTEMPTS = 5

@app.route("/login", methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Handle form submission
        username = request.form.get('username')
        password = request.form.get('password')

        # Find the user by username
        user = User.query.filter_by(username=username).first()

        # Prepare to log the attempt
        login_attempt = LoginAttempt(
            username=username,
            timestamp=datetime.utcnow(),
            success=False,  # Default to failed attempt
            ip_address=request.remote_addr,
        )

        if not user:
            flash("User not found. Please register.", "error")
            db.session.add(login_attempt)
            db.session.commit()
            return redirect(url_for("register"))

        if not user.is_active:
            flash("Account is not activated. Check your email to activate.", "error")
            db.session.add(login_attempt)
            db.session.commit()
            return redirect(url_for("index"))

        if user.failed_attempts >= MAX_FAILED_ATTEMPTS:
            flash("Account locked due to too many failed login attempts. Contact admin.", "error")
            db.session.add(login_attempt)
            db.session.commit()
            return redirect(url_for("index"))

        if bcrypt.check_password_hash(user.password_hash, password):
            if user.is_2fa_enabled:
                session["username"] = username
                flash("Enter the 2FA code to complete login.", "info")
                login_attempt.success = True  # Password is correct
                db.session.add(login_attempt)
                db.session.commit()
                return redirect(url_for("verify_2fa"))

            # Successful login without 2FA
            session["username"] = username
            user.failed_attempts = 0
            db.session.commit()
            flash("Login successful!", "success")
            login_attempt.success = True
            db.session.add(login_attempt)
            db.session.commit()
            return redirect(url_for("profile"))

        # Failed login: Increment failed attempts
        user.failed_attempts += 1
        db.session.commit()
        if user.failed_attempts >= MAX_FAILED_ATTEMPTS:
            flash("Account locked due to too many failed login attempts.", "error")
        else:
            flash("Invalid password. Please try again.", "error")
        db.session.add(login_attempt)
        db.session.commit()
        return redirect(url_for("index"))

    # Handle GET request (render login page)
    return render_template("login.html")


@app.route("/login/google/authorized")
def google_login():
    print("Step 1: Reached authorized endpoint")
    if not google.authorized:
        print("Step 2: Not authorized")
        return redirect(url_for("index"))

    resp = google.get("/oauth2/v1/userinfo")
    print(f"Step 3: Google response: {resp.json()}")

    user_info = resp.json()
    email = user_info.get("email")

    # Check if user exists in the database
    user = User.query.filter_by(username=email).first()
    if not user:
        # If the user doesn't exist, create a new one
        user = User(username=email, is_active=True, login_method="google")
        db.session.add(user)
        db.session.commit()

    # Set the session
    session["username"] = user.username  # Or any identifier

    flash(f"Welcome, {user.username}! You have successfully logged in.", "success")
    return redirect(url_for("profile"))


@app.route("/verify-2fa", methods=["GET", "POST"])
def verify_2fa():
    user = User.query.filter_by(username=session.get("username")).first()
    if not user or not user.is_2fa_enabled:
        flash("2FA is not enabled for your account.", "error")
        return redirect(url_for("index"))

    if request.method == "POST":
        code = request.form["code"]
        if verify_totp(user.totp_secret, code):
            flash("2FA verified successfully!", "success")
            return redirect(url_for("profile"))
        else:
            flash("Invalid 2FA code. Please try again.", "error")
            return redirect(url_for("verify_2fa"))

    return render_template("verify_2fa.html")

@app.route("/profile", methods=["GET", "POST"])
def profile():
    user = User.query.filter_by(username=session.get("username")).first()
    if request.method == "POST":
        if "enable_2fa" in request.form:
            user.totp_secret = generate_totp_secret()
            user.is_2fa_enabled = True
            db.session.commit()
            flash("2FA enabled. Use the displayed QR code to configure your authenticator app.", "success")
        elif "disable_2fa" in request.form:
            user.is_2fa_enabled = False
            user.totp_secret = None
            db.session.commit()
            flash("2FA disabled.", "success")
    return render_template("profile.html", user=user)

@app.route("/qrcode")
def qrcode_page():
    user = User.query.filter_by(username=session.get("username")).first()
    if not user or not user.totp_secret:
        flash("2FA is not enabled for your account.", "error")
        return redirect(url_for("profile"))

    totp = pyotp.TOTP(user.totp_secret)
    uri = totp.provisioning_uri(
        name=user.username, issuer_name="YourAppName"
    )
    qr = qrcode.make(uri)
    buffer = BytesIO()
    qr.save(buffer)
    buffer.seek(0)
    img_str = b64encode(buffer.getvalue()).decode("utf-8")
    return render_template("qrcode.html", img_data=img_str)

@app.route("/admin/login_attempts")
def view_login_attempts():
    login_attempts = LoginAttempt.query.order_by(LoginAttempt.timestamp.desc()).all()
    return render_template("admin_login_attempts.html", login_attempts=login_attempts)


@app.route('/password-reset', methods=['GET', 'POST'])
def request_password_reset():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(username=email).first()

        if user:
            token = generate_token()
            expiration_time = datetime.utcnow() + timedelta(hours=1)  # Token expires in 1 hour
            reset_token = PasswordResetToken(user_id=user.id, token=token, expiration=expiration_time)
            db.session.add(reset_token)
            db.session.commit()

            # Send email with reset link
            reset_link = url_for('reset_password', token=token, _external=True)
            send_email(
                to=email,
                subject="Password Reset Request",
                body=f"Click the link to reset your password: {reset_link}\nThe link expires in 1 hour."
            )

            flash("An email with password reset instructions has been sent.", "info")
        else:
            flash("If the email is associated with an account, a password reset email will be sent.", "info")
        return redirect(url_for('login'))

    return render_template('password_reset_request.html')

@app.route('/password-reset/<token>', methods=['GET', 'POST'])
def reset_password(token):
    reset_token = PasswordResetToken.query.filter_by(token=token).first()

    # Check if the token is valid
    if not reset_token or reset_token.expiration < datetime.utcnow():
        flash("The password reset token is invalid or has expired.", "error")
        return redirect(url_for('request_password_reset'))

    if request.method == 'POST':
        new_password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if new_password != confirm_password:
            flash("Passwords do not match.", "error")
            return redirect(request.url)  # Stay on the same page

        # Update the user's password
        user = User.query.get(reset_token.user_id)
        if not user:
            flash("User not found.", "error")
            return redirect(url_for('request_password_reset'))

        # Save the hashed password to the correct field in the database
        user.password_hash = bcrypt.generate_password_hash(new_password).decode('utf-8')
        db.session.commit()

        # Delete the used token
        db.session.delete(reset_token)
        db.session.commit()

        flash("Your password has been reset successfully.", "success")
        return redirect(url_for('login'))  # Redirect to login page after success

    return render_template('password_reset.html')





if __name__ == "__main__":
    app.run(debug=True)
