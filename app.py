from flask import Flask, render_template, redirect, url_for, flash, jsonify, request, session
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from extensions import db
from models import User
from forms import RegistrationForm, LoginForm
import yfinance as yf
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_mail import Mail, Message
from dotenv import load_dotenv
import os
from random import randint
from werkzeug.security import generate_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'

bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]
)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Create database tables
with app.app_context():
    db.init_app(app)
    db.create_all()

# Load environment variables from .env file
load_dotenv()

# Set configuration variables from environment variables
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT'))
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS').lower() in ['true', '1', 't']
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER')

mail = Mail(app)

@app.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created!', 'success')
        
        # Send a confirmation email upon successful registration
        msg = Message('Welcome to Flask App', recipients=[user.email])
        msg.html = render_template('welcome_email.html')
        mail.send(msg)
        
        return redirect(url_for('login'))
    
    return render_template('register.html', title='Register', form=form)

@app.route("/login", methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            return redirect(url_for('dashboard'))
        else:
            flash('Login unsuccessful. Please check email and password', 'danger')
    return render_template('login.html', title='Login', form=form, show_header_footer=False)


@app.route("/dashboard")
@login_required
def dashboard():
    banknifty_ticker = yf.Ticker("^NSEBANK")
    nifty50_ticker = yf.Ticker("^NSEI")
    sensex_ticker = yf.Ticker("^BSESN")

    banknifty_ltp = banknifty_ticker.history(period="1d")['Close'].iloc[-1]
    nifty50_ltp = nifty50_ticker.history(period="1d")['Close'].iloc[-1]
    sensex_ltp = sensex_ticker.history(period="1d")['Close'].iloc[-1]

    return render_template('dashboard.html', title='Dashboard', banknifty_ltp=round(banknifty_ltp, 2), nifty50_ltp=round(nifty50_ltp, 2), sensex_ltp=round(sensex_ltp, 2), show_header_footer=True)


@app.route("/stock")
@login_required
def stock():
    reliance_ticker = yf.Ticker("RELIANCE.NS")
    nifty50_ticker = yf.Ticker("^NSEI")

    reliance_ltp = reliance_ticker.history(period="1d")['Close'].iloc[-1]
    nifty50_ltp = nifty50_ticker.history(period="1d")['Close'].iloc[-1]

    return render_template('stock.html', title='Stock Price', reliance_ltp=round(reliance_ltp, 2), nifty50_ltp=round(nifty50_ltp, 2))

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return render_template('home.html')

@app.route("/")
@app.route("/home")
def home():
    return render_template('home.html', title='Home')

@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify(error="Rate limit exceeded. Please try again in a minute."), 429

@app.route('/forgot', methods=['GET', 'POST'])
def forgot():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()
        if user:
            otp = randint(100000, 999999)
            session['otp'] = otp
            session['email'] = email
            msg = Message('Your OTP Code', recipients=[email])
            msg.body = f'Your OTP code is {otp}'
            mail.send(msg)
            return redirect(url_for('verify_otp'))
        else:
            flash('Email not found', 'danger')
    return render_template('forgot.html')

@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    if request.method == 'POST':
        entered_otp = request.form['otp']
        if int(entered_otp) == session.get('otp'):
            return redirect(url_for('change_password'))
        else:
            flash('Invalid OTP', 'danger')
    return render_template('verify_otp.html')

@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    if request.method == 'POST':
        new_password = request.form['password']
        email = session.get('email')
        hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
        user = User.query.filter_by(email=email).first()
        if user:
            user.password = hashed_password
            db.session.commit()
            session.pop('otp', None)
            session.pop('email', None)
            flash('Password changed successfully', 'success')
            return redirect(url_for('login'))
    return render_template('change_password.html')

if __name__ == '__main__':
    app.run(debug=True)
