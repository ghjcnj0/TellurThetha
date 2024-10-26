from flask import Flask, flash, redirect, render_template, request, url_for, jsonify, make_response
from datetime import datetime
from datetime import timedelta
from datetime import timezone
from flask_jwt_extended import create_access_token
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import jwt_required
from flask_jwt_extended import JWTManager, set_access_cookies
from flask_jwt_extended import get_jwt
from DBAdapter import Adapter
import bcrypt
app = Flask(__name__)
app.secret_key = 'some_secret'
app.config["JWT_SECRET_KEY"] = "super-secret"  # Change this!
app.config['JWT_TOKEN_LOCATION'] = ['cookies']
app.config['JWT_COOKIE_CSRF_PROTECT'] = True
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)
jwt = JWTManager(app)


def generate_hash(password):
    password_bytes = password.encode("utf-8")
    password_salt = bcrypt.gensalt()
    hash_bytes = bcrypt.hashpw(password_bytes, password_salt)
    hash_str = hash_bytes.decode("utf-8")
    return hash_str

def check_password_hash(user_password,hash_password):
    user_password = user_password.encode("utf-8")
    hash_password = hash_password.encode("utf-8")
    return bcrypt.checkpw(user_password,hash_password)

@app.after_request
def refresh_expiring_jwts(response):
    try:
        exp_timestamp = get_jwt()["exp"]
        now = datetime.now(timezone.utc)
        target_timestamp = datetime.timestamp(now + timedelta(minutes=30))
        if target_timestamp > exp_timestamp:
            access_token = create_access_token(identity=get_jwt_identity())
            set_access_cookies(response, access_token)
        return response
    except (RuntimeError, KeyError):
        return response
    
@app.route('/')
def index():
    return render_template('index.html')
@app.route('/account')
@jwt_required()
def account():
    username = get_jwt_identity()
    return render_template('user_data.html',username=username)
@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        password = request.form['password']
        username = request.form['username']
        db = Adapter(schema="prod_test_db",host="85.208.86.99",port="6432",dbname="sch58_db",sslmode="verify-full",user="Admin",password="atdhfkm2024",target_session_attrs="read-write")
        user = db.sel_userdata_by_username(username=f"{username}")
        del db
        if user == []:
            error = 'Инвалид кредентиалz'
        else:
            if check_password_hash(password,user['password']):
                access_token = create_access_token(identity=user['username'])
                flash('You were successfully logged in','logged_in')
                resp = make_response(render_template('login.html'))
                set_access_cookies(resp, access_token)
                return resp
            else:
                error = 'Инвалид кредентиалz'
    return render_template('login.html', error=error)
@app.route('/registration',methods=['GET','POST'])
def registration():
    error = None
    if request.method == "POST":
        password = request.form['password']
        username = request.form['username']
        forbidden_symbols = ["{","}","'",'"']
        db = Adapter(schema="prod_test_db",host="85.208.86.99",port="6432",dbname="sch58_db",sslmode="verify-full",user="Admin",password="atdhfkm2024",target_session_attrs="read-write")
        user = db.sel_userdata_by_username(username=f"{username}")
        del db
        if any(i in forbidden_symbols for i in username) or any(i in forbidden_symbols for i in password):
            error = 'Инвалид кредентиалz, недопустимые символы'
        else:
            if user != []:
                error = "Имя пользователя занято"
            else:
                db = Adapter(schema="prod_test_db",host="85.208.86.99",port="6432",dbname="sch58_db",sslmode="verify-full",user="Admin",password="atdhfkm2024",target_session_attrs="read-write")
                db.insert_userdata_inDB(username=username,hashed_password=generate_hash(password=password))
                del db
                flash('You were successfully registered','Registered')
                return render_template('registration.html')
    return render_template('registration.html', error=error)
@jwt.expired_token_loader
def my_expired_token_callback(jwt_header, jwt_payload):
    return redirect(url_for('login'))

if __name__ == "__main__":
    app.run(debug=True)