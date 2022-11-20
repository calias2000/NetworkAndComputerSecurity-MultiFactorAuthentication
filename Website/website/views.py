from flask import Blueprint, render_template, request, flash, redirect, session
from .models import User
from . import db
import string, random, nacl.utils, hashlib, re, nacl.secret
from nacl.public import PrivateKey, Box
from nacl.signing import SigningKey, VerifyKey
from nacl.encoding import HexEncoder

views = Blueprint('views', __name__)

privkserver = PrivateKey.generate()
pubkserver = privkserver.public_key


# Register user
@views.route('/register', methods = ['GET', 'POST'])
def sign_up():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        password1 = request.form.get('password1')

        # Password ate least (8 characters, 1 upper_case, 1 lower_case, 1 number, 1 special char)
        m = re.compile(r'^(?=.*[A-Z])(?=.*[!@#$&*])(?=.*[0-9])(?=.*[a-z]).{8,}$')

        if User.query.filter_by(email=email).first():
            flash('Email already exists', category='error')
        elif len(username) < 4:
            flash('Username needs to have at least 4 characters', category='error')
        elif len(email) < 3:
            flash('Email needs to have at least 3 characters', category='error')
        elif not m.match(password):
            flash('Password needs to have at least 8 characters, one upper case, one number and one special symbol ($!&)', category='error')
        elif password != password1:
            flash('Passwords do not match', category='error')
        else:
            createToken = ''.join(random.choice(string.ascii_uppercase + string.digits + string.ascii_lowercase) for _ in range(10))
            db.session.add(User(username=username, email=email, password=hashlib.sha1(password.encode('utf-8')).hexdigest(), money=0, createToken=createToken, smartphoneLinked=0))
            db.session.commit()
            flash('Account created', category='success')
            return redirect('/')

    return render_template("register.html")


# Login
@views.route('/', methods = ['GET', 'POST'])
def login():
    session.pop('credentials', None)
    session.pop('authenticated', None)
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        password = hashlib.sha1(password.encode('utf-8')).hexdigest()

        user = User.query.filter_by(email=email).first()

        if user:
            if user.password == password:
                flash('Credentials accepted', category='success')
                session['credentials'] = user.id
                return redirect('/authentication')
            else:
                flash('Incorrect Credentials', category='error')
        else:
            flash('Email does not exist', category='error')

    return render_template("login.html")


# Authentication with login Token
@views.route('/authentication', methods = ['GET', 'POST'])
def authentication():
    try:
        user = User.query.filter_by(id=session['credentials']).first()
        if user.smartphoneLinked == 0:
            createToken = 'Activation token to be inserted in the smartphone app: ' + user.createToken
        else:
            createToken = 'Smartphone linked to the account'
    except:
        flash('Login first', category='error')
        return redirect('/')

    if request.method == 'POST':
        if request.form.get('token') == user.loginToken:
            session['authenticated'] = True
            flash('You have successfully logged in to the Wallet Web Application', category='success')
            return redirect('/home_user')
        else:
            session.pop('credentials', None)
            flash('Incorrect token', category='error')
            return redirect('/')
    return render_template("authentication.html", createToken=createToken, username=user.username)

# User home page
@views.route('/home_user' , methods = ['GET', 'POST'])
def home_user():
    if 'authenticated' not in session or 'credentials' not in session:
        flash('User is not authenticated', category='error')
        session.pop('credentials', None)
        session.pop('authenticated', None)
        return redirect('/')

    user = User.query.filter_by(id=session['credentials']).first()

    return render_template("home_user.html", username=user.username, money = user.money)

# Deposit cash
@views.route('/deposit', methods = ['GET', 'POST'])
def deposit():
    if 'credentials' not in session or 'authenticated' not in session:
        flash('Login first', category='error')
        session.pop('credentials', None)
        session.pop('authenticated', None)
        return redirect('/')

    elif request.method == 'POST':
        deposited = int(request.form.get('deposited'))
        user = User.query.filter_by(id=session['credentials']).first()

        if deposited > 0:
            user.money += deposited
            db.session.commit()
            flash('You have successfully deposited', category='success')
            return redirect('/home_user')
        else:
            flash('Incorrect amount', category='error')
            return redirect('/deposit')

    return render_template("deposit.html")


# Send money to another user
@views.route('/send_money', methods = ['GET', 'POST'])
def send_money():
    if 'credentials' not in session or 'authenticated' not in session:
        flash('Login first', category='error')
        session.pop('credentials', None)
        session.pop('authenticated', None)
        return redirect('/')

    elif request.method == 'POST':
        money_sent = int(request.form.get('money_sent'))
        sent_to = request.form.get('sent_to')

        user = User.query.filter_by(id=session['credentials']).first()
        receiver = User.query.filter_by(username=sent_to).first()

        if money_sent > 0 and money_sent <= user.money:

            receiver.money += money_sent
            user.money -= money_sent
            db.session.commit()
            flash('You have successfully money_sent', category='success')
            return redirect('/home_user')
        else:
            flash('Incorrect amount or receiver does not exist', category='error')
            return redirect('/send_money')

    return render_template("send_money.html")


# Logout
@views.route('/logout')
def logout():
    session.pop('credentials', None)
    session.pop('authenticated', None)
    flash('User successfully logged out', category='success')
    return redirect('/')


# --------------------------------  APP ROUTES  -----------------------------------------------

@views.route('/appLogin', methods = ['GET', 'POST'])
#@csrf.exempt
def appLogin():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()
        password = hashlib.sha1(password.encode('utf-8')).hexdigest()

        if user:
            if user.password == password:
                return "Credentials Accepted"
            else:
                return "Incorrect Credentials"
        else:
            return "Email does not exist"

    return "Login app route"


@views.route('/keyexchange', methods = ['GET', 'POST'])
def keyexchange():
    if request.method == 'POST':
        user = User.query.filter_by(email=request.form.get('email')).first()
        if user:
            user.pubkuser = request.form.get('pubkuser')
            user.nonce = request.form.get('nonce')
            db.session.commit()
            return bytes(pubkserver).hex()

    return 'Key exchange app route'


@views.route('/atestation', methods = ['GET', 'POST'])
def atestation():
    if request.method == 'POST':

        user = User.query.filter_by(email=request.form.get('email')).first()

        if user:

            pubkuser = nacl.public.PublicKey(bytes.fromhex(user.pubkuser))
            server_box = Box(privkserver, pubkuser)
            signedPubKey = bytes.fromhex(request.form.get('signedPubKey'))
            verify_key = VerifyKey(signedPubKey)
            createToken = server_box.decrypt(bytes.fromhex(request.form.get('createToken')), bytes.fromhex(request.form.get('nonce')))
            createToken1 = verify_key.verify(bytes.fromhex(createToken.decode('utf-8'))).decode('utf-8')

            if createToken1 == user.createToken:
                user.smartphoneLinked = 1
                db.session.commit()
                return "create token valid"
            else:
                return "incorrect create token"
        else:
            return "user does not exist"

    return 'Atestation app route'

@views.route('/loginToken', methods = ['GET', 'POST'])
def loginToken():
    if request.method == 'POST':
        user = User.query.filter_by(email=request.form.get('email')).first()
        if user:

            pubkuser = nacl.public.PublicKey(bytes.fromhex(user.pubkuser))
            server_box = Box(privkserver, pubkuser)
            signedPubKey = bytes.fromhex(request.form.get('signedPubKey'))
            verify_key = VerifyKey(signedPubKey)
            createToken = server_box.decrypt(bytes.fromhex(request.form.get('createToken')), bytes.fromhex(request.form.get('nonce')))
            createToken1 = verify_key.verify(bytes.fromhex(createToken.decode('utf-8'))).decode('utf-8')

            if createToken1 == user.createToken:

                signing_key = SigningKey.generate()
                signed_token = signing_key.sign(bytes(user.loginToken, encoding='utf-8'), encoder=HexEncoder)

                nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE) #bytes

                encrypted = server_box.encrypt(signed_token, nonce).hex()

                verify_key_server = signing_key.verify_key
                verify_key_server_hex = verify_key_server.encode(encoder=HexEncoder)

                final = "" + nonce.hex() + ":" + encrypted + ":" + verify_key_server_hex.decode('utf-8')

                return final
            else:
                return "incorrect create token"
        else:
            return "user does not exist"

    return 'Login Token app route'
