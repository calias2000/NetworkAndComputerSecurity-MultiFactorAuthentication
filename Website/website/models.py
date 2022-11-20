from . import db
from flask_login import UserMixin

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True)
    email = db.Column(db.String(150), unique=True)
    password = db.Column(db.String(150))
    money = db.Column(db.Integer)
    createToken = db.Column(db.String(10), unique=True)
    loginToken = db.Column(db.String(10), unique=True)
    smartphoneLinked = db.Column(db.Integer)
    pubkuser = db.Column(db.String(150), unique=True)
