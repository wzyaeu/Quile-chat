from flask import Flask
from flask_sqlalchemy import SQLAlchemy
import os

VERSION = 'v0.1.0'

class chat_type():
    group = 'group'
    friend = 'friend'

class msg_type():
    SC = 'Success'# 成功
    MF = 'Missing field: '# 缺失字段
    EF = 'Field error: '# 字段错误
    UC = 'Unknown chat'# 未知聊天
    IP = 'Insufficient permissions'# 权限不足
    UP = 'Unable to proceed: ' #无法完成

app = Flask(__name__)

db_path = os.path.join(os.getcwd(), 'data.db')
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path.replace('\\','/')}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

class User(db.Model):
    user = db.Column(db.String(30), primary_key=True)
    name = db.Column(db.String(30))
    token = db.Column(db.String(25))
    time = db.Column(db.Integer)
    password = db.Column(db.String(64))
    otpkey = db.Column(db.String(32))
    prepared_otpkey = db.Column(db.String(32))
    blacklist = db.Column(db.JSON)
    friend_application = db.Column(db.JSON)
    friend = db.Column(db.JSON)

class Chat(db.Model):
    id = db.Column(db.String(10), primary_key=True)
    type = db.Column(db.String(10))
    name = db.Column(db.String(15))
    password = db.Column(db.String(64))
    chat = db.Column(db.JSON)
    user = db.Column(db.JSON)
    setting = db.Column(db.JSON)