from flask import Flask, Blueprint, request, send_from_directory, make_response
from flask_sqlalchemy import SQLAlchemy
from colorama import Style, Fore, init
from typing import Callable
from functools import wraps
import json
import pyotp
import time
import hashlib
import random
import logging
from logging.handlers import RotatingFileHandler
import os

def flask_init():
    global app, db, config, VERSION
    global User, Chat, chat_type, msg_type

    init()
    app = Flask(__name__)
    VERSION = 'v0.1.1'

    BASE_DIR = os.path.abspath(os.path.dirname(__file__))
    db_path = os.path.join(BASE_DIR, 'data.db')
    app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}'
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


    with app.app_context():
        db.create_all()

    import json

    try:
        with open('config.json','r') as configdata :
            config = json.loads(configdata.read())
    except:
        config = {
                "SERVER_HOST": "127.0.0.1",
                "SERVER_PORT": 5000,
                "SERVER_NAME": "Quile Server",
                "RESPONSE_LOG": True,
                "TOKEN_EXPIRATION_TIME": 3600000,
                "MESSAGE_RETRACT_TIME": 3600000,
                "MAX_CONTENT_LENGTH": {
                    "unit": 3,
                    "quantity": 1
                },
                "FRIEND_REQUST_TIME": 3600000
            }
        with open('config.json','w') as configdata :
            configdata.write(json.dumps(config))

flask_init()

def apilog(func: Callable):
    def apilog_wrapper(*args,**kwargs):
        logging.info(f'route call: {'/'+str(func.__name__).replace('_','/')}')
        r = func(*args,**kwargs)
        if str(r[1])[0] == 2:
            logging.info(f'retrun-code: {r[1]}')
        if str(r[1])[0] == 3:
            logging.info(f'retrun-code: {r[1]}')
        if str(r[1])[0] == 4:
            logging.warning(f'retrun-code: {r[1]}')
        if str(r[1])[0] == 5:
            logging.error(f'retrun-code: {r[1]}')
        return r
    return apilog_wrapper

def getbody(*bodyargs):
    def decorator(func: Callable):
        @wraps(func)
        def gb(*args, **kwargs):
            try:
                kw = {arg:(json.loads(request.data.decode('utf-8'))[arg] if arg in request.data.decode('utf-8') else None) for arg in bodyargs}
                return func(*args,**kw,**kwargs)
            except Exception as e:
                return apireturn(400,msg_type.UP+f'error body: {e}',None)
        return gb
    return decorator

def timestamp():
    return int(time.time())

def sha256text(text:str):
    """sha256哈希字符串"""
    return hashlib.sha256(text.encode('utf-8')).hexdigest()

def apireturn(code: int,msg: str,data: dict):
    """格式化API返回内容"""
    return {'code':code,'msg':msg,'data':data}, code

def Token() -> str:
    import string
    """生成token"""
    while True:
        token = ''.join(random.sample(string.ascii_letters + string.ascii_uppercase + string.digits,k=25))
        # 检查Token是否已存在
        if not User.query.filter_by(token=token).first():
            return token

def id() -> str:
    """生成编号"""
    return sha256text(str(int(timestamp()))+'-'+str(random.randint(0,9999)))

def Verify_token(token) -> bool:
    """检查token是否正确"""
    user = User.query.filter_by(token=token).first()
    print(user.time)
    if user:
        if timestamp() - user.time < config['TOKEN_EXPIRATION_TIME']:
            return True
        else:
            return False
    return False

def userinfo(type,keyword,flag) -> dict :
    """获取用户信息，flag用于是否返回隐私内容"""
    if type == 'user':
        user = User.query.filter_by(id=str(keyword)).first()
    elif type == 'token':
        user = User.query.filter_by(token=str(keyword)).first()
    else:
        return {}
    
    if user:
        user_dict = {
            'user': user.id,
            'name': user.name,
            'token': user.token,
            'time': user.time,
            'password': user.password,
            'otpkey': user.otpkey,
            'prepared_otpkey': user.prepared_otpkey,
            'blacklist': user.blacklist,
            'friend_application': user.friend_application,
            'friend': user.friend
        }
        if not flag:
            try:
                del user_dict['token']
                del user_dict['password']
                del user_dict['otpkey']
                del user_dict['prepared_otpkey']
            except:
                pass
        del user_dict['time']
        return user_dict
    return {}

def chatinfo(chatid) -> dict :
    """获取聊天信息"""
    chat = Chat.query.filter_by(id=str(chatid)).first()
    if chat:
        chat_dict = {
            'type': chat.type,
            'id': chat.id,
            'name': chat.name,
            'password': chat.password,
            'chat': chat.chat,
            'user': chat.user,
            'setting': chat.setting
        }
        del chat_dict['chat']
        del chat_dict['user']
        del chat_dict['password']
        del chat_dict['setting']
        return chat_dict
    return {}

def leveltonumber(level) -> int|bool:
    """聊天内用户等级转数字"""
    if level == 'guest':
        return 0
    elif level == 'member':
        return 1
    elif level == 'admin':
        return 2 
    elif level == 'owner':
        return 3 
    elif type(level) == int and 0 <= level <= 3:
        return level 
    else:
        return False
    
def userlevel(chatid,user,level):
    chat = Chat.query.filter_by(id=str(chatid)).first()
    if chat:
        for chatuser in chat.user:
            if chatuser['user'] == user:
                if leveltonumber(chatuser['level']) >= str(level):
                    return True
                else:
                    return False
    return False

def adduser(name,token,user,password):
    """添加用户"""
    new_user = User(
        user=user,
        name=name,
        token=token,
        time=timestamp(),
        password=password,
        otpkey='',
        prepared_otpkey='',
        blacklist=[],
        friend_application={},
        friend=[]
    )
    db.session.add(new_user)
    db.session.commit()
    
def addchat(name,password,ownertoken,id,chattype):
    """添加聊天"""
    info: dict = userinfo('token',ownertoken,False)
    info['jointime'] = timestamp()
    if chattype == chat_type.group:
        info['level'] = 'owner'
        new_chat = Chat(
            id=id,
            type=chattype,
            name=name,
            password=(sha256text(password) if password else ''),
            chat=[],
            user=[info],
            setting={'anncmnt':[]}
        )
    elif chattype == 'friend':
        new_chat = Chat(
            id=id,
            type=chattype,
            chat=[],
            user=[info]
        )
    db.session.add(new_chat)
    db.session.commit()

def chatrules(chatid,rulename)-> dict:
    """获取聊天规则"""
    chat = Chat.query.filter_by(id=str(chatid)).first()
    if chat and 'rules' in chat.setting and rulename in chat.setting['rules']:
        return chat.setting['rules'][rulename]
    return {}