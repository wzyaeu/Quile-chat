from flask import Flask, request, send_from_directory, make_response
from flask_sqlalchemy import SQLAlchemy
import os
import json
import logging
from logging.handlers import RotatingFileHandler
from waitress import serve
import random
from typing import Callable
import hashlib
import time
import sys
import pyotp
from colorama import Style, Fore, Back, init
    
init()
app = Flask(__name__)
VERSION = 'v0.1.1'

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
db_path = os.path.join(BASE_DIR, 'data.db')
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}' if sys.platform == 'win32' else f'sqlite://{db_path}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

with app.app_context():
    db.create_all()

class User(db.Model):
    __tablename__ = 'users'
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

def print_list(_list: dict|list,title=None,level=0,last=0):
    if title:
        print(Style.RESET_ALL+title)
    if len(_list) == 0:
        print(Style.RESET_ALL+Style.DIM+('│ ' * (level-last)+'╰ ' * last)+'╰ （空）')
    else:
        if type(_list) is dict:
            for index, (key,value) in enumerate(_list.items()):
                if type(value) is dict or type(value) is list:
                    print(Style.RESET_ALL+Style.DIM+('│ ' * level)+'├ '+Style.RESET_ALL+Style.BRIGHT+str(key).rstrip("\n")+Style.RESET_ALL)
                    print_list(value,level=level+1,last=(last+1 if index == len(_list.items())-1 else 0))
                elif value == None:
                    print(Style.RESET_ALL+Style.DIM+('│ ' * level)+'├ '+Style.RESET_ALL+Style.BRIGHT+str(key).rstrip("\n")+Style.RESET_ALL+': （空）'+Style.RESET_ALL)
                else:
                    print(Style.RESET_ALL+Style.DIM+(('│ ' * (level-last)+'╰ ' * last) if index == len(_list.items())-1 else ('│ ' * level))+('╰ ' if index == len(_list.items())-1 else'├ ')+Style.RESET_ALL+Fore.CYAN+Style.RESET_ALL+Style.BRIGHT+str(key).rstrip("\n")+Style.RESET_ALL+': '+(Fore.LIGHTBLUE_EX if type(value) == bool else Fore.LIGHTCYAN_EX if type(value) == int or type(value) == float else Style.RESET_ALL if type(value) == str else Fore.LIGHTYELLOW_EX)+str(value).rstrip("\n")+Style.RESET_ALL)
        elif type(_list) is list:
            for index, value in enumerate(_list):
                if type(value) is dict or type(value) is list:
                    print(Style.RESET_ALL+Style.DIM+('│ ' * level)+'├─╮'+Style.RESET_ALL)
                    print_list(value,level=level+1,last=(last+1 if index == len(_list)-1 else 0))
                elif type(value) is None:
                    print(Style.RESET_ALL+Style.DIM+('│ ' * level)+'├ '+Style.RESET_ALL+Style.BRIGHT+'（空）'+Style.RESET_ALL)
                else:
                    print(Style.RESET_ALL+Style.DIM+(('│ ' * (level-last)+'╰ ' * last) if index == len(_list)-1 else ('│ ' * level))+('╰ ' if index == len(_list)-1 else'├ ')+Style.RESET_ALL+Fore.CYAN+Style.RESET_ALL+(Fore.LIGHTBLUE_EX if type(value) == bool else Fore.LIGHTCYAN_EX if type(value) == int or type(value) == float else Style.RESET_ALL if type(value) == str else Fore.LIGHTYELLOW_EX)+str(value).rstrip("\n")+Style.RESET_ALL)

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

def initialize():
    global VERSION
    global config
    global app
    global logging
    global db
    
    # 创建log目录
    log_dir = "log"
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
    
    # 删除所有旧的日志文件
    if os.path.exists(log_dir):
        for filename in os.listdir(log_dir):
            if filename.endswith('.log'):
                try:
                    os.remove(os.path.join(log_dir, filename))
                except OSError:
                    pass
    
    # 配置日志系统，使用RotatingFileHandler实现文件分割
    log_file = os.path.join(log_dir, "log.log")
    handler = RotatingFileHandler(
        log_file,
        maxBytes=2*1024*1024,  # 2MB
        backupCount=10,  # 保留最多10个备份文件
        encoding='utf-8'
    )
    handler.setFormatter(logging.Formatter(
        "%(asctime)s [%(name)s | %(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    ))
    
    # 配置根日志记录器
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)
    root_logger.addHandler(handler)

    try:
        with open('config.json','r') as configdata :
            config = json.loads(configdata.read())
    except:
        config = {'TOKEN_EXPIRATION_TIME':1*60*60*1000,'MESSAGE_RETRACT_TIME':1*60*60*1000,'SERVER_HOST':'127.0.0.1','SERVER_PORT':5000,'RESPONSE_LOG':True,'SERVER_NAME':'Quile Server','MAX_CONTENT_LENGTH':{'unit':3,'quantity':1},'FRIEND_REQUST_TIME':1*60*60*1000}
        with open('config.json','w') as configdata :
            configdata.write(json.dumps(config))

    app.config['MAX_CONTENT_LENGTH'] = (1024 ^ config['MAX_CONTENT_LENGTH']['unit']) * config['MAX_CONTENT_LENGTH']['quantity']

    os.system('cls')
    import pyfiglet
    print(Fore.CYAN+pyfiglet.figlet_format("Q u i l e  C h a t", font="standard"))
    
    import re
    server_info = {'服务器端口':Fore.LIGHTBLUE_EX+str(config['SERVER_PORT']),
                   '服务器版本':Fore.CYAN+VERSION+Style.RESET_ALL}
    print_list(server_info,title='服务器信息')
    print_list(config,title='配置文件')
    print(Style.RESET_ALL+'按下'+Fore.CYAN+'Ctrl+c'+Style.RESET_ALL+'关闭')
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

# API
@app.errorhandler(404)
def error(error):
    return apireturn(int(error.code),str(error),None)

@app.route('/api',methods=['POST','GET'], endpoint='api')
# 测试连通性
@apilog
def api():
    return apireturn(200,msg_type.SC,{'host':'chatapihost','version':VERSION})

# 服务器类
@app.route('/api/serve/anncmnt',methods=['POST','GET'], endpoint='api_serve_anncmnt')
@apilog
# 服务器公告
def api_serve_anncmnt():
    return apireturn(200,msg_type.SC,{'anncmnt':config.get('anncmnt',None)})
@app.route('/api/serve/name',methods=['POST','GET'], endpoint='api_serve_name')
@apilog
# 服务器公告
def api_serve_name():
    return apireturn(200,msg_type.SC,{'name':config.get('server',None)})

# 用户类
@app.route('/api/user/register',methods=['POST'], endpoint='api_user_register')
@apilog
# 注册用户
def api_user_register():
    # 获取字段
    try :
        requestbody: dict = {key: str(value) for key, value in json.loads(request.data).items()}
    except:
        return apireturn(400,msg_type.UP+'error body',None)
    user = requestbody.get('user')
    if not user:
        return apireturn(400,msg_type.MF+'user',None)
    name:str = requestbody.get('name',user)
    password = requestbody.get('password')
    if not password:
        return apireturn(400,msg_type.MF+'password',None)

    # 检查用户编号是否违规
    if not user.isalnum() and not(5 <= len(user.strip()) <= 30):
        return apireturn(403,msg_type.EF+'user',None)

    # 检查名字是否违规
    if not(2 <= len(user.strip()) <= 30):
        return apireturn(403,msg_type.EF+'user',None)

    # 检查用户编号是否重复
    if User.query.filter_by(user=user).first():
        return apireturn(403,msg_type.UP+'The user is taken',None)

    # 数据库存储
    new_user = User(
        user=user,
        name=name,
        token='',
        time=time.time(),
        password=password,
        otpkey='',
        prepared_otpkey='',
        blacklist=[],
        friend_application={},
        friend=[]
    )
    db.session.add(new_user)
    db.session.commit()

    return apireturn(200,msg_type.SC,None)
@app.route('/api/user/login',methods=['POST'], endpoint='api_user_login')
@apilog
# 登录用户
def api_user_login():
    # 获取字段
    try :
        requestbody: dict = {key: str(value) for key, value in json.loads(request.data).items()}
    except:
        return apireturn(400,msg_type.UP+'error body',None)
    user = requestbody.get('user')
    if not user:
        return apireturn(400,msg_type.MF+'user',None)
    password = requestbody.get('password')
    if not password:
        return apireturn(400,msg_type.MF+'password',None)
    otpcode = requestbody.get('otpcode')
    
    # 检查user
    _user = User.query.filter_by(user=user).first()
    if not _user:
        return apireturn(401,msg_type.EF+'user',None)
    
    # 检查密码
    if not (password == _user.password):
        return apireturn(401,msg_type.EF+'password',None)
    
    # 检查otp
    if _user.otpkey and not pyotp.TOTP(_user.otpkey).verify(otpcode):
        return apireturn(401,msg_type.EF+'otpkey',None)
    
    # 检查是否有token
    if not _user.token:
        # 设置token
        token = Token()
        _user.token = token
        _user.time = time.time()
        db.session.commit()
    else:
        token = _user.token

    return apireturn(200,msg_type.SC,{'token':token})
@app.route('/api/user/info',methods=['POST'], endpoint='api_user_info')
@apilog
# 获取用户信息
def api_user_info():
    # 获取字段
    try :
        requestbody: dict = {key: str(value) for key, value in json.loads(request.data).items()}
    except:
        return apireturn(400,msg_type.UP+'error body',None)
    user = requestbody.get('user')
    if not user:
        return apireturn(400,msg_type.MF+'user',None)
    token = requestbody.get('token')

    # 检查user
    _user = User.query.filter_by(user=user).first()
    if not _user:
        return apireturn(401,msg_type.EF+'user',None)

    # 获取用户信息
    info = {
        'user': _user.id,
        'name': _user.name,
        'token': _user.token,
        'time': _user.time,
        'password': _user.password,
        'otpkey': _user.otpkey,
        'prepared_otpkey': _user.prepared_otpkey,
        'blacklist': _user.blacklist,
        'friend_application': _user.friend_application,
        'friend': _user.friend
    }

    # 获取已加入聊天的信息
    joinchat = []
    for chat in Chat.query.all():
        for chatuser in chat.user:
            if chatuser['user'] == info['user']:
                joinchat.append({
                    'id': chat.id,
                    'type': chat.type,
                    'name': chat.name,
                    'password': chat.password,
                    'user': chat.user,
                    'setting': chat.setting
                })
                break
    info['joinchat'] = joinchat
    
    # 检查token
    if not Verify_token(token) and info['user'] == user:
        del info['joinchat']
        del info['token']
        del info['time']
        del info['password']

    return apireturn(200,msg_type.SC,info)
@app.route('/api/user/joinchat',methods=['POST'], endpoint='api_user_joinchat')
@apilog
# 获取用户已加入聊天的信息
def api_user_joinchat():
    # 获取字段
    try :
        requestbody: dict = {key: str(value) for key, value in json.loads(request.data).items()}
    except:
        return apireturn(400,msg_type.UP+'error body',None)
    token = requestbody.get('token')
    if not token:
        return apireturn(400,msg_type.MF+'token',None)
    
    # 检查token
    if not Verify_token(token) :
        return apireturn(401,msg_type.EF+'token',None)

    # 获取用户信息
    user = User.query.filter_by(token=token).first()
    if not user:
        return apireturn(401,msg_type.EF+'token',None)

    # 获取已加入聊天的信息
    joinchat = []
    for chat in Chat.query.all():
        for chatuser in chat.user:
            if chatuser['user'] == user.id:
                joinchat.append({
                    'id': chat.id,
                    'type': chat.type,
                    'name': chat.name
                })
                break

    return apireturn(200,msg_type.SC,joinchat)
@app.route('/api/user/refreshtoken',methods=['POST'], endpoint='api_user_refreshtoken')
@apilog
# 刷新令牌
def api_user_refreshtoken():
    # 获取字段
    try :
        requestbody: dict = {key: str(value) for key, value in json.loads(request.data).items()}
    except:
        return apireturn(400,msg_type.UP+'error body',None)
    token = requestbody.get('token')
    if not token:
        return apireturn(400,msg_type.MF+'token',None)
    
    # 检查token
    if not Verify_token(token) :
        return apireturn(401,msg_type.EF+'token',None)
    
    # 获取用户信息
    user = User.query.filter_by(token=token).first()
    if not user:
        return apireturn(401,msg_type.EF+'token',None)
    
    # 设置新token
    new_token = Token()
    user.token = new_token
    user.time = timestamp()
    db.session.commit()

    return apireturn(200,msg_type.SC,{'token':new_token})
@app.route('/api/user/otp/generated',methods=['POST'], endpoint='api_user_otp_generated')
@apilog
# 生成OTP密钥
def api_user_otp_generated():
    # 获取字段
    try :
        requestbody: dict = {key: str(value) for key, value in json.loads(request.data).items()}
    except:
        return apireturn(400,msg_type.UP+'error body',None)
    token = requestbody.get('token')
    if not token:
        return apireturn(400,msg_type.MF+'token',None)
    img = requestbody.get('img')
    
    # 检查token
    if not Verify_token(token) :
        return apireturn(401,msg_type.EF+'token',None)
    
    # 获取用户信息
    user = User.query.filter_by(token=token).first()
    if not user:
        return apireturn(401,msg_type.EF+'token',None)
    
    # 检查已有的otp密钥
    if user.otpkey:
        return apireturn(401,msg_type.UP+'OTP key already exists',None)
    
    # 生成otp密钥
    if user.prepared_otpkey:
        otpkey = user.prepared_otpkey
    else:
        otpkey = pyotp.random_base32()
        user.prepared_otpkey = otpkey
        db.session.commit()
    
    otp = pyotp.totp.TOTP(otpkey, interval=30, digits=6)
    uri = otp.provisioning_uri(name=user.id, issuer_name=config['SERVER_NAME'])

    # 生成二维码dataurl
    if img == 'true' :
        import base64
        import qrcode
        from io import BytesIO
        # 生成二维码图片
        qr = qrcode.QRCode(version=1,error_correction=qrcode.constants.ERROR_CORRECT_L, box_size=10, border=4,
        )
        qr.add_data(uri)
        qr.make(fit=True)
        otpimg = qr.make_image(fill_color="black", back_color="white")

        # 转dataurl
        _format = 'PNG'
        buffered = BytesIO()
        otpimg.save(buffered, format=_format)
        img_base64 = base64.b64encode(buffered.getvalue()).decode()
        dataurl = f"data:image/{_format.lower()};base64,{img_base64}"

        resp = make_response(apireturn(200,msg_type.SC,{'key':otpkey,'dataurl':dataurl}))
    else:
        resp = make_response(apireturn(200,msg_type.SC,{'key':otpkey}))

    return resp
@app.route('/api/user/otp/verify',methods=['POST'], endpoint='api_user_otp_verify')
@apilog
# 验证OTP密钥
def api_user_otp_verify():
    # 获取字段
    try :
        requestbody: dict = {key: str(value) for key, value in json.loads(request.data).items()}
    except:
        return apireturn(400,msg_type.UP+'error body',None)
    token = requestbody.get('token')
    if not token:
        return apireturn(400,msg_type.MF+'token',None)
    otpcode = requestbody.get('otpcode')
    if not token:
        return apireturn(400,msg_type.MF+'otpcode',None)
    
    # 检查token
    if not Verify_token(token) :
        return apireturn(401,msg_type.EF+'token',None)
    
    # 获取用户信息
    user = User.query.filter_by(token=token).first()
    if not user:
        return apireturn(401,msg_type.EF+'token',None)
    
    # 检查是否无预备密钥
    if not user.prepared_otpkey:
        return apireturn(401,msg_type.UP+'There is currently no otpkey',None)
    
    # 检查代码
    otp = pyotp.totp.TOTP(user.prepared_otpkey)
    if not otp.verify(int(otpcode)):
        return apireturn(401,msg_type.EF+'otpcode',None)
    
    # 设置密钥
    user.otpkey = user.prepared_otpkey
    user.prepared_otpkey = None
    db.session.commit()

    return apireturn(200,msg_type.SC,None)
@app.route('/api/user/otp/clear',methods=['POST'], endpoint='api_user_otp_clear')
@apilog
# 清除OTP密钥
def api_user_otp_clear():
    # 获取字段
    try :
        requestbody: dict = {key: str(value) for key, value in json.loads(request.data).items()}
    except:
        return apireturn(400,msg_type.UP+'error body',None)
    otpcode = requestbody.get('otpcode')
    if not otpcode:
        return apireturn(400,msg_type.MF+'otpcode',None)
    token = requestbody.get('token')
    if not token:
        return apireturn(400,msg_type.MF+'token',None)
    
    # 检查token
    if not Verify_token(token) :
        return apireturn(401,msg_type.EF+'token',None)
    
    # 获取用户信息
    user = User.query.filter_by(token=token).first()
    if not user:
        return apireturn(401,msg_type.EF+'token',None)
    
    # 检查是否有otp密钥
    if not user.otpkey:
        return apireturn(304,msg_type.UP+'There is currently no OTP keys',None)
    
    # 检查是否与密钥一样
    if pyotp.totp.TOTP(user.otpkey).now() == otpcode:
        return apireturn(304,msg_type.EF+'otpcode',None)
    
    # 删除密钥
    user.otpkey = None
    db.session.commit()

    return apireturn(200,msg_type.SC,None)

# 好友类接口
@app.route('/api/friend/add',methods=['POST'], endpoint='api_friend_add')
@apilog
# 申请添加好友
def api_friend_add():
    # 获取字段
    try :
        requestbody: dict = {key: str(value) for key, value in json.loads(request.data).items()}
    except:
        return apireturn(400,msg_type.UP+'error body',None)
    user = requestbody.get('user')
    if not user:
        return apireturn(400,msg_type.MF+'user',None)
    token = requestbody.get('token')
    if not token:
        return apireturn(400,msg_type.MF+'token',None)
    
    # 检查token
    if not Verify_token(token):
        return apireturn(401,msg_type.EF+'token',None)
    
    # 检查user
    target_user = User.query.filter_by(user=user).first()
    if not target_user:
        return apireturn(401,msg_type.EF+'user',None)
    
    # 获取当前用户信息
    current_user = User.query.filter_by(token=token).first()
    if not current_user:
        return apireturn(401,msg_type.EF+'token',None)
    
    # 检查黑名单
    if current_user.id in target_user.blacklist:
        return apireturn(401,msg_type.UP+'in the blacklist',None)
    
    # 检查申请
    if current_user.id in target_user.friend_application:
        if timestamp() - target_user.friend_application[current_user.id]['time'] < config['FRIEND_REQUST_TIME']:
            return apireturn(401,msg_type.UP+'has already applied',None)
    
    # 发送申请
    target_user.friend_application[current_user.id] = {'user': current_user.id, 'time': timestamp()}
    db.session.commit()

    return apireturn(200,msg_type.SC,None)

@app.route('/api/friend/agree',methods=['POST'], endpoint='api_friend_agree')
@apilog
# 同意添加好友
def api_friend_agree():
    # 获取字段
    try :
        requestbody: dict = {key: str(value) for key, value in json.loads(request.data).items()}
    except:
        return apireturn(400,msg_type.UP+'error body',None)
    user = requestbody.get('user')
    if not user:
        return apireturn(400,msg_type.MF+'user',None)
    token = requestbody.get('token')
    if not token:
        return apireturn(400,msg_type.MF+'token',None)
    
    # 检查token
    if not Verify_token(token):
        return apireturn(401,msg_type.EF+'token',None)
    
    # 获取当前用户信息
    current_user = User.query.filter_by(token=token).first()
    if not current_user:
        return apireturn(401,msg_type.EF+'token',None)
    
    # 检查申请
    if user not in current_user.friend_application:
        return apireturn(401,msg_type.UP+'there is no application for this user',None)
    
    # 检查时间
    if timestamp() - current_user.friend_application[user]['time'] > config['FRIEND_REQUST_TIME']:
        return apireturn(401,msg_type.UP+'it has been timed out',None)
    
    # 设置编号
    newchatid = str(random.randint(0,9999999999)).zfill(10)
    while Chat.query.filter_by(id=newchatid).first():
        newchatid = str(random.randint(0,9999999999)).zfill(10)

    # 删除申请
    del current_user.friend_application[user]

    # 添加好友
    target_user = User.query.filter_by(user=user).first()
    if not target_user:
        return apireturn(401,msg_type.EF+'user',None)
    
    current_user.friend.append({'user': user, 'chatid': newchatid})
    target_user.friend.append({'user': current_user.id, 'chatid': newchatid})

    # 创建私聊聊天
    addchat('', '', token, newchatid, chat_type.friend)
    db.session.commit()

    return apireturn(200,msg_type.SC,{'chatid': newchatid})

@app.route('/api/friend/blacklist',methods=['POST'], endpoint='api_friend_blacklist')
@apilog
# 好友黑名单查看
def api_friend_blacklist():
    # 获取字段
    try :
        requestbody: dict = {key: str(value) for key, value in json.loads(request.data).items()}
    except:
        return apireturn(400,msg_type.UP+'error body',None)
    token = requestbody.get('token')
    if not token:
        return apireturn(400,msg_type.MF+'token',None)
    
    # 检查token
    if not Verify_token(token):
        return apireturn(401,msg_type.EF+'token',None)
    
    # 获取用户信息
    user = User.query.filter_by(token=token).first()
    if not user:
        return apireturn(401,msg_type.EF+'token',None)

    return apireturn(200,msg_type.SC,{'blacklist': user.blacklist})

@app.route('/api/friend/blacklist/add',methods=['POST'], endpoint='api_friend_blacklist_add')
@apilog
# 好友黑名单添加
def api_friend_blacklist_add():
    # 获取字段
    try :
        requestbody: dict = {key: str(value) for key, value in json.loads(request.data).items()}
    except:
        return apireturn(400,msg_type.UP+'error body',None)
    user = requestbody.get('user')
    if not user:
        return apireturn(400,msg_type.MF+'user',None)
    token = requestbody.get('token')
    if not token:
        return apireturn(400,msg_type.MF+'token',None)
    
    # 检查token
    if not Verify_token(token) :
        return apireturn(401,msg_type.EF+'token',None)
    
    # 获取当前用户信息
    current_user = User.query.filter_by(token=token).first()
    if not current_user:
        return apireturn(401,msg_type.EF+'token',None)
    
    # 检查目标用户是否存在
    target_user = User.query.filter_by(user=user).first()
    if not target_user:
        return apireturn(401,msg_type.EF+'user',None)
    
    # 添加黑名单
    if user not in current_user.blacklist:
        current_user.blacklist.append(user)
        db.session.commit()

    return apireturn(200,msg_type.SC,None)

@app.route('/api/friend/blacklist/del',methods=['POST'], endpoint='api_friend_blacklist_del')
@apilog
# 好友黑名单删除
def api_friend_blacklist_del():
    # 获取字段
    try :
        requestbody: dict = {key: str(value) for key, value in json.loads(request.data).items()}
    except:
        return apireturn(400,msg_type.UP+'error body',None)
    user = requestbody.get('user')
    if not user:
        return apireturn(400,msg_type.MF+'user',None)
    token = requestbody.get('token')
    if not token:
        return apireturn(400,msg_type.MF+'token',None)
    
    # 检查token
    if not Verify_token(token) :
        return apireturn(401,msg_type.EF+'token',None)
    
    # 获取当前用户信息
    current_user = User.query.filter_by(token=token).first()
    if not current_user:
        return apireturn(401,msg_type.EF+'token',None)
    
    # 检查目标用户是否存在
    target_user = User.query.filter_by(user=user).first()
    if not target_user:
        return apireturn(401,msg_type.EF+'user',None)
    
    # 删除黑名单
    if user in current_user.blacklist:
        current_user.blacklist.remove(user)
        db.session.commit()

    return apireturn(200,msg_type.SC,None)

# 聊天类
@app.route('/api/chat/add',methods=['POST'], endpoint='api_chat_add')
@apilog
# 添加聊天
def api_chat_add():
    # 获取字段
    try :
        requestbody: dict = {key: str(value) for key, value in json.loads(request.data).items()}
    except:
        return apireturn(400,msg_type.UP+'error body',None)
    name = requestbody.get('name')
    if not name:
        return apireturn(400,msg_type.MF+'name',None)
    password = requestbody.get('password')
    token = requestbody.get('token')
    if not token:
        return apireturn(400,msg_type.MF+'token',None)
    friend = requestbody.get('friend')
    if not friend:
        return apireturn(400,msg_type.MF+'friend',None)
    try:
        friend = json.loads(friend)
        if not isinstance(friend,list):
            return apireturn(401,msg_type.EF+'friend, not list',None)
    except:
        return apireturn(401,msg_type.EF+'friend, not list',None)
    
    # 检查token
    if not Verify_token(token):
        return apireturn(401,msg_type.EF+'token',None)
    # 检查名称是否违规
    if not(2 <= len(name.strip()) <= 15):
        apireturn(403,msg_type.EF+'user',None)
    
    # 设置编号
    newchatid = str(random.randint(0,9999999999)).zfill(10)
    while Chat.query.filter_by(id=newchatid).first():
        newchatid = str(random.randint(0,9999999999)).zfill(10)

    # 获取用户信息
    user = User.query.filter_by(token=token).first()
    if not user:
        return apireturn(401,msg_type.EF+'token',None)
    
    # 检查好友是否存在
    if len(friend) < 1:
        return apireturn(401,msg_type.EF+'friend,empty list',None)
    try:
        for fri in friend:
            if User.query.filter_by(user=fri).first():
                return apireturn(401,msg_type.EF+'friend',None)
    except:
        return apireturn(401,msg_type.EF+'friend',None)
    
    # 设置初始人员
    users = [{
            'user': user.id,
            'level': 'owner',
            'jointime': timestamp()
        }]
    
    for fri in friend:
        fridata = User.query.filter_by(user=fri).first()
        users.append({
            'user': fridata.id,
            'level': 'member',
            'jointime': timestamp()
        })

    # 创建聊天
    new_chat = Chat(
        id=newchatid,
        type=chat_type.group,
        name=name,
        password=password,
        chat=[],
        user=users,
        setting={'anncmnt': []}
    )
    db.session.add(new_chat)
    db.session.commit()

    return apireturn(200,msg_type.SC,{'chatid':newchatid})
@app.route('/api/chat/<int:chatid>/info',methods=['POST'], endpoint='api_chat_info')
@apilog
# 获取聊天信息
def api_chat_info(chatid):
    # 获取字段
    try :
        requestbody: dict = {key: str(value) for key, value in json.loads(request.data).items()}
    except:
        return apireturn(400,msg_type.UP+'error body',None)
    token = requestbody.get('token')
    if not token:
        return apireturn(400,msg_type.MF+'token',None)
    
    # 检查token
    if not Verify_token(token):
        return apireturn(401,msg_type.EF+'token',None)
    
    # 检查聊天是否存在
    chat = Chat.query.filter_by(id=chatid).first()
    if not chat:
        return apireturn(404,msg_type.UC,None)
    
    output = {
                'id': chat.id,
                'name': chat.name
            }
    
    return apireturn(200,msg_type.SC,output)

@app.route('/api/chat/join',methods=['POST'], endpoint='api_chat_join')
@apilog
# 加入聊天
def api_chat_join():
    # 获取字段
    try :
        requestbody: dict = {key: str(value) for key, value in json.loads(request.data).items()}
    except:
        return apireturn(400,msg_type.UP+'error body',None)
    password = requestbody.get('password')
    chatid = sha256text(requestbody.get('chatid'))
    if not chatid:
        return apireturn(400,msg_type.MF+'chatid',None)
    token = requestbody.get('token')
    if not token:
        return apireturn(400,msg_type.MF+'token',None)
    
    # 检查token
    if not Verify_token(token):
        return apireturn(401,msg_type.EF+'token',None)
    
    # 检查聊天是否存在
    chat = Chat.query.filter_by(id=chatid).first()
    if not chat:
        return apireturn(404,msg_type.UC,None)
    
    # 检查聊天密码
    if chat.password and chat.password != password:
        return apireturn(401,msg_type.EF+'password',None)
    
    # 获取用户信息
    user = User.query.filter_by(token=token).first()
    if not user:
        return apireturn(401,msg_type.EF+'token',None)
    
    # 添加用户
    new_user = {
        'user': user.id,
        'level': 'guest',
        'jointime': timestamp()
    }
    chat.user.append(new_user)
    
    # 发送加入消息
    join_message = {
        'type': '-1',
        'time': timestamp(),
        'content': {
            'tiptype': 'join',
            'user': user.id
        }
    }
    chat.chat.append(join_message)
    
    db.session.commit()

    return apireturn(200,msg_type.SC,None)
@app.route('/api/chat/<int:chatid>/user/list',methods=['POST'], endpoint='api_chat_user_list')
@apilog
# 用户列表
def api_chat_user_list(chatid):
    # 检查聊天编号
    chat = Chat.query.filter_by(id=str(chatid)).first()
    if not chat:
        return apireturn(404,msg_type.UC,None)
    
    # 获取字段
    try :
        requestbody: dict = {key: str(value) for key, value in json.loads(request.data).items()}
    except:
        return apireturn(400,msg_type.UP+'error body',None)
    token = requestbody.get('token')
    if not token:
        return apireturn(400,msg_type.MF+'token',None)
    
    # 检查token
    if not Verify_token(token) :
        return apireturn(401,msg_type.EF + 'token',None)
    
    # 获取用户信息
    user = User.query.filter_by(token=token).first()
    if not user:
        return apireturn(401,msg_type.EF + 'token',None)
    
    # 检查是否在聊天内
    chatusers = [chatuser['user'] for chatuser in chat.user]
    if user.id not in chatusers:
        return apireturn(403,msg_type.IP,None)
    
    return apireturn(200,msg_type.SC,chat.user)

@app.route('/api/chat/<string:chatid>/chat/send',methods=['POST'], endpoint='api_chat_chat_send')
@apilog
# 发送聊天信息
def api_chat_chat_send(chatid):
    # 检查聊天编号
    chat = Chat.query.filter_by(id=chatid).first()
    if not chat:
        return apireturn(404,msg_type.UC,None)
    
    # 获取字段
    try :
        requestbody: dict = dict(request.form)
    except Exception as e:
        return apireturn(400,msg_type.UP+'error body '+e,None)
    token = requestbody.get('token')
    if not token:
        return apireturn(400,msg_type.MF+'token',None)
    type = str(requestbody.get('type','0'))
    
    # 检查token
    if not Verify_token(token):
        return apireturn(401,msg_type.EF + 'token',None)
    
    # 获取用户信息
    user = User.query.filter_by(token=token).first()
    if not user:
        return apireturn(401,msg_type.EF + 'token',None)
    
    # 检查是否有权限
    if userlevel(chatid, user.id, 1):
        return apireturn(403,msg_type.IP,None)
    
    # 检查是否在聊天内
    chatusers = [chatuser['user'] for chatuser in chat.user]
    if user.id not in chatusers:
        return apireturn(403,msg_type.IP,None)
    
    # 普通消息
    if type == '0':
        chat_send_0(token,chatid)
    # 引用消息
    elif type == '1':
        chat_send_1(token,chatid)
    # 文件消息
    elif type == '2':
        chat_send_2(token,chatid)
    else :
        return apireturn(400,msg_type.EF+'type',None)

    db.session.commit()

    return apireturn(200,msg_type.SC,None)

def chat_send_0(request,token,chatid):
    # 获取字段
    try :
        requestbody: dict = {key: str(value) for key, value in json.loads(request.data).items()}
    except:
        return apireturn(400,msg_type.UP+'error body',None)
    message = requestbody.get('message')
    if not message:
        return apireturn(400,msg_type.MF+'message',None)
    
    # 获取聊天信息
    chat = Chat.query.filter_by(id=str(chatid)).first()
    if not chat:
        return apireturn(404,msg_type.UC,None)
    
    # 获取用户信息
    user = User.query.filter_by(token=token).first()
    if not user:
        return apireturn(401,msg_type.EF + 'token',None)
    
    # 添加消息
    chat.chat.append({'type':'0','sender':user.id,'time':timestamp(),'content':{'text':message},'id':id() })
    db.session.commit()

def chat_send_1(request,token,chatid):
    
        # 获取字段
        try :
            requestbody: dict = {key: str(value) for key, value in json.loads(request.data).items()}
        except Exception as e:
            return apireturn(400,msg_type.UP+'error body',None)
        citation = requestbody.get('citation')
        if not citation:
            return apireturn(400,msg_type.MF+'citation',None)
        message = requestbody.get('message')
        if not message:
            return apireturn(400,msg_type.MF+'message',None)
        
        # 获取聊天信息
        chat = Chat.query.filter_by(id=str(chatid)).first()
        if not chat:
            return apireturn(404,msg_type.UC,None)
        
        # 获取用户信息
        user = User.query.filter_by(token=token).first()
        if not user:
            return apireturn(401,msg_type.EF + 'token',None)
        
        # 检查引用是否正确
        flag = False
        for msg in chat.chat:
            if msg['id'] == citation:
                if msg['type'] == '-1':
                    return apireturn(400,msg_type.UP+'Unquotable message',None)
                flag = True
                break
        if not flag:
            return apireturn(400,msg_type.EF+'citation',None)
        
        # 添加消息
        chat.chat.append({'type':'1','sender':user.id,'time':timestamp(),'content':{'text':message,'citation':citation},'id':id() })
        db.session.commit()

def chat_send_2(request,token,chatid):
    # 获取上传的文件对象
        uploaded_file = request.files.get('file')
        if not uploaded_file:
            return apireturn(400, msg_type.MF + 'file', None)
        
        def save_uploaded_file(uploaded_file , chat_id):
            # 生成保存目录
            base_storage_dir = 'files'
            os.makedirs(base_storage_dir, exist_ok=True)
            chat_storage_dir = os.path.join(base_storage_dir, chat_id, '/chat/')
            os.makedirs(chat_storage_dir, exist_ok=True)

            # 保存文件
            sha256_hash = hashlib.sha256()

            while True:
                chunk = uploaded_file.read(65536)
                if not chunk:
                    break
                # 更新哈希
                sha256_hash.update(chunk)
            
            uploaded_file.seek(0)
            hash_filename = sha256_hash.hexdigest()

            with open(os.path.join(chat_storage_dir, hash_filename), 'wb') as output_file:
                while True:
                    chunk = uploaded_file.read(65536)
                    if not chunk:
                        break
                    # 写入文件
                    output_file.write(chunk)

            return {
                'fileid': hash_filename,          
                'name': uploaded_file.filename
            }

        filedata = save_uploaded_file(uploaded_file, chatid)

        # 获取聊天信息
        chat = Chat.query.filter_by(id=str(chatid)).first()
        if not chat:
            return apireturn(404,msg_type.UC,None)
        
        # 获取用户信息
        user = User.query.filter_by(token=token).first()
        if not user:
            return apireturn(401,msg_type.EF + 'token',None)
        
        # 添加消息
        chat.chat.append({'type':'2','sender':user.id,'time':timestamp(),'content':filedata,'id':sha256text(str(int(timestamp()))+str(random.randint(0,9999))) })
        db.session.commit()

@app.route('/api/chat/<int:chatid>/chat/get',methods=['POST'], endpoint='api_chat_chat_get')
@apilog
# 获取聊天信息
def api_chat_chat_get(chatid):
    # 检查聊天编号
    chat = Chat.query.filter_by(id=chatid).first()
    if not chat:
        return apireturn(404,msg_type.UC,None)
    
    # 获取字段
    try :
        requestbody: dict = {key: str(value) for key, value in json.loads(request.data).items()}
    except:
        return apireturn(400,msg_type.UP+'error body',None)
    token = requestbody.get('token')
    if not token:
        return apireturn(400,msg_type.MF + 'token',None)
    starttime = requestbody.get('starttime',None)
    overtime = requestbody.get('overtime',None)
    
    # 检查token
    if not Verify_token(token):
        return apireturn(401,msg_type.EF + 'token',None)
    
    # 获取用户信息
    user = User.query.filter_by(token=token).first()
    if not user:
        return apireturn(401,msg_type.EF + 'token',None)
    
    # 检查是否在聊天内
    chatusers = [chatuser['user'] for chatuser in chat.user]
    if user.id not in chatusers:
        return apireturn(403,msg_type.IP,None)
    
    # 用户最开始进入聊天时间
    jointime = None
    for chatuser in chat.user:
        if chatuser['user'] == user.id:
            jointime = chatuser['jointime']
            break
    
    # 遍历聊天信息
    chatlist = []
    for msg in chat.chat:
        if (starttime is None or msg['time'] >= starttime) and (overtime is None or msg['time'] <= overtime) and (jointime is None or msg['time'] >= jointime):
            chatlist.append(msg)

    return apireturn(200,msg_type.SC,chatlist)

@app.route('/api/chat/<int:chatid>/chat/getfile',methods=['POST'], endpoint='api_chat_file_get')
@apilog
# 获取文件
def api_chat_file_get(chatid):
    # 检查聊天编号
    chat = Chat.query.filter_by(id=str(chatid)).first()
    if not chat:
        return apireturn(404,msg_type.UC,None)
    
    # 获取字段
    try :
        requestbody: dict = {key: str(value) for key, value in json.loads(request.data).items()}
    except:
        return apireturn(400,msg_type.UP+'error body',None)
    token = requestbody.get('token')
    fileid = requestbody.get('fileid',0)
    if not fileid:
        return apireturn(400,msg_type.MF + 'fileid',None)
    
    # 检查token
    if not Verify_token(token) :
        return apireturn(401,msg_type.EF + 'token',None)
    
    # 获取用户信息
    user = User.query.filter_by(token=token).first()
    if not user:
        return apireturn(401,msg_type.EF + 'token',None)
    
    # 检查是否在聊天内
    chatusers = [chatuser['user'] for chatuser in chat.user]
    if user.id not in chatusers:
        return apireturn(403,msg_type.IP,None)
    
    # 检查文件是否存在
    filepath = "files/"+str(chatid)+"/chat"
    if not os.path.exists(filepath+"/"+fileid):
        return apireturn(404,msg_type.UP+"The fileid is incorrect or the file has been deleted.",None)
    
    # 返回文件
    return send_from_directory(filepath, fileid, as_attachment=True), 200

@app.route('/api/chat/<int:chatid>/chat/retract',methods=['POST'], endpoint='api_chat_chat_retract')
@apilog
# 撤销自己的聊天信息
def api_chat_chat_retract(chatid):
    # 检查聊天编号
    chat = Chat.query.filter_by(id=chatid).first()
    if not chat:
        return apireturn(404,msg_type.UC,None)
    
    # 获取字段
    try :
        requestbody: dict = {key: str(value) for key, value in json.loads(request.data).items()}
    except:
        return apireturn(400,msg_type.UP+'error body',None)
    token = requestbody.get('token')
    if not token:
        return apireturn(400,msg_type.MF + 'token',None)
    msgid = requestbody.get('msgid',0)
    if not msgid:
        return apireturn(400,msg_type.MF + 'msgid',None)
    
    # 检查token
    if not Verify_token(token):
        return apireturn(401,msg_type.EF + 'token',None)
    
    # 获取用户信息
    user = User.query.filter_by(token=token).first()
    if not user:
        return apireturn(401,msg_type.EF + 'token',None)
    
    # 检查是否有权限
    if userlevel(chatid, user.id, 1):
        return apireturn(403,msg_type.IP,None)
    
    # 检查是否在聊天内
    chatusers = [chatuser['user'] for chatuser in chat.user]
    if user.id not in chatusers:
        return apireturn(403,msg_type.IP,None)
    
    # 检查类型
    if not(msg['type'] == '-1' or msg['type'] == '2') :
        return apireturn(403,msg_type.EF + 'msgid',None)

    # 检查id和令牌是否正确
    flag = False
    for msg in chat.chat:
        if msg['user'] == msgid:
            # 验证token
            if msg['content']['sender'] != user.id and not userlevel(chatid, user.id, 2):
                return apireturn(403,msg_type.IP,None)
            flag = True
            index = chat.chat.index(msg)
            break
    if not flag:
        return apireturn(400,msg_type.EF+'msgid',None)
    
    # 检查消息是否已过期
    if (timestamp() - msg['time']) > config['MESSAGE_RETRACT_TIME']:
        return apireturn(406,msg_type.UP+'The sent time has passed too long.',None)
    
    # 替换为提示信息
    chat.chat[index]['type'] = '-1'
    chat.chat[index]['content'] = {'tiptype':'retract','user':user.id}
    del chat.chat[index]['sender']
    db.session.commit()
    
    return apireturn(200,msg_type.SC,None)

@app.route('/api/chat/<int:chatid>/level/set',methods=['POST'], endpoint='api_chat_level_set')
@apilog
# 设置用户等级
def api_chat_level_set(chatid):
    # 检查聊天编号
    chat = Chat.query.filter_by(id=chatid).first()
    if not chat:
        return apireturn(404,msg_type.UC,None)
    
    # 检查是否为群聊
    if chat.type != chat_type.group:
        return apireturn(404,msg_type.UP+'need a group',None)
    
    # 获取字段
    try :
        requestbody: dict = {key: str(value) for key, value in json.loads(request.data).items()}
    except:
        return apireturn(400,msg_type.UP+'error body',None)
    token = requestbody.get('token')
    if not token:
        return apireturn(400,msg_type.MF + 'token',None)
    user = requestbody.get('user',0)
    if not user:
        return apireturn(400,msg_type.MF + 'user',None)
    level = requestbody.get('level',0)
    if not level:
        return apireturn(400,msg_type.MF + 'level',None)

    # 检查等级是否正确
    if not(isinstance(leveltonumber(level),int) or (isinstance(level,int) and -1<level<3)):
        return apireturn(400,msg_type.EF + 'level',None)
    
    # 检查token
    if not Verify_token(token):
        return apireturn(401,msg_type.EF + 'token',None)
    
    # 获取用户信息
    current_user = User.query.filter_by(token=token).first()
    if not current_user:
        return apireturn(401,msg_type.EF + 'token',None)
    
    # 检查是否在聊天内
    chatusers = [chatuser['user'] for chatuser in chat.user]
    if current_user.id not in chatusers:
        return apireturn(403,msg_type.IP,None)
    
    # 检查是否有权限
    if userlevel(chatid, current_user.id, 2):
        return apireturn(403,msg_type.IP,None)
    
    # 检查对方是否在聊天内
    flag = False
    for chatuser in chat.user:
        if chatuser['user'] == user:
            # 检查是不是自己
            if chatuser['user'] == current_user.id:
                return apireturn(400,msg_type.UP + 'Cannot change your own level.',None)
            flag = True

            # 检查是否要修改成房主
            if level == '3':
                return apireturn(400,msg_type.UP + 'cannot be modified to owner.',None)

            # 检查等级高低
            if userlevel(chatid, user, chatuser['level']):
                return apireturn(400,msg_type.UP + 'cannot modify users with high permissions',None)

            # 修改对方等级
            chatuser['level'] = level

            # 添加消息
            content =  {'tiptype':'levelset','user':current_user.id,'reactive':chatuser['user'],'level':level}
            chat.chat.append({'type':'-1','time':timestamp(),'content':content,'id':id() })
    if not flag :
        return apireturn(401,msg_type.EF + 'user',None)
    
    db.session.commit()
    
    return apireturn(200,msg_type.SC,None)
@app.route('/api/chat/<int:chatid>/anncmnt',methods=['POST'], endpoint='api_chat_anncmnt')
@apilog
# 查看公告
def api_chat_anncmnt(chatid):
    # 检查聊天编号
    chat = Chat.query.filter_by(id=chatid).first()
    if not chat:
        return apireturn(404,msg_type.UC,None)
    
    # 检查是否为群聊
    if chat.type != chat_type.group:
        return apireturn(404,msg_type.UP+'need a group',None)
    
    # 获取字段
    try :
        requestbody: dict = {key: str(value) for key, value in json.loads(request.data).items()}
    except:
        return apireturn(400,msg_type.UP+'error body',None)
    token = requestbody.get('token')
    if not token:
        return apireturn(400,msg_type.MF + 'token',None)
    
    # 检查token
    if not Verify_token(token):
        return apireturn(401,msg_type.EF + 'token',None)
    
    # 获取用户信息
    user = User.query.filter_by(token=token).first()
    if not user:
        return apireturn(401,msg_type.EF + 'token',None)
    
    # 检查是否在聊天内
    chatusers = [chatuser['user'] for chatuser in chat.user]
    if user.id not in chatusers:
        return apireturn(403,msg_type.IP,None)
    
    # 获取公告
    anncmnt = chat.setting.get('anncmnt', [])
    
    return apireturn(200,msg_type.SC,anncmnt)

@app.route('/api/chat/<int:chatid>/anncmnt/add',methods=['POST'], endpoint='api_chat_anncmnt_add')
@apilog
# 增加公告
def api_chat_anncmnt_add(chatid):
    # 检查聊天编号
    chat = Chat.query.filter_by(id=str(chatid)).first()
    if not chat:
        return apireturn(404,msg_type.UC,None)
    
    # 检查是否为群聊
    if chat.type != chat_type.group:
        return apireturn(404,msg_type.UP+'need a group',None)
    
    # 获取字段
    try :
        requestbody: dict = {key: str(value) for key, value in json.loads(request.data).items()}
    except:
        return apireturn(400,msg_type.UP+'error body',None)
    token = requestbody.get('token')
    if not token:
        return apireturn(400,msg_type.MF + 'token',None)
    title = requestbody.get('title',0)
    if not title:
        return apireturn(400,msg_type.MF + 'title',None)
    content = requestbody.get('content',0)
    if not content:
        return apireturn(400,msg_type.MF + 'content',None)
    
    # 检查token
    if not Verify_token(token) :
        return apireturn(401,msg_type.EF + 'token',None)
    
    # 获取用户信息
    user = User.query.filter_by(token=token).first()
    if not user:
        return apireturn(401,msg_type.EF + 'token',None)
    
    # 检查是否在聊天内
    chatusers = [chatuser['user'] for chatuser in chat.user]
    if user.id not in chatusers:
        return apireturn(403,msg_type.IP,None)
    
    # 检查是否有权限
    if not userlevel(chatid, user.id, 2):
        return apireturn(403,msg_type.IP,None)
        
    # 检查content
    import base64
    try:
        content_decode = base64.b64encode(content.encode('utf-8'))
    except:
        return apireturn(403,msg_type.EF + 'content',None)
    
    # 添加新公告
    if 'anncmnt' not in chat.setting:
        chat.setting['anncmnt'] = []
    chat.setting['anncmnt'].append({'title':str(title),'content':content,'id':id(),'creation_time':timestamp(),'modify_time':timestamp()})
    db.session.commit()

    return apireturn(200,msg_type.SC,None)

@app.route('/api/chat/<int:chatid>/anncmnt/modify',methods=['POST'], endpoint='api_chat_anncmnt_modify')
@apilog
# 更改公告
def api_chat_anncmnt_modify(chatid):
    # 检查聊天编号
    chat = Chat.query.filter_by(id=str(chatid)).first()
    if not chat:
        return apireturn(404,msg_type.UC,None)
    
    # 检查是否为群聊
    if chat.type != chat_type.group:
        return apireturn(404,msg_type.UP+'need a group',None)
    
    # 获取字段
    try :
        requestbody: dict = {key: str(value) for key, value in json.loads(request.data).items()}
    except:
        return apireturn(400,msg_type.UP+'error body',None)
    token = requestbody.get('token')
    if not token:
        return apireturn(400,msg_type.MF + 'token',None)
    mid = requestbody.get('id',0)
    if not mid:
        return apireturn(400,msg_type.MF + 'id',None)
    title = requestbody.get('title',0)
    if not title:
        return apireturn(400,msg_type.MF + 'title',None)
    content = requestbody.get('content',0)
    if not content:
        return apireturn(400,msg_type.MF + 'content',None)
    
    # 检查token
    if not Verify_token(token) :
        return apireturn(401,msg_type.EF + 'token',None)
    
    # 获取用户信息
    user = User.query.filter_by(token=token).first()
    if not user:
        return apireturn(401,msg_type.EF + 'token',None)
    
    # 检查是否在聊天内
    chatusers = [chatuser['user'] for chatuser in chat.user]
    if user.id not in chatusers:
        return apireturn(403,msg_type.IP,None)
    
    # 检查是否有权限
    if not userlevel(chatid, user.id, 2):
        return apireturn(403,msg_type.IP,None)
    
    # 检查编号
    flag = False
    if 'anncmnt' in chat.setting:
        for anncmnt in chat.setting['anncmnt']:
            if anncmnt['id'] == mid:
                flag = True
                
                # 检查content
                import base64
                try:
                    content_decode = base64.b64encode(content.encode('utf-8'))
                except:
                    return apireturn(403,msg_type.EF + 'content',None)
                
                anncmnt['title'] = title
                anncmnt['content'] = content
                anncmnt['modify_time'] = timestamp()
                db.session.commit()
                break
    if not flag :
        return apireturn(401,msg_type.EF + 'id',None)

    return apireturn(200,msg_type.SC,None)

@app.route('/api/chat/<int:chatid>/anncmnt/del',methods=['POST'], endpoint='api_chat_anncmnt_del')
@apilog
# 删除公告
def api_chat_anncmnt_del(chatid):
    # 检查聊天编号
    chat = Chat.query.filter_by(id=str(chatid)).first()
    if not chat:
        return apireturn(404,msg_type.UC,None)
    
    # 检查是否为群聊
    if chat.type != chat_type.group:
        return apireturn(404,msg_type.UP+'need a group',None)
    
    # 获取字段
    try :
        requestbody: dict = {key: str(value) for key, value in json.loads(request.data).items()}
    except:
        return apireturn(400,msg_type.UP+'error body',None)
    token = requestbody.get('token')
    if not token:
        return apireturn(400,msg_type.MF + 'token',None)
    mid = requestbody.get('id',0)
    if not mid:
        return apireturn(400,msg_type.MF + 'id',None)
    
    # 检查token
    if not Verify_token(token) :
        return apireturn(401,msg_type.EF + 'token',None)
    
    # 获取用户信息
    user = User.query.filter_by(token=token).first()
    if not user:
        return apireturn(401,msg_type.EF + 'token',None)
    
    # 检查是否在聊天内
    chatusers = [chatuser['user'] for chatuser in chat.user]
    if user.id not in chatusers:
        return apireturn(403,msg_type.IP,None)
    
    # 检查是否有权限
    if not userlevel(chatid, user.id, 2):
        return apireturn(403,msg_type.IP,None)
    
    # 检查编号
    flag = False
    if 'anncmnt' in chat.setting:
        for i, anncmnt in enumerate(chat.setting['anncmnt']):
            if anncmnt['id'] == mid:
                flag = True
                del chat.setting['anncmnt'][i]
                db.session.commit()
                break
    if not flag :
        return apireturn(401,msg_type.EF + 'id',None)

    return apireturn(200,msg_type.SC,None)

if __name__ == '__main__':
    initialize()
    serve(app, host=config['SERVER_HOST'], port=config['SERVER_PORT'])