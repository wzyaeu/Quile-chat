from flask import Flask, request
from flask_sqlalchemy import SQLAlchemy
import os
import logging
import threading
from logging.handlers import RotatingFileHandler
from waitress import serve
from colorama import Style, Fore, init
from typing import Callable
from functools import wraps
from definition import *
import json
import requests
import time
import hashlib
import random
import os

VERSION = 'v0.1.1'

def chatrules(chatid,rulename)-> dict:
    """获取聊天规则"""
    chat = Chat.query.filter_by(id=str(chatid)).first()
    if chat and 'rules' in chat.setting and rulename in chat.setting['rules']:
        return chat.setting['rules'][rulename]
    return {}

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
                kw = {arg:(str(json.loads(request.data.decode('utf-8'))[arg]) if arg in request.data.decode('utf-8') else None) for arg in bodyargs}
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

def display(**kwargs):
    os.system('cls')
    import pyfiglet
    print(CYAN+pyfiglet.figlet_format("Q u i l e  C h a t", font="standard"))
    
    server_info = {'服务器端口':Fore.LIGHTBLUE_EX+str(config['SERVER_PORT']),
                '服务器版本':CYAN+VERSION+RESET_ALL}
    print_list(server_info,title='服务器信息')
    print_list(config,title='配置文件')
    print(RESET_ALL+'输入'+CYAN+'over'+RESET_ALL+'关闭')

    while True:
        cmd = input(RESET_ALL+DIM+'['+RESET_ALL+CYAN+'command'+RESET_ALL+DIM+']> '+RESET_ALL)
        match cmd:
            case 'over':
                break
            case 'help':
                print(CYAN+'command教程'+RESET_ALL)
                print(CYAN+'格式'+RESET_ALL+'head command\n')
                print(BRIGHT+'head : over'+RESET_ALL)
                print('信息：关闭程序')
                print('用法：over')
                print(BRIGHT+'head : help'+RESET_ALL)
                print('信息：帮助')
                print('用法：help')
                print(BRIGHT+'head : run'+RESET_ALL)
                print('信息：进行api调用')
                print('用法：run <api> <args>')
                print('api：http地址"/api"后的地址，如无则为"/"')
                print('api示例：`/`表示调用`/api`，`/server/name`表示调用`/api/server/name`。')
                print('args：请求所需要的json请求体数据，为key:word的字典形式。')
                print('args示例：`user:username`表示`{"user":"username"}`。')
            case _:
                try:
                    cmdarg = cmd.split(' ')
                    if cmdarg[0] == 'run':
                        try:
                            print(json.dumps(
                                    {arg.split(':')[0]:\
                                     arg.split(':')[1]\
                                     for arg in cmdarg[2:]}
                                ))
                            respose = requests.post(f'http://{config['SERVER_HOST']}:{config['SERVER_PORT']}/api{'' if cmdarg[1]=='/' else cmdarg[1]}',
                                data=json.dumps(
                                    {arg.split(':')[0]:\
                                     arg.split(':')[1]\
                                     for arg in cmdarg[2:]}
                                )
                            )
                            print(print_list(json.loads(respose.content),'respose'))
                        except Exception as e:
                            print(e)
                    else:
                        print('未知指令')
                except Exception as e:
                    print(e)

def print_list(_list: dict|list,title=None,level=0,last=0):
    if title:
        print(RESET_ALL+title)
    if len(_list) == 0:
        print(RESET_ALL+DIM+('│ ' * (level-last)+'╰ ' * last)+'╰ （空）')
    else:
        if type(_list) is dict:
            for index, (key,value) in enumerate(_list.items()):
                if type(value) is dict or type(value) is list:
                    print(RESET_ALL+DIM+('│ ' * level)+'├ '+RESET_ALL+BRIGHT+str(key).rstrip("\n")+RESET_ALL)
                    print_list(value,level=level+1,last=(last+1 if index == len(_list.items())-1 else 0))
                elif value == None:
                    print(RESET_ALL+DIM+('│ ' * level)+'├ '+RESET_ALL+BRIGHT+str(key).rstrip("\n")+RESET_ALL+': （空）'+RESET_ALL)
                else:
                    print(RESET_ALL+DIM+(('│ ' * (level-last)+'╰ ' * last) if index == len(_list.items())-1 else ('│ ' * level))+('╰ ' if index == len(_list.items())-1 else'├ ')+RESET_ALL+CYAN+RESET_ALL+BRIGHT+str(key).rstrip("\n")+RESET_ALL+': '+(Fore.LIGHTBLUE_EX if type(value) == bool else Fore.LIGHTCYAN_EX if type(value) == int or type(value) == float else RESET_ALL if type(value) == str else Fore.LIGHTYELLOW_EX)+str(value).rstrip("\n")+RESET_ALL)
        elif type(_list) is list:
            for index, value in enumerate(_list):
                if type(value) is dict or type(value) is list:
                    print(RESET_ALL+DIM+('│ ' * level)+'├─╮'+RESET_ALL)
                    print_list(value,level=level+1,last=(last+1 if index == len(_list)-1 else 0))
                elif type(value) is None:
                    print(RESET_ALL+DIM+('│ ' * level)+'├ '+RESET_ALL+BRIGHT+'（空）'+RESET_ALL)
                else:
                    print(RESET_ALL+DIM+(('│ ' * (level-last)+'╰ ' * last) if index == len(_list)-1 else ('│ ' * level))+('╰ ' if index == len(_list)-1 else'├ ')+RESET_ALL+CYAN+RESET_ALL+(Fore.LIGHTBLUE_EX if type(value) == bool else Fore.LIGHTCYAN_EX if type(value) == int or type(value) == float else RESET_ALL if type(value) == str else Fore.LIGHTYELLOW_EX)+str(value).rstrip("\n")+RESET_ALL)

def main():

    global app, db, User, Chat, chat_type, msg_type, RESET_ALL, CYAN, DIM, BRIGHT, config, VERSION
    
    RESET_ALL = Style.RESET_ALL
    CYAN = Fore.CYAN
    DIM = Style.DIM
    BRIGHT = Style.BRIGHT
    init()

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

    with app.app_context():
        db.create_all()
    
    # 配置根日志记录器
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)
    root_logger.addHandler(handler)

    app.config['MAX_CONTENT_LENGTH'] = (1024 ^ config['MAX_CONTENT_LENGTH']['unit']) * config['MAX_CONTENT_LENGTH']['quantity']

    import api.api as api
    import api.server as server
    import api.user as user
    import api.friend as friend
    import api.chat as chat

    app.register_blueprint(api.app)
    app.register_blueprint(server.app)
    app.register_blueprint(user.app)
    app.register_blueprint(friend.app)
    app.register_blueprint(chat.app)

    server_thread = threading.Thread(target=serve, kwargs={'app':app,'host':config['SERVER_HOST'],'port':config['SERVER_PORT']})
    server_thread.daemon = True
    server_thread.start()

    display()

if __name__ == '__main__':
    main()