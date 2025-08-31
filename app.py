from flask import Flask, request, send_from_directory, make_response, redirect, url_for
import os
import json
import random
import hashlib
import string
import time
import pyotp

msgSC = 'Success'# 成功
msgMF = 'Missing field: '# 缺失字段
msgEF = 'Field error: '# 字段错误
msgUR = 'Unknown chat'# 未知房间
msgIP = 'Insufficient permissions'# 权限不足
msgUP = 'Unable to proceed:' #无法完成
msgSE = 'Server Error:' #内部错误

def initialize():
    global users
    global chats
    global useridlist
    global config
    global chatidlist
    global emailsendlist
    
    try:
        with open('config.json','r') as configdata :
            config = json.loads(configdata.read())
    except:
        config = {'TOKEN_EXPIRATION_TIME':1*60*60*1000,'MESSAGE_RETRACT_TIME':1*60*60*1000}
        with open('config.json','w') as configdata :
            configdata.write(json.dumps(config))

    try:
        with open('user.json','r') as userdata :
            users = json.loads(userdata.read())
    except:
        users = {}
        save_user_data()
    
    try:
        with open('chat.json','r') as chatdata :
            chats = json.loads(chatdata.read())
    except:
        chats = {}
        save_chat_data()
    
    useridlist = []
    for user in list(users.values()):
        useridlist.append(user['id'])
        
    chatidlist = []
    for chat in list(chats.values()):
        chatidlist.append(chat['id'])
        
    emailsendlist = {}

def sha256text(text):
    """sha256哈希字符串"""
    return hashlib.sha256(text.encode('utf-8')).hexdigest()

def save_user_data():
    """保存user.json"""
    with open('user.json','w') as userdata :
        userdata.write(json.dumps(users))
def save_chat_data():
    """保存chat.json"""
    with open('chat.json','w') as chatdata :
        chatdata.write(json.dumps(chats))

def apireturn(code,msg,data):
    """格式化API返回内容"""
    return {'code':code,'msg':msg,'data':data}, code

def Token() -> str:
    """生成token"""
    token = ''.join(random.sample(string.ascii_letters + string.ascii_uppercase + string.digits))
    while token in list(chats.values()) :
        token = ''.join(random.sample(string.ascii_letters + string.ascii_uppercase + string.digits))
    
    return token

def msgid() -> str:
    """生成消息编号"""
    return sha256text(str(int(time.time()))+str(random.randint(0,9999)))

def Verify_token(token) -> bool:
    """检查token是否正确"""
    for user in list(users.values()):
        if user['Token'] == token:
            if time.time() - user['time'] < config['TOKEN_EXPIRATION_TIME']:
                return True
            else:
                return False
        
    return False

def userinfo(type,keyword,flag) -> dict :
    """获取用户信息，flag用于是否返回隐私内容"""
    for user in list(users.values()):
        if user[type] == str(keyword):
            user_copy = user.copy()
            if not flag:
                del user_copy['Token']
                del user_copy['password']
            del user_copy['time']
            return user_copy
    return {}

def leveltonumber(level) -> str|None:
    """房间内用户等级转数字"""
    return '0' if level == 'guest' else ('1' if level == 'admin' else ('2' if level == 'owner' else None))

def adduser(name,token,id,password):
    """添加用户"""
    users[id] = {'id':id,'name':name,'Token':token,'time':time.time(),'password':password}
    useridlist.append(id)
    save_user_data()
    
def addchat(name,password,ownertoken,id):
    """添加聊天"""
    ownerinfo: dict = userinfo('Token',ownertoken,False)
    ownerinfo['level'] = 'owner'
    ownerinfo['jointime'] = time.time()
    chats[id] = {'id':id,'name':name,'password':(sha256text(password) if password else ''),'chat':[],'user':[ownerinfo],'setting':{}}
    chatidlist.append(id)
    save_chat_data()

def chatrules(chatid,rulename)-> dict:
    """获取聊天规则"""
    if rulename not in chats[chatid]['rules'] :
        return {}
    else:
        return chats[chatid]['rules']['rulename']

initialize()
app = Flask(__name__)

# API
@app.route('/api/',methods=['POST','GET'])
# 测试连通性
def api():
    return apireturn(200,msgSC,'chatapihost')

@app.route('/api/user/register',methods=['POST','GET'])
# 添加用户
def api_user_register():
    # 获取字段
    try :
        requestbody: dict = {key: str(value) for key, value in json.loads(request.data).items()}
    except Exception as e:
        return apireturn(400,msgUP+'error body',None)
    userid = requestbody.get('userid')
    if not userid:
        return apireturn(400,msgMF+'userid',None)
    name:str = requestbody.get('name',userid)
    password = requestbody.get('password')
    passwordsha256 = requestbody.get('password')
    if (not password) and (not passwordsha256):
        return apireturn(400,msgMF+'password(sha256)',None)
    final_password = sha256text(password) if password else passwordsha256

    # 检查用户编号是否违规
    if userid.isalnum():
        apireturn(403,msgEF+'userid',None)

    # 检查用户编号是否重复
    userids = [user['id'] for user in users ]
    if userid in userids:
        apireturn(403,msgUP+'The userid is taken',None)

    # 本地存储
    adduser(name,userid,final_password,final_password) 

    return apireturn(200,msgSC,None)
@app.route('/api/user/login',methods=['POST','GET'])
# 登录用户
def api_user_login():
    # 获取字段
    try :
        requestbody: dict = {key: str(value) for key, value in json.loads(request.data).items()}
    except Exception as e:
        return apireturn(400,msgUP+'error body',None)
    userid = requestbody.get('userid')
    if not userid:
        return apireturn(400,msgMF+'userid',None)
    password = requestbody.get('password')
    passwordsha256 = requestbody.get('passwordsha56')
    if (not password) and (not passwordsha256):
        return apireturn(400,msgMF+'token',None)
    final_password = sha256text(password) if password else passwordsha256
    otp = requestbody.get('otp')
    
    # 检查userid
    _userinfo = userinfo('id',userid,True)
    if not _userinfo :
        return apireturn(401,msgEF+'userid',None)
    
    # 检查密码
    if not (final_password == _userinfo['password']):
        return apireturn(401,msgEF+'password',None)
    
    # 检查otp
    if 'otp' in users[userid] and not(users[userid]['otp']):
        otp_code = pyotp.TOTP(users[userid]['otp']).now()
        if otp != otp_code:
            return apireturn(401,msgEF+'otp',None)
    
    # 检查是否有token
    if users[userid]['Token'] == '':
        # 设置token
        token = Token()

        # 本地存储
        users[userid]['Token'] = sha256text(token)
        save_user_data()
    else:
        token = users[userid]['Token']

    return apireturn(200,msgSC,{'Token':sha256text(token)})
@app.route('/api/user/info',methods=['POST','GET'])
# 获取用户信息
def api_user_info():
    # 获取字段
    try :
        requestbody: dict = {key: str(value) for key, value in json.loads(request.data).items()}
    except Exception as e:
        return apireturn(400,msgUP+'error body',None)
    userid = requestbody.get('userid')
    if not userid:
        return apireturn(400,msgMF+'userid',None)
    
    # 检查id是否正确
    if not(userid in users):
        return apireturn(400,msgEF+'userid',None)

    # 获取用户信息
    info = userinfo('id',userid,False)

    return apireturn(200,msgSC,info)
@app.route('/api/user/joinchat',methods=['POST','GET'])
# 获取用户已加入房间的列表
def api_user_joinchat():
    # 获取字段
    try :
        requestbody: dict = {key: str(value) for key, value in json.loads(request.data).items()}
    except Exception as e:
        return apireturn(400,msgUP+'error body',None)
    token = requestbody.get('token')
    if not token:
        return apireturn(400,msgMF+'token',None)
    
    # 检查token
    if not Verify_token('re',token) :
        return apireturn(401,msgEF+'token',None)

    # 获取已加入房间的列表
    userid = userinfo('token',token,False)
    joinchat = []
    for chat in list(chats.values()):
        for chatuser in list(chat['user'].values()):
            if chatuser['id'] == userid:
                joinchat.append(chat['id'])
                break


    return apireturn(200,msgSC,{'joinchat':joinchat})
@app.route('/api/user/refreshtoken',methods=['POST','GET'])
# 刷新令牌
def api_user_refreshtoken():
    # 获取字段
    try :
        requestbody: dict = {key: str(value) for key, value in json.loads(request.data).items()}
    except Exception as e:
        return apireturn(400,msgUP+'error body',None)
    token = requestbody.get('token')
    if not token:
        return apireturn(400,msgMF+'token',None)
    
    # 检查token
    if not Verify_token('re',token) :
        return apireturn(401,msgEF+'token',None)
    
    # 设置token
    token = Token()

    # 本地存储
    userid = userinfo('Token',token,False)['id']
    users[userid]['Token'] = sha256text(token)

    save_user_data()

    return apireturn(200,msgSC,{'Token':sha256text(token)})
@app.route('/api/user/otp/set',methods=['POST','GET'])
# 设置OTP密钥
def api_user_otp_set():
    # 获取字段
    try :
        requestbody: dict = {key: str(value) for key, value in json.loads(request.data).items()}
    except Exception as e:
        return apireturn(400,msgUP+'error body',None)
    key = requestbody.get('otpkey')
    if not key:
        return apireturn(400,msgMF+'otpkey',None)
    token = requestbody.get('token')
    if not token:
        return apireturn(400,msgMF+'token',None)
    
    # 检查token
    if not Verify_token(token) :
        return apireturn(401,msgEF+'token',None)
    
    # 检查已有的otp密钥
    if 'otp' in userinfo('Token',token,False) :
        return apireturn(401,msgUP+'OTP key already exists',None)
    
    # 检查密钥
    try:
        pyotp.TOTP(key)
    except Exception as e:
        return apireturn(200,msgUP+e,None)
    
    # 保存密钥
    users[userinfo('Token',token,False)['id']]['otp'] = key
    save_user_data()

    return apireturn(200,msgSC,None)
@app.route('/api/user/otp/clear',methods=['POST','GET'])
# 清除OTP密钥
def api_user_otp_clear():
    # 获取字段
    try :
        requestbody: dict = {key: str(value) for key, value in json.loads(request.data).items()}
    except Exception as e:
        return apireturn(400,msgUP+'error body',None)
    otp = requestbody.get('otp')
    if not otp:
        return apireturn(400,msgMF+'otp',None)
    token = requestbody.get('token')
    if not token:
        return apireturn(400,msgMF+'token',None)
    
    # 检查token
    if not Verify_token(token) :
        return apireturn(401,msgEF+'token',None)
    
    # 检查是否有otp密钥
    if 'otp' not in userinfo('Token',token,False) :
        return apireturn(304,msgUP+'There is currently no OTP keys',None)
    
    # 删除密钥
    del users[userinfo('Token',token,False)['id']]['otp']
    save_user_data()

    return apireturn(200,msgSC,None)
# 房间类接口
@app.route('/api/chat/add',methods=['POST','GET'])
# 添加房间
def api_chat_add():
    # 获取字段
    try :
        requestbody: dict = {key: str(value) for key, value in json.loads(request.data).items()}
    except Exception as e:
        return apireturn(400,msgUP+'error body',None)
    name = requestbody.get('name')
    if not name:
        return apireturn(400,msgMF+'name',None)
    password = requestbody.get('password')
    token = requestbody.get('token')
    if not token:
        return apireturn(400,msgMF+'token',None)
    
    # 检查token
    if not Verify_token(token) :
        return apireturn(401,msgEF+'token',None)
    
    # 设置编号
    newchatid = str(random.randint(0,9999999999)).zfill(10) 
    while newchatid in chatidlist :
        newchatid = str(random.randint(0,9999999999)).zfill(10)

    # 本地存储
    addchat(name,password,token,newchatid) 

    return apireturn(200,msgSC,{'chatid':newchatid})

@app.route('/api/chat/<int:chatid>/join',methods=['POST','GET'])
# 加入房间
def api_chat_join(chatid):
    # 检查房间编号
    if not (chatid in chatidlist):
        return apireturn(404,msgUR,None)
    
    # 获取字段
    try :
        requestbody: dict = {key: str(value) for key, value in json.loads(request.data).items()}
    except Exception as e:
        return apireturn(400,msgUP+'error body',None)
    password = requestbody.get('password')
    passwordsha256 = requestbody.get('passwordsha256')
    token = requestbody.get('token')
    if not token:
        return apireturn(400,msgMF+'token',None)
    final_password = sha256text(password) if password else passwordsha256
    
    # 检查token
    if not Verify_token(token) :
        return apireturn(401,msgEF+'token',None)
    
    # 检查房间密码
    if (not chats[chatid]['password']) and (chats[chatid]['password'] == final_password) :
        return apireturn(401,msgEF+'password or passwordsha256',None)
    
    # 添加用户
    newuser = userinfo('Token',token,False)
    newuser['level'] = 'guest'
    newuser['jointime'] = time.time()
    chats[chatid]['user'].append(newuser)

    # 发送加入消息
    chats[chatid]['chat'].append({
        'type':'-1','time':time.time(),
        'content':{
            'tiptype':'join',
            'user':userinfo('Token',token,False)['id']
        } 
    })
    

    save_chat_data()

    return apireturn(200,msgSC,None)
@app.route('/api/chat/<int:chatid>/user/list',methods=['POST','GET'])
# 用户列表
def api_chat_user_list(chatid):
    # 检查房间编号
    if not (chatid in chatidlist):
        return apireturn(404,msgUR,None)
    
    # 获取字段
    try :
        requestbody: dict = {key: str(value) for key, value in json.loads(request.data).items()}
    except Exception as e:
        return apireturn(400,msgUP+'error body',None)
    token = requestbody.get('token')
    if not token:
        return apireturn(400,msgMF+'token',None)
    
    # 检查token
    if not Verify_token(token) :
        return apireturn(401,msgEF + 'token',None)
    
    # 检查是否在房间内
    chatusertoken = []
    for chatuser in chats[chatid]['user']:
        chatusertoken.append(userinfo('id',chatuser['id'],True)['Token'])
    if not(token in chatusertoken):
        return apireturn(403,msgIP,None)
    
    return apireturn(200,msgSC,{'chatid':chats[chatid]['user']})

@app.route('/api/chat/<int:chatid>/chat/send',methods=['POST','GET'])
# 发送聊天信息
def api_chat_chat_send(chatid):
    # 检查房间编号
    if not (chatid in chatidlist):
        return apireturn(404,msgUR,None)
    
    # 获取字段
    try :
        requestbody: dict = {key: str(value) for key, value in json.loads(request.data).items()}
    except Exception as e:
        return apireturn(400,msgUP+'error body',None)
    token = requestbody.get('token')
    if not token:
        return apireturn(400,msgMF+'token',None)
    type = requestbody.get('type','0')
    
    # 检查token
    if not Verify_token(token) :
        return apireturn(401,msgEF + 'token',None)
    
    # 检查是否在房间内
    chatusertoken = []
    for chatuser in chats[chatid]['user']:
        chatusertoken.append(userinfo('id',chatuser['id'],True)['Token'])
    if not(token in chatusertoken):
        return apireturn(403,msgIP,None)
    
    # 普通消息
    if type == '0':
        message = requestbody.get('message')
        if not message:
            return apireturn(400,msgMF+'message',None)
        
        chats[chatid]['chat'].append({'type':'0','sender':userinfo('Token',token,True)['id'],'time':time.time(),'content':{'text':message},'id':msgid() })
    # 引用消息
    elif type == '1':
        # 获取字段
        try :
            requestbody: dict = {key: str(value) for key, value in json.loads(request.data).items()}
        except Exception as e:
            return apireturn(500,msgSE,None)
        citation = requestbody.get('citation')
        if not citation:
            return apireturn(400,msgMF+'citation',None)
        message = requestbody.get('message')
        if not message:
            return apireturn(400,msgMF+'message',None)
        
        # 检查引用是否正确
        flag = False
        for msg in chats[chatid]['chat']:
            if msg['id'] == citation:
                if msg['type'] == '-1':
                    return apireturn(400,msgUP+'Unquotable message',None)
                flag = True
                break
        if not flag:
            return apireturn(400,msgEF+'citation',None)
        
        chats[chatid]['chat'].append({'type':'1','sender':userinfo('Token',token,True)['id'],'time':time.time(),'content':{'text':message,'citation':citation},'id':msgid() })
    # 文件消息
    elif type == '2':
        return apireturn(400,msgUP+'This API has been deprecated, please switch to the new API:/api/chat/<chatid>/file/send',None)
    # 自定义消息
    elif type == '3':
        # 检查规则
        if not chatrules(chatid,'SentCustomMessage'):
            return apireturn(403,msgUP+'The SentCustomMessage rule is prohibited.',None)
        
        # 获取body并判断是否为空
        body: dict = request.get_json()
        if body == None :
            return apireturn(400,msgUP+'Empty body',None)
        
        # 添加消息
        chats[chatid]['chat'].append({'type':'3','sender':userinfo('Token',token,True)['id'],'time':time.time(),'content':body,'id':msgid() })
    else :
        return apireturn(400,msgEF+'type',None)

    save_chat_data()

    return apireturn(200,msgSC,None)

@app.route('/api/chat/<int:chatid>/chat/get',methods=['POST','GET'])
# 获取聊天信息
def api_chat_chat_get(chatid):
    # 检查房间编号
    if not (chatid in chatidlist):
        return apireturn(404,msgUR,None)
    
    # 获取字段
    try :
        requestbody: dict = {key: str(value) for key, value in json.loads(request.data).items()}
    except Exception as e:
        return apireturn(400,msgUP+'error body',None)
    token = requestbody.get('token')
    tokensha256 = requestbody.get('tokensha256')
    if (not token) and (not tokensha256):
        return apireturn(400,msgMF + 'token',None)
    starttime = requestbody.get('starttime',None)
    overtime = requestbody.get('overtime',None)
    token = sha256text(token) if token else tokensha256
    
    # 检查token
    if not Verify_token(token) :
        return apireturn(401,msgEF + 'token',None)
    
    # 检查是否在房间内
    chatusertoken = []
    for chatuser in chats[chatid]['user']:
        chatusertoken.append(userinfo('id',chatuser['id'],True)['Token'])
    if not(token in chatusertoken):
        return apireturn(403,msgIP,None)
    
    # 用户最开始进入房间时间
    for user in chats[chatid]['user']:
        if user['id'] == userinfo('token',token,False)['id']:
            jointime = user['jointime']
    
    # 遍历聊天信息
    chatlist = []
    for msg in chats[chatid]['chat']:
        if (starttime == None or chats[chatid]['chat']['time'] >= starttime) and (overtime == None or chats[chatid]['chat']['time'] <= overtime) and chats[chatid]['chat']['time'] >= jointime:
            chatlist.append(msg)

    return apireturn(200,msgSC,{'content':chatlist})

@app.route('/api/chat/<int:chatid>/chat/retract',methods=['POST','GET'])
# 撤销自己的聊天信息
def api_chat_chat_retract(chatid):
    
    # 检查房间编号
    if not (chatid in chatidlist):
        return apireturn(404,msgUR,None)
    
    # 获取字段
    try :
        requestbody: dict = {key: str(value) for key, value in json.loads(request.data).items()}
    except Exception as e:
        return apireturn(400,msgUP+'error body',None)
    token = requestbody.get('token')
    tokensha256 = requestbody.get('tokensha256')
    if (not token) and (not tokensha256):
        return apireturn(400,msgMF + 'token',None)
    msgid = requestbody.get('msgid',0)
    if not msgid:
        return apireturn(400,msgMF + 'msgid',None)
    token = sha256text(token) if token else tokensha256
    
    # 检查token
    if not Verify_token(token) :
        return apireturn(401,msgEF + 'token',None)
    
    # 检查是否在房间内
    chatusertoken = []
    for chatuser in chats[chatid]['user']:
        chatusertoken.append(userinfo('id',chatuser['id'],True)['Token'])
    if not(token in chatusertoken):
        return apireturn(403,msgIP,None)
    
    # 检查id和令牌是否正确
    flag = False
    for msg in chats[chatid]['chat']:
        if not(msg['type'] == '-1') :
            if msg['id'] == msgid:
                # 验证token
                if not(userinfo('id',msg['content']['sender'],True)['Token'] == token):
                    return apireturn(403,msgIP,None)
                flag = True
                index = chats[chatid]['chat'].index(msg)
                break
    if not flag:
        return apireturn(400,msgEF+'msgid',None)
    
    # 检查消息是否已过期
    if (time.time() - msg['time']) > config['MESSAGE_RETRACT_TIME']:
        return apireturn(406,msgUP+'The sent time has passed too long.',None)
    
    # 替换为提示信息
    chats[chatid]['chat'][index] = {'type':'-1','tiptype':'retract','user':userinfo('Token',token,False)['id']}
    save_chat_data()
    
    return apireturn(200,msgSC,None)

@app.route('/api/chat/<int:chatid>/file/send/',methods=['POST','GET'])
# 发送文件
def api_chat_file_send(chatid):
    # 检查房间编号
    if not (chatid in chatidlist):
        return apireturn(404,msgUR,None)
    
    # 获取字段
    try :
        requestbody: dict = {key: str(value) for key, value in json.loads(request.data).items()}
    except Exception as e:
        return apireturn(400,msgUP+'error body',None)
    token = requestbody.get('token')
    if not token:
        return apireturn(400,msgMF+'token',None)
    
    # 检查token
    if not Verify_token(token) :
        return apireturn(401,msgEF + 'token',None)
    
    # 检查是否在房间内
    chatusertoken = []
    for chatuser in chats[chatid]['user']:
        chatusertoken.append(userinfo('id',chatuser['id'],True)['Token'])
    if not(token in chatusertoken):
        return apireturn(403,msgIP,None)
    
    # 获取上传的文件对象
    uploaded_file = request.files.get('file')
    if not uploaded_file:
        return apireturn(400, msgMF + 'file', None)
    if uploaded_file.filename == '':
        return apireturn(400, msgMF + 'filename', None)
    
    def save_uploaded_file(uploaded_file, chat_id):
        # 生成保存目录
        base_storage_dir = 'files'
        os.makedirs(base_storage_dir, exist_ok=True)
        chat_storage_dir = os.path.join(base_storage_dir, chat_id)
        os.makedirs(chat_storage_dir, exist_ok=True)

        # 生成存储路径
        file_content = uploaded_file.read()
        stored_file_name = hashlib.sha256(file_content[1:100]+str(time.time())).hexdigest()
        stored_file_path = os.path.join(chat_storage_dir, stored_file_name)

        # 保存文件
        uploaded_file.seek(0) # 将文件指针转到开头
        uploaded_file.save(stored_file_path)

        return {
            'fileid': stored_file_name,          
            'name': uploaded_file.filename
            }

    filedata = save_uploaded_file(uploaded_file, chatid)

    # 添加信息
    chats[chatid]['chat'].append({'type':'2','sender':userinfo('Token',token,False)['id'],'time':time.time(),'content':filedata,'id':sha256text(str(int(time.time()))+str(random.randint(0,9999))) })

    save_chat_data()

    return apireturn(200,msgSC,None)

@app.route('/api/chat/<int:chatid>/file/get',methods=['POST','GET'])
# 获取文件
def api_chat_file_get(chatid):
    # 检查房间编号
    if not (chatid in chatidlist):
        return apireturn(404,msgUR,None)
    
    # 获取字段
    try :
        requestbody: dict = {key: str(value) for key, value in json.loads(request.data).items()}
    except Exception as e:
        return apireturn(400,msgUP+'error body',None)
    token = requestbody.get('token')
    fileid = requestbody.get('fileid',0)
    if not fileid:
        return apireturn(400,msgMF + 'fileid',None)
    
    # 检查token
    if not Verify_token(token) :
        return apireturn(401,msgEF + 'token',None)
    
    # 检查是否在房间内
    chatusertoken = []
    for chatuser in chats[chatid]['user']:
        chatusertoken.append(userinfo('id',chatuser['id'],True)['Token'])
    if not(token in chatusertoken):
        return apireturn(403,msgIP,None)
    
    # 检查文件是否存在
    filepath = "files/"+chatid
    if not os.path.exists(filepath+"/"+fileid):
        return apireturn(404,msgUP+"The fileid is incorrect or the file has been deleted.",None)
    
    # 返回文件
    return send_from_directory(filepath, fileid, as_attachment=True), 200

@app.route('/api/chat/<int:chatid>/level',methods=['POST','GET'])
# 获取自己的等级
def api_chat_level(chatid):
    # 检查房间编号
    if not (chatid in chatidlist):
        return apireturn(404,msgUR,None)
    
    # 获取字段
    try :
        requestbody: dict = {key: str(value) for key, value in json.loads(request.data).items()}
    except Exception as e:
        return apireturn(400,msgUP+'error body',None)
    token = requestbody.get('token')
    tokensha256 = requestbody.get('tokensha256')
    if (not token) and (not tokensha256):
        return apireturn(400,msgMF + 'token',None)
    token = sha256text(token) if token else tokensha256
    
    # 检查token
    if not Verify_token(token) :
        return apireturn(401,msgEF + 'token',None)
    
    # 检查是否在房间内
    chatusertoken = []
    for chatuser in chats[chatid]['user']:
        chatusertoken.append(userinfo('id',chatuser['id'],True)['Token'])
    if not(token in chatusertoken):
        return apireturn(403,msgIP,None)
    
    # 获取等级
    for chatuser in chats[chatid]['user']:
        if chatuser['id'] == userinfo('Token',token,False)['id']:
            level = chatuser['level']
    
    return apireturn(200,msgSC,{'level':level})

@app.route('/api/chat/<int:chatid>/level/set',methods=['POST','GET'])
# 设置用户等级
def api_chat_level_set(chatid):
    # 检查房间编号
    if not (chatid in chatidlist):
        return apireturn(404,msgUR,None)
    
    # 获取字段
    try :
        requestbody: dict = {key: str(value) for key, value in json.loads(request.data).items()}
    except Exception as e:
        return apireturn(400,msgUP+'error body',None)
    token = requestbody.get('token')
    tokensha256 = requestbody.get('tokensha256')
    if (not token) and (not tokensha256):
        return apireturn(400,msgMF + 'token',None)
    userid = requestbody.get('userid',0)
    if not userid:
        return apireturn(400,msgMF + 'userid',None)
    level = requestbody.get('level',0)
    if not level:
        return apireturn(400,msgMF + 'level',None)
    token = sha256text(token) if token else tokensha256

    # 检查等级是否正确
    if not(isinstance(leveltonumber(level),int) or (isinstance(level,int) and -1<level<3)):
        return apireturn(400,msgEF + 'level',None)
    
    # 检查token
    if not Verify_token(token) :
        return apireturn(401,msgEF + 'token',None)
    
    # 检查是否在房间内
    chatusertoken = []
    for chatuser in chats[chatid]['user']:
        chatusertoken.append(userinfo('id',chatuser['id'],True)['Token'])
    if not(token in chatusertoken):
        return apireturn(403,msgIP,None)
    
    # 检查是否有权限
    index = chatusertoken.index[token]
    if not(leveltonumber(chats[chatid]['user'][index]['level']) > 0):
        return apireturn(403,msgIP,None)
    
    # 检查对方是否在房间内
    flag = False
    for chatuser in chats[chatid]['user']:
        if chatuser['id'] == userid:
            # 检查是不是自己
            if userinfo('id',chatuser['id'],True)['Token'] == token:
                return apireturn(400,msgUP + 'Cannot change your own level.',None)
            flag = True
            # 修改对方等级
            chatuser['level'] = level

            # 添加消息
            content =  {'tiptype':'levelset','user':userinfo('Token',token,False)['id'],'passively':chatuser['id'],'level':level}
            chats[chatid]['chat'].append({'type':'-1','time':time.time(),'content':content,'id':msgid() })
    if not flag :
        return apireturn(401,msgEF + 'userid',None)
    
    return apireturn(200,msgSC,None)

if __name__ == '__main__':
    initialize()
    app.run(debug=True)