from flask import Flask, request, send_from_directory, make_response
import os
import json
import qrcode
import base64
from io import BytesIO
import random
import hashlib
import string
import time
import pyotp

msgSC = 'Success'# 成功
msgMF = 'Missing field: '# 缺失字段
msgEF = 'Field error: '# 字段错误
msgUC = 'Unknown chat'# 未知聊天
msgIP = 'Insufficient permissions'# 权限不足
msgUP = 'Unable to proceed: ' #无法完成

def initialize():
    global users
    global chats
    global useridlist
    global chatidlist
    global config
    if os.path.exists('log.txt'):
        os.remove('log.txt')
    
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

    useridlist = [user['user'] for user in users]
    chatidlist = [chat['id'] for chat in chats]
        

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
    token = ''.join(random.sample(string.ascii_letters + string.ascii_uppercase + string.digits,k=25))
    while token in list(chats.values()) :
        token = ''.join(random.sample(string.ascii_letters + string.ascii_uppercase + string.digits,k=25))
    
    return token

def msgid() -> str:
    """生成消息编号"""
    return sha256text(str(int(time.time()))+'-'+str(random.randint(0,9999)))

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
                del user_copy['otpkey']
                try:
                    del user_copy['prepared otpkey']
                except:
                    pass
            del user_copy['time']
            return user_copy
    return {}

def chatinfo(chatid) -> dict :
    """获取聊天信息"""
    for chat in list(chats.values()):
        if chat['user'] == str(chatid):
            chat_copy = chat.copy()
            del chat_copy['chat']
            del chat_copy['user']
            del chat_copy['password']
            del chat_copy['setting']
            return chat_copy
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
    try:
        for chatuser in chats[chatid]['user']:
            if chatuser['user'] == user:
                if leveltonumber(chatuser['level']) >= str(level) :
                    return True
                else:
                    return False
    except:
        pass

    return False

def adduser(name,token,user,password):
    """添加用户"""
    users[user] = {'user':user,'name':name,'Token':token,'time':time.time(),'password':password}
    useridlist.append(user)
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
    print(users.values())
    return apireturn(200,msgSC,'chatapihost')

@app.route('/api/user/register',methods=['POST','GET'])
# 注册用户
def api_user_register():
    # 获取字段
    try :
        requestbody: dict = {key: str(value) for key, value in json.loads(request.data).items()}
    except Exception as e:
        return apireturn(400,msgUP+'error body',None)
    user = requestbody.get('user')
    if not user:
        return apireturn(400,msgMF+'user',None)
    name:str = requestbody.get('name',user)
    password = requestbody.get('password')
    if not password:
        return apireturn(400,msgMF+'password',None)

    # 检查用户编号是否违规
    if user.isalnum():
        apireturn(403,msgEF+'user',None)

    # 检查用户编号是否重复
    _useridlist = [user['user'] for user in list(users.values()) ]
    if user in _useridlist:
        apireturn(403,msgUP+'The user is taken',None)

    # 本地存储
    adduser(name,'',user,password) 

    return apireturn(200,msgSC,None)
@app.route('/api/user/login',methods=['POST','GET'])
# 登录用户
def api_user_login():
    # 获取字段
    try :
        requestbody: dict = {key: str(value) for key, value in json.loads(request.data).items()}
    except Exception as e:
        return apireturn(400,msgUP+'error body',None)
    user = requestbody.get('user')
    if not user:
        return apireturn(400,msgMF+'user',None)
    password = requestbody.get('password')
    if not password:
        return apireturn(400,msgMF+'password',None)
    otpcode = requestbody.get('otpcode')
    
    # 检查user
    _userinfo = userinfo('user',user,True)
    if not _userinfo :
        return apireturn(401,msgEF+'user',None)
    
    # 检查密码
    if not (password == _userinfo['password']):
        return apireturn(401,msgEF+'password',None)
    
    # 检查otp
    if 'otpkey' in users[user] and not(users[user]['otpkey']):
        if not pyotp.TOTP(users[user]['otpkey']).verify(otpcode):
            return apireturn(401,msgEF+'otpkey',None)
    
    # 检查是否有token
    if users[user]['Token'] == '':
        # 设置token
        token = Token()

        # 本地存储
        users[user]['Token'] = sha256text(token)
        save_user_data()
    else:
        token = users[user]['Token']

    return apireturn(200,msgSC,{'token':sha256text(token)})
@app.route('/api/user/info',methods=['POST','GET'])
# 获取用户信息
def api_user_info():
    # 获取字段
    try :
        requestbody: dict = {key: str(value) for key, value in json.loads(request.data).items()}
    except Exception as e:
        return apireturn(400,msgUP+'error body',None)
    user = requestbody.get('user')
    if not user:
        return apireturn(400,msgMF+'user',None)
    
    # 检查输入是否正确
    if not(user in users):
        return apireturn(400,msgEF+'user',None)

    # 获取用户信息
    info = userinfo('user',user,False)

    return apireturn(200,msgSC,info)
@app.route('/api/user/joinchat',methods=['POST','GET'])
# 获取用户已加入聊天的信息
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
    if not Verify_token(token) :
        return apireturn(401,msgEF+'token',None)

    # 获取已加入聊天的信息
    user = userinfo('token',token,False)
    joinchat = []
    for chat in list(chats.values()):
        for chatuser in list(chat['user'].values()):
            if chatuser['user'] == user:
                joinchat.append(chatinfo(chat['user']))
                break


    return apireturn(200,msgSC,joinchat)
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
    if not Verify_token(token) :
        return apireturn(401,msgEF+'token',None)
    
    # 设置token
    token = Token()

    # 本地存储
    user = userinfo('Token',token,False)['user']
    users[user]['Token'] = sha256text(token)

    save_user_data()

    return apireturn(200,msgSC,{'token':sha256text(token)})
@app.route('/api/user/otp/generated',methods=['POST','GET'])
# 生成OTP密钥
def api_user_otp_generated():
    # 获取字段
    try :
        requestbody: dict = {key: str(value) for key, value in json.loads(request.data).items()}
    except Exception as e:
        return apireturn(400,msgUP+'error body',None)
    token = requestbody.get('token')
    if not token:
        return apireturn(400,msgMF+'token',None)
    img = requestbody.get('img')
    
    # 检查token
    if not Verify_token(token) :
        return apireturn(401,msgEF+'token',None)
    
    # 检查已有的otp密钥
    if 'otpkey' in userinfo('Token',token,False) :
        return apireturn(401,msgUP+'OTP key already exists',None)
    
    # 生成otp密钥
    if 'prepared otpkey' in userinfo('Token',token,False):
        otpkey = userinfo('Token',token,False)['prepared otpkey']
    else:
        otpkey = pyotp.random_base32()

        # 保存预备密钥
        users[userinfo('Token',token,False)['user']]['prepared otpkey'] = otpkey
        save_user_data()
    
    otp = pyotp.totp.TOTP(otpkey, interval=30, digits=6)
    uri = otp.provisioning_uri(name=userinfo('Token',token,False)['user'], issuer_name='Secure App')

    # 生成二维码dataurl
    if img == 'true' :
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

        resp = make_response(apireturn(200,msgSC,{'key':otpkey,'dataurl':dataurl}))
    else:
        resp = make_response(apireturn(200,msgSC,{'key':otpkey}))

    return resp
@app.route('/api/user/otp/verify',methods=['POST','GET'])
# 验证OTP密钥
def api_user_otp_verify():
    # 获取字段
    try :
        requestbody: dict = {key: str(value) for key, value in json.loads(request.data).items()}
    except Exception as e:
        return apireturn(400,msgUP+'error body',None)
    token = requestbody.get('token')
    if not token:
        return apireturn(400,msgMF+'token',None)
    otpcode = requestbody.get('otpcode')
    if not token:
        return apireturn(400,msgMF+'otpcode',None)
    
    # 检查token
    if not Verify_token(token) :
        return apireturn(401,msgEF+'token',None)
    
    # 检查是否无预备密钥
    if 'prepared otpkey' not in userinfo('Token',token,False) :
        return apireturn(401,msgUP+'There is currently no otpkey',None)
    
    # 检查代码
    otp = pyotp.totp.TOTP(userinfo('Token',token,False)['prepared otpkey'])
    print(otp.now())
    if not otp.verify(int(otpcode)):
        return apireturn(401,msgEF+'otpcode',None)
    
    # 设置密钥
    users[userinfo('Token',token,False)['user']]['otpkey'] = users[userinfo('Token',token,False)['user']]['prepared otpkey']
    del users[userinfo('Token',token,False)['user']]['prepared otpkey']
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
    otpcode = requestbody.get('otpcode')
    if not otpcode:
        return apireturn(400,msgMF+'otpcode',None)
    token = requestbody.get('token')
    if not token:
        return apireturn(400,msgMF+'token',None)
    
    # 检查token
    if not Verify_token(token) :
        return apireturn(401,msgEF+'token',None)
    
    # 检查是否有otp密钥
    if 'otpkey' not in userinfo('Token',token,False) :
        return apireturn(304,msgUP+'There is currently no OTP keys',None)
    
    # 检查是否与密钥一样
    if pyotp.totp.TOTP(userinfo('Token',token,False)['otpkey']).now() == otpcode:
        return apireturn(304,msgEF+'otpcode',None)
    
    # 删除密钥
    del users[userinfo('Token',token,False)['user']]['otpkey']
    save_user_data()

    return apireturn(200,msgSC,None)
# 聊天类接口
@app.route('/api/chat/add',methods=['POST','GET'])
# 添加聊天
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

@app.route('/api/chat/join',methods=['POST','GET'])
# 加入聊天
def api_chat_join():
    
    # 获取字段
    try :
        requestbody: dict = {key: str(value) for key, value in json.loads(request.data).items()}
    except Exception as e:
        return apireturn(400,msgUP+'error body',None)
    password = requestbody.get('password')
    chatid = sha256text(requestbody.get('chatid'))
    if not chatid:
        return apireturn(400,msgMF+'chatid',None)
    token = requestbody.get('token')
    if not token:
        return apireturn(400,msgMF+'token',None)
    
    # 检查token
    if not Verify_token(token) :
        return apireturn(401,msgEF+'token',None)
    
    # 检查聊天密码
    if (not chats[chatid]['password']) and (chats[chatid]['password'] == password) :
        return apireturn(401,msgEF+'password',None)
    
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
            'user':userinfo('Token',token,False)['user']
        } 
    })
    

    save_chat_data()

    return apireturn(200,msgSC,None)
@app.route('/api/chat/<int:chatid>/user/list',methods=['POST','GET'])
# 用户列表
def api_chat_user_list(chatid):
    # 检查聊天编号
    if not (chatid in chatidlist):
        return apireturn(404,msgUC,None)
    
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
    
    # 检查是否在聊天内
    chatusertoken = [userinfo('user',chatuser['user'],True)['Token'] for chatuser in chats[chatid]['user']]
    if not(token in chatusertoken):
        return apireturn(403,msgIP,None)
    
    return apireturn(200,msgSC,chats[chatid]['user'])

@app.route('/api/chat/<int:chatid>/chat/send',methods=['POST','GET'])
# 发送聊天信息
def api_chat_chat_send(chatid):
    # 检查聊天编号
    if not (chatid in chatidlist):
        return apireturn(404,msgUC,None)
    
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
    
    # 检查是否有权限
    if userlevel(chatid, userinfo('token',token,False)['user'], 1):
        return apireturn(403,msgIP,None)
    
    # 检查是否在聊天内
    chatusertoken = [userinfo('user',chatuser['user'],True)['Token'] for chatuser in chats[chatid]['user']]
    if not(token in chatusertoken):
        return apireturn(403,msgIP,None)
    
    # 普通消息
    if type == '0':
        message = requestbody.get('message')
        if not message:
            return apireturn(400,msgMF+'message',None)
        
        chats[chatid]['chat'].append({'type':'0','sender':userinfo('Token',token,True)['user'],'time':time.time(),'content':{'text':message},'id':msgid() })
    # 引用消息
    elif type == '1':
        # 获取字段
        try :
            requestbody: dict = {key: str(value) for key, value in json.loads(request.data).items()}
        except Exception as e:
            return apireturn(400,msgUP+'error body',None)
        citation = requestbody.get('citation')
        if not citation:
            return apireturn(400,msgMF+'citation',None)
        message = requestbody.get('message')
        if not message:
            return apireturn(400,msgMF+'message',None)
        
        # 检查引用是否正确
        flag = False
        for msg in chats[chatid]['chat']:
            if msg['user'] == citation:
                if msg['type'] == '-1':
                    return apireturn(400,msgUP+'Unquotable message',None)
                flag = True
                break
        if not flag:
            return apireturn(400,msgEF+'citation',None)
        
        chats[chatid]['chat'].append({'type':'1','sender':userinfo('Token',token,True)['user'],'time':time.time(),'content':{'text':message,'citation':citation},'id':msgid() })
    # 文件消息
    elif type == '2':
        # 获取上传的文件对象
        uploaded_file = requestbody.get('file')
        if not uploaded_file:
            return apireturn(400, msgMF + 'file', None)
        
        def save_uploaded_file(uploaded_file, chat_id):
            # 生成保存目录
            base_storage_dir = 'files'
            os.makedirs(base_storage_dir, exist_ok=True)
            chat_storage_dir = os.path.join(base_storage_dir, chat_id)
            os.makedirs(chat_storage_dir, exist_ok=True)

            # 生成存储路径
            file_content = uploaded_file.read()
            stored_file_name = hashlib.sha256(file_content[0:100]+str(time.time())).hexdigest()
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
        chats[chatid]['chat'].append({'type':'2','sender':userinfo('Token',token,False)['user'],'time':time.time(),'content':filedata,'id':sha256text(str(int(time.time()))+str(random.randint(0,9999))) })
    else :
        return apireturn(400,msgEF+'type',None)

    save_chat_data()

    return apireturn(200,msgSC,None)

@app.route('/api/chat/<int:chatid>/chat/get',methods=['POST','GET'])
# 获取聊天信息
def api_chat_chat_get(chatid):
    # 检查聊天编号
    if not (chatid in chatidlist):
        return apireturn(404,msgUC,None)
    
    # 获取字段
    try :
        requestbody: dict = {key: str(value) for key, value in json.loads(request.data).items()}
    except Exception as e:
        return apireturn(400,msgUP+'error body',None)
    token = requestbody.get('token')
    if token:
        return apireturn(400,msgMF + 'token',None)
    starttime = requestbody.get('starttime',None)
    overtime = requestbody.get('overtime',None)
    
    # 检查token
    if not Verify_token(token) :
        return apireturn(401,msgEF + 'token',None)
    
    # 检查是否在聊天内
    chatusertoken = [userinfo('user',chatuser['user'],True)['Token'] for chatuser in chats[chatid]['user']]
    if not(token in chatusertoken):
        return apireturn(403,msgIP,None)
    
    # 用户最开始进入聊天时间
    for user in chats[chatid]['user']:
        if user['user'] == userinfo('token',token,False)['user']:
            jointime = user['jointime']
    
    # 遍历聊天信息
    chatlist = []
    for msg in chats[chatid]['chat']:
        if (starttime == None or chats[chatid]['chat']['time'] >= starttime) and (overtime == None or chats[chatid]['chat']['time'] <= overtime) and chats[chatid]['chat']['time'] >= jointime:
            chatlist.append(msg)

    return apireturn(200,msgSC,chatlist)

@app.route('/api/chat/<int:chatid>/chat/getfile',methods=['POST','GET'])
# 获取文件
def api_chat_file_get(chatid):
    # 检查聊天编号
    if not (chatid in chatidlist):
        return apireturn(404,msgUC,None)
    
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
    
    # 检查是否在聊天内
    chatusertoken = [userinfo('user',chatuser['user'],True)['Token'] for chatuser in chats[chatid]['user']]
    if not(token in chatusertoken):
        return apireturn(403,msgIP,None)
    
    # 检查文件是否存在
    filepath = "files/"+chatid
    if not os.path.exists(filepath+"/"+fileid):
        return apireturn(404,msgUP+"The fileid is incorrect or the file has been deleted.",None)
    
    # 返回文件
    return send_from_directory(filepath, fileid, as_attachment=True), 200

@app.route('/api/chat/<int:chatid>/chat/retract',methods=['POST','GET'])
# 撤销自己的聊天信息
def api_chat_chat_retract(chatid):
    
    # 检查聊天编号
    if not (chatid in chatidlist):
        return apireturn(404,msgUC,None)
    
    # 获取字段
    try :
        requestbody: dict = {key: str(value) for key, value in json.loads(request.data).items()}
    except Exception as e:
        return apireturn(400,msgUP+'error body',None)
    token = requestbody.get('token')
    if not token:
        return apireturn(400,msgMF + 'token',None)
    msgid = requestbody.get('msgid',0)
    if not msgid:
        return apireturn(400,msgMF + 'msgid',None)
    
    # 检查token
    if not Verify_token(token) :
        return apireturn(401,msgEF + 'token',None)
    
    # 检查是否有权限
    if userlevel(chatid, userinfo('token',token,False)['user'], 1):
        return apireturn(403,msgIP,None)
    
    # 检查是否在聊天内
    chatusertoken = [userinfo('user',chatuser['user'],True)['Token'] for chatuser in chats[chatid]['user']]
    if not(token in chatusertoken):
        return apireturn(403,msgIP,None)
    
    # 检查id和令牌是否正确
    flag = False
    for msg in chats[chatid]['chat']:
        if not(msg['type'] == '-1') :
            if msg['user'] == msgid:
                # 验证token
                if not(userinfo('user',msg['content']['sender'],True)['Token'] == token) and not userlevel(chatid, userinfo('token',token,False)['user'], 2):
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
    chats[chatid]['chat'][index]['type'] = '-1'
    chats[chatid]['chat'][index]['content'] = {'tiptype':'retract','user':userinfo('Token',token,False)['user']}
    del chats[chatid]['chat'][index]['sender']
    save_chat_data()
    
    return apireturn(200,msgSC,None)

@app.route('/api/chat/<int:chatid>/level/set',methods=['POST','GET'])
# 设置用户等级
def api_chat_level_set(chatid):
    # 检查聊天编号
    if not (chatid in chatidlist):
        return apireturn(404,msgUC,None)
    
    # 获取字段
    try :
        requestbody: dict = {key: str(value) for key, value in json.loads(request.data).items()}
    except Exception as e:
        return apireturn(400,msgUP+'error body',None)
    token = requestbody.get('token')
    if not token:
        return apireturn(400,msgMF + 'token',None)
    user = requestbody.get('user',0)
    if not user:
        return apireturn(400,msgMF + 'user',None)
    level = requestbody.get('level',0)
    if not level:
        return apireturn(400,msgMF + 'level',None)

    # 检查等级是否正确
    if not(isinstance(leveltonumber(level),int) or (isinstance(level,int) and -1<level<3)):
        return apireturn(400,msgEF + 'level',None)
    
    # 检查token
    if not Verify_token(token) :
        return apireturn(401,msgEF + 'token',None)
    
    # 检查是否在聊天内
    chatusertoken = [userinfo('user',chatuser['user'],True)['Token'] for chatuser in chats[chatid]['user']]
    if not(token in chatusertoken):
        return apireturn(403,msgIP,None)
    
    # 检查是否有权限
    if userlevel(chatid, user, 2):
        return apireturn(403,msgIP,None)
    
    # 检查对方是否在聊天内
    flag = False
    for chatuser in chats[chatid]['user']:
        if chatuser['user'] == user:
            # 检查是不是自己
            if userinfo('user',chatuser['user'],True)['Token'] == token:
                return apireturn(400,msgUP + 'Cannot change your own level.',None)
            flag = True

            # 检查是否要修改成房主
            if level == '3':
                return apireturn(400,msgUP + 'cannot be modified to owner.',None)

            # 检查等级高低
            if userlevel(chatid, user, chatuser['level']):
                return apireturn(400,msgUP + 'cannot modify users with high permissions',None)

            # 修改对方等级
            chatuser['level'] = level

            # 添加消息
            content =  {'tiptype':'levelset','user':userinfo('Token',token,False)['user'],'reactive':chatuser['user'],'level':level}
            chats[chatid]['chat'].append({'type':'-1','time':time.time(),'content':content,'id':msgid() })
    if not flag :
        return apireturn(401,msgEF + 'user',None)
    
    return apireturn(200,msgSC,None)

if __name__ == '__main__':
    initialize()
    app.run(debug=True)