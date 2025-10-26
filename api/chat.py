from flask import Blueprint, send_from_directory
from main import *

app = Blueprint('chat', __name__)

# 聊天类
@app.route('/api/chat/add',methods=['POST'], endpoint='api_chat_add')
@apilog
@getbody('name','password','token','friend')
# 添加聊天
def api_chat_add(name,password,token,friend):
    # 检查字段
    if not name:
        return apireturn(400,msg_type.MF+'name',None)
    if not token:
        return apireturn(400,msg_type.MF+'token',None)
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
@getbody('token')
# 获取聊天信息
def api_chat_info(chatid,token):
    # 检查字段
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
@getbody('password','chatid','token')
# 加入聊天
def api_chat_join(password,chatid,token):
    # 检查字段
    if not chatid:
        return apireturn(400,msg_type.MF+'chatid',None)
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
@getbody('token')
# 用户列表
def api_chat_user_list(chatid,token):
    # 检查聊天编号
    chat = Chat.query.filter_by(id=str(chatid)).first()
    if not chat:
        return apireturn(404,msg_type.UC,None)
    
    # 检查字段
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
@getbody('token','type','message','citation')
# 发送聊天信息
def api_chat_chat_send(chatid,token,type,**kwargs):
    # 检查聊天编号
    chat = Chat.query.filter_by(id=chatid).first()
    if not chat:
        return apireturn(404,msg_type.UC,None)
    
    # 检查字段
    if not token:
        return apireturn(400,msg_type.MF+'token',None)
    
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
        return chat_send_0(token,chatid,**kwargs)
    # 引用消息
    elif type == '1':
        return chat_send_1(token,chatid,**kwargs)
    # 文件消息
    elif type == '2':
        return chat_send_2(token,chatid,file=request.files.get('file'))
    else :
        return apireturn(400,msg_type.EF+'type',None)

def chat_send_0(token,chatid,message):
    # 检查字段
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

    return apireturn(200,msg_type.SC,None)

def chat_send_1(token,chatid,message,citation):
    if not citation:
        return apireturn(400,msg_type.MF+'citation',None)
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

    return apireturn(200,msg_type.SC,None)

def chat_send_2(file,token,chatid):
    # 获取上传的文件对象
    if not file:
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
            'name': uploaded_file.filename,
            'text': f'文件 {uploaded_file.filename}'
        }

    filedata = save_uploaded_file(file, chatid)

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

    return apireturn(200,msg_type.SC,None)

@app.route('/api/chat/<int:chatid>/chat/get',methods=['POST'], endpoint='api_chat_chat_get')
@apilog
@getbody('token','starttime','overtime','count','removal_count')
# 获取聊天信息
def api_chat_chat_get(chatid,token,starttime,overtime,count,removal_count):
    # 检查聊天编号
    chat = Chat.query.filter_by(id=chatid).first()
    if not chat:
        return apireturn(404,msg_type.UC,None)
    
    # 检查字段
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
    
    if count:
        if type(count) == int:
            if removal_count:
                if type(removal_count) == int:
                    chatlist = chat.chat[-count:][:-removal_count]
                else: return apireturn(401,msg_type.EF + 'removal_count, need int',None)
            chatlist = chat.chat[-count:]
        else: return apireturn(401,msg_type.EF + 'count, need int',None)
    else:
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

    return apireturn(200,msg_type.SC,{'chatlist':chatlist})

@app.route('/api/chat/<int:chatid>/chat/getfile',methods=['POST'], endpoint='api_chat_file_get')
@apilog
@getbody('token','fileid')
# 获取文件
def api_chat_file_get(chatid,token,fileid):
    # 检查聊天编号
    chat = Chat.query.filter_by(id=str(chatid)).first()
    if not chat:
        return apireturn(404,msg_type.UC,None)
    
    # 检查字段
    if not token:
        return apireturn(400,msg_type.MF + 'token',None)
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
@getbody('token','msgid')
# 撤销聊天信息
def api_chat_chat_retract(chatid,token,msgid):
    # 检查聊天编号
    chat = Chat.query.filter_by(id=chatid).first()
    if not chat:
        return apireturn(404,msg_type.UC,None)
    
    # 检查字段
    if not token:
        return apireturn(400,msg_type.MF + 'token',None)
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
@getbody('token','user','level')
# 设置用户等级
def api_chat_level_set(chatid,token,user,level):
    # 检查聊天编号
    chat = Chat.query.filter_by(id=chatid).first()
    if not chat:
        return apireturn(404,msg_type.UC,None)
    
    # 检查是否为群聊
    if chat.type != chat_type.group:
        return apireturn(404,msg_type.UP+'need a group',None)
    
    # 检查字段
    if not token:
        return apireturn(400,msg_type.MF + 'token',None)
    if not user:
        return apireturn(400,msg_type.MF + 'user',None)
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
@getbody('token')
# 查看公告
def api_chat_anncmnt(chatid,token):
    # 检查聊天编号
    chat = Chat.query.filter_by(id=chatid).first()
    if not chat:
        return apireturn(404,msg_type.UC,None)
    
    # 检查是否为群聊
    if chat.type != chat_type.group:
        return apireturn(404,msg_type.UP+'need a group',None)
    
    # 检查字段
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
@getbody('token','title','content')
# 增加公告
def api_chat_anncmnt_add(chatid,token,title,content):
    # 检查聊天编号
    chat = Chat.query.filter_by(id=str(chatid)).first()
    if not chat:
        return apireturn(404,msg_type.UC,None)
    
    # 检查是否为群聊
    if chat.type != chat_type.group:
        return apireturn(404,msg_type.UP+'need a group',None)
    
    # 检查字段
    if not token:
        return apireturn(400,msg_type.MF + 'token',None)
    if not title:
        return apireturn(400,msg_type.MF + 'title',None)
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
@getbody('token','mid','title','content')
# 更改公告
def api_chat_anncmnt_modify(chatid,token,mid,title,content):
    # 检查聊天编号
    chat = Chat.query.filter_by(id=str(chatid)).first()
    if not chat:
        return apireturn(404,msg_type.UC,None)
    
    # 检查是否为群聊
    if chat.type != chat_type.group:
        return apireturn(404,msg_type.UP+'need a group',None)
    
    # 检查字段
    if not token:
        return apireturn(400,msg_type.MF + 'token',None)
    if not mid:
        return apireturn(400,msg_type.MF + 'id',None)
    if not title:
        return apireturn(400,msg_type.MF + 'title',None)
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
                try: base64.b64encode(content.encode('utf-8'))
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
@getbody('token','mid')
# 删除公告
def api_chat_anncmnt_del(chatid,token,mid):
    # 检查聊天编号
    chat = Chat.query.filter_by(id=str(chatid)).first()
    if not chat:
        return apireturn(404,msg_type.UC,None)
    
    # 检查是否为群聊
    if chat.type != chat_type.group:
        return apireturn(404,msg_type.UP+'need a group',None)
    
    # 检查字段
    if not token:
        return apireturn(400,msg_type.MF + 'token',None)
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
