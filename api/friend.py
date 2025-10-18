from flask import Blueprint
from definition import apilog, getbody, apireturn, msg_type, Verify_token, User, timestamp, config, db, Chat, random, addchat, chat_type

app = Blueprint('friend', __name__)

# 好友类接口
@app.route('/api/friend/add',methods=['POST'], endpoint='api_friend_add')
@apilog
@getbody('user','token')
# 申请添加好友
def api_friend_add(user,token):
    # 检查字段
    if not user:
        return apireturn(400,msg_type.MF+'user',None)
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
    
    # 检查申请getbody
    if current_user.id in target_user.friend_application:
        if timestamp() - target_user.friend_application[current_user.id]['time'] < config['FRIEND_REQUST_TIME']:
            return apireturn(401,msg_type.UP+'has already applied',None)
    
    # 发送申请
    target_user.friend_application[current_user.id] = {'user': current_user.id, 'time': timestamp()}
    db.session.commit()

    return apireturn(200,msg_type.SC,None)

@app.route('/api/friend/agree',methods=['POST'], endpoint='api_friend_agree')
@apilog
@getbody('user','token')
# 同意添加好友
def api_friend_agree(user,token):
    # 检查字段
    if not user:
        return apireturn(400,msg_type.MF+'user',None)
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
@getbody('token')
# 好友黑名单查看
def api_friend_blacklist(token):
    # 检查字段
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
@getbody('user','token')
# 好友黑名单添加
def api_friend_blacklist_add(user,token):
    # 检查字段
    if not user:
        return apireturn(400,msg_type.MF+'user',None)
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
@getbody('user','token')
# 好友黑名单删除
def api_friend_blacklist_del(user,token):
    # 检查字段
    if not user:
        return apireturn(400,msg_type.MF+'user',None)
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
