from flask import Blueprint
from definition import db, apireturn, apilog, getbody, msg_type, Verify_token, User, timestamp, config, db, Chat, time, Token, pyotp, make_response


app = Blueprint('user', __name__)

# 用户类
@app.route('/api/user/register',methods=['POST'], endpoint='api_user_register')
@apilog
@getbody('user','name','password')
# 注册用户
def api_user_register(user,name,password):
    if not user:
        return apireturn(400,msg_type.MF+'user',None)
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
@getbody('user','password','otpcode')
# 登录用户
def api_user_login(user,password,otpcode):
    
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
@getbody('user','token')
# 获取用户信息
def api_user_info(user,token):
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
@getbody('token')
# 获取用户已加入聊天的信息
def api_user_joinchat(token):
    # 检查字段
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
@getbody('token')
# 刷新令牌
def api_user_refreshtoken(token):
    # 检查字段
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
@getbody('token','img')
# 生成OTP密钥
def api_user_otp_generated(token,img):
    # 检查字段
    if not token:
        return apireturn(400,msg_type.MF+'token',None)
    
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
@getbody('token','otpcode')
# 验证OTP密钥
def api_user_otp_verify(token,otpcode):
    # 检查字段
    if not token:
        return apireturn(400,msg_type.MF+'token',None)
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
@getbody('otpcode','token')
# 清除OTP密钥
def api_user_otp_clear(otpcode,token):
    # 检查字段
    if not otpcode:
        return apireturn(400,msg_type.MF+'otpcode',None)
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
