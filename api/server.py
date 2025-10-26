from flask import Blueprint
from main import *

app = Blueprint('server', __name__)

# 服务器类
@app.route('/api/serve/anncmnt',methods=['POST','GET'], endpoint='api_serve_anncmnt')
@apilog
# 服务器公告
def api_serve_anncmnt():
    return apireturn(200,msg_type.SC,{'anncmnt':config.get('ANNCMNT',None)})
@app.route('/api/serve/name',methods=['POST','GET'], endpoint='api_serve_name')
@apilog
# 服务器公告
def api_serve_name():
    return apireturn(200,msg_type.SC,{'name':config.get('SERVER_NAME',None)})
