from definition import apilog, apireturn, msg_type, time, Blueprint, VERSION

app = Blueprint('api', __name__)

# API
@app.errorhandler(404)
def error(error):
    return apireturn(int(error.code),str(error),None)

@app.route('/api',methods=['POST','GET'], endpoint='api')
# 测试连通性
@apilog
def api():
    return apireturn(200,msg_type.SC,{'host':'chatapihost','version':VERSION,'time':time.time()})