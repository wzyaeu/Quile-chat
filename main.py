import os
import logging
from logging.handlers import RotatingFileHandler
from waitress import serve
from colorama import Style, Fore
from definition import app, config, VERSION

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

def initialize():
    global app
    global logging
    
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

    app.config['MAX_CONTENT_LENGTH'] = (1024 ^ config['MAX_CONTENT_LENGTH']['unit']) * config['MAX_CONTENT_LENGTH']['quantity']

    os.system('cls')
    import pyfiglet
    print(Fore.CYAN+pyfiglet.figlet_format("Q u i l e  C h a t", font="standard"))
    
    server_info = {'服务器端口':Fore.LIGHTBLUE_EX+str(config['SERVER_PORT']),
                   '服务器版本':Fore.CYAN+VERSION+Style.RESET_ALL}
    print_list(server_info,title='服务器信息')
    print_list(config,title='配置文件')
    print(Style.RESET_ALL+'按下'+Fore.CYAN+'Ctrl+c'+Style.RESET_ALL+'关闭')

if __name__ == '__main__':
    initialize()
    
    from api.api import app as api_bp
    from api.server import app as server_bp
    from api.user import app as user_bp
    from api.friend import app as friend_bp
    from api.chat import app as chat_bp

    app.register_blueprint(api_bp)
    app.register_blueprint(server_bp)
    app.register_blueprint(user_bp)
    app.register_blueprint(friend_bp)
    app.register_blueprint(chat_bp)

    serve(app, host=config['SERVER_HOST'], port=config['SERVER_PORT'])