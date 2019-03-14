import os
from threading import Thread
from datetime import datetime
from sh.contrib import git

from flask import *
from flask_bootstrap import Bootstrap
from flask_talisman import Talisman
from flask_moment import Moment
from flask_wtf import FlaskForm
from wtforms import *
from sqlalchemy.sql.expression import func
from wtforms.validators import *
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_required, fresh_login_required, login_user, login_fresh, login_url, LoginManager, \
    UserMixin, logout_user, current_user
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from cas_client import *

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

basedir = os.path.dirname(os.path.abspath(__file__))

app = Flask(__name__)
Talisman(app, content_security_policy={
    'default-src': "*",
    'style-src': "'self' http://* 'unsafe-inline'",
    'script-src': "'self' http://* 'unsafe-inline' 'unsafe-eval'",
    'img-src': "'self' http://* 'unsafe-inline' data: *",
})
app.config['SECRET_KEY'] = 'cbYSt76Vck*7^%4d'
app.config['SQLALCHEMY_DATABASE_URI'] = "mysql://flask:ag@bf(*&^^@v320*e@localhost/stunion?charset=utf8"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SERVER_NAME'] = 'stunion.ustc.edu.cn'
app.config['MAIL_SERVER'] = 'smtp.exmail.qq.com'  # 这里用163邮件服务器
app.config['MAIL_PORT'] = 25
app.config['MAIL_USE_TLS'] = False  # 启用安全传输层协议
app.config['MAIL_USERNAME'] = "system@maglee.me"  # 从系统环境变量加载用户名和密码
app.config['MAIL_PASSWORD'] = "DoYouLoveUSTC1.2."

mail = Mail(app)
login_manager = LoginManager(app)
bootstrap = Bootstrap(app)
moment = Moment(app)
db = SQLAlchemy(app)
login_manager.session_protection = "strong"
timelimit = 1

NOT_START_STRING = "活动尚未开始。"
NOT_ACTIVATE_STRING = "对不起，你的账户还未激活！"
FEMALE = 0
MALE = 1

GIT_DATA = git.log('-1', '--pretty=%H%n%an%n%s').strip().split("\n")


def checkTimeLimit():
    # 返回1则正在活动
    nowtime = datetime.now()
    starttime = datetime(2019, 3, 1, 20, 0, 0, 0)
    endtime = datetime(2019, 3, 14, 0, 0, 0, 0)
    return starttime <= nowtime < endtime


# 格式化邮件
def mySendMailFormat(mailSubject, mailSender, mailRecv, mailBody, templates, **kwargs):
    msg = Message(mailSubject, sender=mailSender, recipients=[mailRecv])
    msg.body = render_template(templates + ".txt", **kwargs)
    msg.html = render_template(templates + ".html", **kwargs)
    return msg


# 异步发送邮件函数
def sendMailSyncFuc(app, msg):
    with app.app_context():
        mail.send(msg)


def simpleSendMail(app, msg):
    thr = Thread(target=sendMailSyncFuc, args=[app, msg])
    thr.start()
    return thr


@app.context_processor
def git_revision():
    return {'git_revision': "Revision {}".format(GIT_DATA[0][:7])}


class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, index=True, nullable=True)
    userEmail = db.Column(db.String(64), unique=True, index=True, nullable=True)
    userStatus = db.Column(db.Integer, default=0)
    # userStatus == 0 未激活
    # userStatus == 1 已经激活
    userAccountLevel = db.Column(db.Integer, nullable=True)
    userRealName = db.Column(db.String(128), nullable=True)
    userSchoolNum = db.Column(db.String(64), unique=True, nullable=True)
    userQQnum = db.Column(db.String(64), unique=True, nullable=True)
    userSex = db.Column(db.Integer, nullable=True)
    userWeChatNum = db.Column(db.String(64), nullable=True)
    userCellPhoneNum = db.Column(db.String(64), nullable=True)
    userOpenid = db.Column(db.String(256), nullable=True)
    userPasswordHash = db.Column(db.String(256), nullable=True)
    userSecretText = db.Column(db.String(64), nullable=True)

    def setPassword(self, password):
        self.userPasswordHash = generate_password_hash(password)

    def verifyPassword(self, password):
        return check_password_hash(self.userPasswordHash, password)

    def generate_confirmation_token(self, expiration=3600):
        s = Serializer(current_app.config['SECRET_KEY'], expiration)
        return s.dumps({'confirm': self.id}).decode('utf-8')

    def confirm(self, token):
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            data = s.loads(token.encode('utf-8'))
        except Exception:
            return False
        if data.get('confirm') != self.id:
            return False
        self.userStatus = 1
        db.session.add(self)
        return True

    def generate_reset_token(self, expiration=3600):
        s = Serializer(current_app.config['SECRET_KEY'], expiration)
        return s.dumps({'reset': self.id}).decode('utf-8')

    @staticmethod
    def reset_password(token, new_password):
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            data = s.loads(token.encode('utf-8'))
        except Exception:
            return False
        user = User.query.get(data.get('reset'))
        if user is None:
            return False
        user.setPassword(new_password)
        db.session.add(user)
        return True

    def __repr__(self):
        return '<User %r>' % self.username


@login_manager.user_loader
def loadUser(user_id):
    # print("loadUser: user_id =", user_id)
    return User.query.filter_by(id=int(user_id)).first()


@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404


@app.errorhandler(401)
def unauthorized(e):
    flash("你尚未登录!")
    return redirect(url_for('login'))


@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500


@app.route('/index')
@app.route('/', methods=['GET', 'POST'])
def index():
    if current_user.is_anonymous:
        return render_template('index.html', userStatus=1)
    return render_template('index.html', userStatus=current_user.userStatus)


@app.route('/logout')
@fresh_login_required
def logout():
    logout_user()
    # cas_logout_url = cas_client.get_logout_url(service_url=app_login_url)
    return redirect("https://passport.ustc.edu.cn/logout")


@app.route('/caslogin', methods=['GET', 'POST'])
def caslogin():
    ticket = request.args.get('ticket')
    app_login_url = 'https://stunion.ustc.edu.cn/caslogin'
    cas_url = 'https://passport.ustc.edu.cn'
    cas_client = CASClient(cas_url, auth_prefix='')
    if ticket:
        try:
            cas_response = cas_client.perform_service_validate(
                ticket=ticket,
                service_url=app_login_url,
            )
        except Exception:
            # CAS server is currently broken, try again later.
            return redirect(url_for('index'))
        if cas_response and cas_response.success:
            # print(cas_response)
            # print("cas_response.response_text:", cas_response.response_text)
            # print("cas_response.data", cas_response.data)
            # print("cas_response.user", cas_response.user)
            # print("cas_response.attributes", cas_response.attributes)
            myrecord = User.query.filter_by(userSchoolNum=cas_response.user).first()
            if myrecord is None:
                newuser = User(userSchoolNum=cas_response.user, userStatus=1)
                db.session.add(newuser)
                db.session.commit()
                newuser = User.query.filter_by(userSchoolNum=cas_response.user).first()
                login_user(newuser)
                # cas_client.session_exists(ticket)
                # cas_client.delete_session(ticket)
                return redirect(url_for('index'))
            login_user(myrecord)
            # cas_client.session_exists(ticket)
            # cas_client.delete_session(ticket)
            return redirect(url_for('index'))
    cas_login_url = cas_client.get_login_url(service_url=app_login_url)
    return redirect(cas_login_url)


@app.route('/faq', methods=['GET', 'POST'])
def faq():
    return render_template("faq.html")


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=True)
