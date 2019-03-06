import os
from threading import Thread
from datetime import datetime
from configparser import RawConfigParser
from sh.contrib import git

from flask import *
from flask_bootstrap import Bootstrap
from flask_talisman import Talisman
from flask_wtf import FlaskForm
from wtforms import *
from sqlalchemy.sql.expression import func
from wtforms.validators import *
from flask_sqlalchemy import SQLAlchemy
from flask_login import login_required, fresh_login_required, login_user, login_fresh, login_url, LoginManager, \
    UserMixin, logout_user, current_user
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from cas_client import *

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

basedir = os.path.dirname(os.path.abspath(__file__))

app = Flask(__name__)
talisman = Talisman(app, content_security_policy={
    'default-src': "*",
    'style-src': "'self' http://* 'unsafe-inline'",
    'script-src': "'self' http://* 'unsafe-inline' 'unsafe-eval'",
    'img-src': "'self' http://* 'unsafe-inline' data: *",
})

# Initialize configuration
config_parser = RawConfigParser()
if os.path.isfile('config.ini'):
    config_parser.read('config.ini')
else:
    config_parser.read('config_sample.ini')
config = config_parser["AppConfig"]

app.config['SECRET_KEY'] = 'cbYSt76Vck*7^%4d'
app.config['SQLALCHEMY_DATABASE_URI'] = "mysql://{}:{}@{}/{}?charset=utf8".format(
    config['DB_USER'], config['DB_PASS'], config['DB_HOST'], config.get('DB_NAME', "kstar")
)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SERVER_NAME'] = config.get('SERVER_NAME', "stunion.ustc.edu.cn")

login_manager = LoginManager(app)
bootstrap = Bootstrap(app)
db = SQLAlchemy(app)
login_manager.session_protection = "strong"

GIT_DATA = git.log('-1', '--pretty=%H%n%an%n%s').strip().split("\n")


def checkTimeLimit():
    # 返回1则正在活动
    nowtime = datetime.now()
    starttime = datetime(2019, 3, 12, 20, 0, 0, 0)
    endtime = datetime(2019, 3, 20, 0, 0, 0, 0)
    return starttime <= nowtime < endtime


@app.context_processor
def git_revision():
    return {'git_revision': "Revision {}".format(GIT_DATA[0][:7])}


class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    school_id = db.Column(db.String(64), unique=True)

    def __repr__(self):
        return '<User %r>' % self.userSchoolNum


class Vote(db.Model):
    __tablename__ = 'votes'
    id = db.Column(db.Integer, primary_key=True)
    user = db.Column(db.Integer)
    target = db.Column(db.Integer)
    time = db.Column(db.DateTime)


class Candidate(db.Model):
    __tablename__ = 'candidates'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64))


@login_manager.user_loader
def loadUser(user_id):
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
    return render_template('index.html')


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
                return redirect(url_for('append'))
            login_user(myrecord)
            # cas_client.session_exists(ticket)
            # cas_client.delete_session(ticket)
            return redirect(url_for('append'))
    cas_login_url = cas_client.get_login_url(service_url=app_login_url)
    return redirect(cas_login_url)


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=int(config.get('SERVER_PORT', 6000)), debug=True)
