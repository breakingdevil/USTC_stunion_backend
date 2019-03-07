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
from wtforms.validators import *
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.sql.expression import func, desc
from flask_login import login_required, fresh_login_required, login_user, login_fresh, login_url, LoginManager, \
    UserMixin, logout_user, current_user
from cas_client import *

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Initialize configuration
config_parser = RawConfigParser()
if os.path.isfile('config.ini'):
    config_parser.read('config.ini')
else:
    config_parser.read('config_sample.ini')
config = config_parser["AppConfig"]

# Initialize application
app = Flask(__name__)
if config.get('USE_HTTPS', "false").strip().lower() != "false":
    talisman = Talisman(app, content_security_policy={
        'default-src': "*",
        'style-src': "'self' http://* 'unsafe-inline'",
        'script-src': "'self' http://* 'unsafe-inline' 'unsafe-eval'",
        'img-src': "'self' http://* 'unsafe-inline' data: *",
    })

app.config["APPLICATION_ROOT"] = "/kstar"
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


class PrefixMiddleware:
    def __init__(self, app, prefix=""):
        self.app = app
        self.prefix = prefix

    def __call__(self, env, start_response):
        env['PATH_INFO'] = env['PATH_INFO'][len(self.prefix):]
        env['SCRIPT_NAME'] = self.prefix
        return self.app(env, start_response)


app.wsgi_app = PrefixMiddleware(app.wsgi_app, "/kstar")


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


@app.route("/vote", methods=('GET', 'POST'))
@fresh_login_required
def vote():
    records = Vote.query.filter_by(user=current_user.id).first()
    if records is not None:
        flash("对不起,你已经投过票了!")
        return redirect(url_for('index'))
    candidates = db.session.query(Candidate.id, Candidate.name).order_by(Candidate.id)
    return render_template("vote.html", candidates=candidates)


@app.route("/vote/submit", methods=('POST',))
@fresh_login_required
def submit():
    records = Vote.query.filter_by(user=current_user.id).first()
    if records is not None:
        flash("对不起你已经投过票了!")
        return redirect(url_for('index'))
    data = dict(request.form)
    ids = [int(s[10:]) for s in data if s.startswith("candidate-") and data[s] == ["on"]]
    if len(ids) != 4:
        flash("每个人只能给四个人投票,你选择的人数有问题，少于四个人或者多于四个人!")
        return redirect(url_for("vote"))
    ids.sort()
    now = datetime.now()
    for cid in ids:
        db.session.add(Vote(user=current_user.id, target=cid, time=now))
    db.session.commit()
    flash("投票成功!")
    return redirect(url_for("index"))


@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404


@app.errorhandler(401)
def unauthorized(e):
    flash("你尚未登录!")
    return redirect(url_for('caslogin'))


@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500


@app.route('/index')
@app.route('/', methods=['GET', 'POST'])
def index():
    candidates = db.session.query(Candidate.name, func.count(Vote.target).label('vote_count')) \
                    .join(Vote, Vote.target == Candidate.id) \
                    .group_by(Vote.target) \
                    .order_by(desc(func.count(Vote.target)), Candidate.name)
    return render_template('index.html', candidates=candidates)


@app.route('/caslogin', methods=['GET', 'POST'])
def caslogin():
    ticket = request.args.get('ticket')
    app_login_url = 'https://stunion.ustc.edu.cn/kstar/caslogin'
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
            thisuser = User.query.filter_by(school_id=cas_response.user).first()
            if thisuser is None:
                thisuser = User(school_id=cas_response.user)
                db.session.add(thisuser)
                db.session.commit()
                thisuser = User.query.filter_by(school_id=cas_response.user).first()
            login_user(thisuser)
            return redirect(url_for('index'))
    cas_login_url = cas_client.get_login_url(service_url=app_login_url)
    return redirect(cas_login_url)


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=int(config.get('SERVER_PORT', 6000)), debug=True)
