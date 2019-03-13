import os
from collections import namedtuple
from threading import Thread
from datetime import datetime
from configparser import RawConfigParser
import regex
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
MAX_VOTES = 5


class PrefixMiddleware:
    def __init__(self, app, prefix=""):
        self.app = app
        self.prefix = prefix

    def __call__(self, env, start_response):
        env['PATH_INFO'] = env['PATH_INFO'][len(self.prefix):]
        env['SCRIPT_NAME'] = self.prefix
        return self.app(env, start_response)


app.wsgi_app = PrefixMiddleware(app.wsgi_app, "/kstar")
time_limit_enabled = config.get('TIME_LIMIT', "false").strip().lower() != "false"


def checkTimeLimit():
    nowtime = datetime.now()
    starttime = datetime(2019, 3, 12, 20, 0, 0, 0)
    endtime = datetime(2019, 3, 14, 20, 0, 0, 0)
    return starttime <= nowtime < endtime


@app.context_processor
def git_revision():
    return {'git_revision': "Revision {}".format(GIT_DATA[0][:7])}


class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    school_id = db.Column(db.String(64), unique=True)
    time = db.Column(db.DateTime, default=datetime.now)

    def __repr__(self):
        return '<User %r>' % self.userSchoolNum


class Vote(db.Model):
    __tablename__ = 'votes'
    id = db.Column(db.Integer, primary_key=True)
    user = db.Column(db.Integer)
    target = db.Column(db.Integer)
    time = db.Column(db.DateTime, default=datetime.now)


class Candidate(db.Model):
    __tablename__ = 'candidates'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64))


OptionDisplay = namedtuple("OptionDisplay", ["id", "name", "selected"])


@login_manager.user_loader
def load_user(user_id):
    return User.query.filter_by(id=int(user_id)).first()


@app.route("/vote", methods=('GET', 'POST'))
@fresh_login_required
def vote():
    if time_limit_enabled and not checkTimeLimit():
        flash("投票尚未开始", "danger")
        return redirect(url_for("index"))
    records = list(map(lambda x: x.target, Vote.query.filter_by(user=current_user.id).all()))
    candidates = db.session.query(Candidate.id, Candidate.name).order_by(Candidate.id)
    if records:
        has_voted = True
        display_candidates = [OptionDisplay(c.id, c.name, c.id in records) for c in candidates]
    else:
        has_voted = False
        display_candidates = candidates
    return render_template("vote.html", candidates=display_candidates, has_voted=has_voted, targets=records)


@app.route("/vote/submit", methods=('POST',))
@fresh_login_required
def submit():
    if time_limit_enabled and not checkTimeLimit():
        return redirect(url_for("index")), 400
    records = Vote.query.filter_by(user=current_user.id).all()
    if records:
        flash("你已经投过票了", "info")
        return redirect(url_for("index"))
    data = dict(request.form)
    ids = list({int(s[10:]) for s in data if s.startswith("candidate-") and "on" in [data[s], data[s][0]]})
    if not ids:
        flash("请选择你要投票的选手", "danger")
        return redirect(url_for("vote"))
    elif len(ids) > MAX_VOTES:
        flash("每个人只能给 {} 位选手投票，你投了 {} 票".format(MAX_VOTES, len(ids)), "danger")
        return redirect(url_for("vote"))
    ids.sort()
    now = datetime.now()
    for cid in ids:
        db.session.add(Vote(user=current_user.id, target=cid, time=now))
    db.session.commit()
    flash("投票成功！", "success")
    return redirect(url_for("index"))


@app.route("/api/count", methods=('GET', 'POST'))
def api_count():
    candidates = db.session.query(Candidate.id, Candidate.name, func.count(Vote.target).label('vote_count')) \
        .join(Vote, Vote.target == Candidate.id) \
        .group_by(Vote.target) \
        .order_by(Candidate.id)
    return jsonify({'candidates': [{'id': c.id, 'name': c.name, 'votes': c.vote_count} for c in candidates]})


@app.route('/index')
@app.route('/', methods=['GET', 'POST'])
def index():
    candidates = db.session.query(Candidate.name, func.count(Vote.target).label('vote_count')) \
        .join(Vote, Vote.target == Candidate.id) \
        .group_by(Vote.target) \
        .order_by(desc(func.count(Vote.target)), Candidate.name)
    if current_user.is_authenticated:
        has_voted = Vote.query.filter_by(user=current_user.id).first() is not None
    else:
        has_voted = False
    return render_template("index.html", candidates=candidates, has_voted=has_voted)


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
            flash("统一身份认证服务出现故障，请稍后重试", 'danger')
            return redirect(url_for('index'))
        if cas_response and cas_response.success:
            thisuser = User.query.filter_by(school_id=cas_response.user).first()
            if thisuser is None:
                # Validate school ID
                if not regex.compile(r"(?i)^[A-Z]{2}\d{8}$").match(cas_response.user):
                    flash("请使用有效学号登录", 'danger')
                    return redirect(url_for('index'))
                thisuser = User(school_id=cas_response.user, time=datetime.now())
                db.session.add(thisuser)
                db.session.commit()
                thisuser = User.query.filter_by(school_id=cas_response.user).first()
            login_user(thisuser)
            return redirect(url_for('index'))
    cas_login_url = cas_client.get_login_url(service_url=app_login_url)
    return redirect(cas_login_url)


@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404


@app.errorhandler(401)
def unauthorized(e):
    return redirect(url_for('caslogin'))


@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(config.get('SERVER_PORT', 6000)), debug=True)
