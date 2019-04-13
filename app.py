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
from werkzeug.routing import Rule

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
app.url_rule_class = lambda path, **options: Rule(app.config['APPLICATION_ROOT'] + path, **options)


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


time_limit_enabled = config.get('TIME_LIMIT', "false").strip().lower() != "false"


def checkTimeLimit():
    nowtime = datetime.now()
    starttime = datetime(2019, 3, 12, 20, 0, 0, 0)
    endtime = datetime(2019, 3, 14, 20, 0, 0, 0)
    return starttime <= nowtime < endtime


@app.context_processor
def git_revision():
    return {'git_revision': "Revision {}".format(GIT_DATA[0][:7])}


class Vote(db.Model):
    __tablename__ = 'votes'
    id = db.Column(db.Integer, primary_key=True)
    ticketId = db.Column(db.Integer)
    target = db.Column(db.Integer)
    time = db.Column(db.DateTime, default=datetime.now)


class Candidate(db.Model):
    __tablename__ = 'candidates'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64))


class Ticket(db.Model):
    __tablename__ = 'tickets'
    id = db.Column(db.Integer, primary_key=True)
    ticketNum = db.Column(db.String(16))
    ticketLevel = db.Column(db.Integer, default=1)


OptionDisplay = namedtuple("OptionDisplay", ["id", "name", "selected"])


@app.route("/vote", methods=('GET',))
def vote():
    if time_limit_enabled and not checkTimeLimit():
        flash("投票已经结束，感谢您的参与", "success")
        return redirect(url_for("index"))
    candidates = db.session.query(Candidate.id, Candidate.name).order_by(Candidate.id)
    display_candidates = [OptionDisplay(c.id, c.name, False) for c in candidates]
    return render_template("vote.html", candidates=display_candidates)


@app.route("/vote/submit", methods=('POST',))
def submit():
    if time_limit_enabled and not checkTimeLimit():
        return redirect(url_for("index")), 400

    ticketInfo = Ticket.query.filter_by(ticketNum=request.form['ticketNum']).first()
    if ticketInfo is None:
        flash("此票不存在", "danger")
        return redirect(url_for("index"))
    record = Vote.query.filter_by(ticketId=ticketInfo.id).first()
    if record is not None:
        flash("此票已经使用", "info")
        return redirect(url_for("index"))
    if 'candidate' not in request.form:
        flash("未选择选手", "info")
        return redirect(url_for("index"))
    newVote = Vote(ticketId=ticketInfo.id, target=request.form['candidate'])
    db.session.add(newVote)
    db.session.commit()
    flash("投票成功", "success")
    return redirect(url_for("index"))


@app.route("/api/count", methods=('GET', 'POST'))
def api_count():
    candidates = db.session.query(Candidate.id, Candidate.name, func.count(Vote.target).label('vote_count')) \
        .join(Vote, Vote.target == Candidate.id) \
        .group_by(Vote.target) \
        .order_by(Candidate.id)
    return jsonify({'candidates': [{'id': c.id, 'name': c.name, 'votes': c.vote_count} for c in candidates]})


@app.route('/index')
@app.route('/', methods=('GET', 'POST'))
def index():
    candidates = db.session.query(Candidate.name, func.count(Vote.target).label('vote_count')) \
        .join(Vote, Vote.target == Candidate.id) \
        .group_by(Vote.target) \
        .order_by(desc(func.count(Vote.target)), Candidate.name)
    enabled = checkTimeLimit() or not time_limit_enabled
    return render_template("index.html", candidates=candidates, enabled=enabled)


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
