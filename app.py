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

basedir = os.path.dirname(os.path.abspath(__file__))

app = Flask(__name__)
Talisman(app, content_security_policy={
    'default-src': "*",
    'style-src': "'self' http://* 'unsafe-inline'",
    'script-src': "'self' http://* 'unsafe-inline' 'unsafe-eval'"
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
    userSchoolNum = db.Column(db.String(64), nullable=True)
    userQQnum = db.Column(db.String(64), nullable=True)
    userSex = db.Column(db.Integer, nullable=True)
    userWeChatNum = db.Column(db.String(64), nullable=True)
    userCellPhoneNum = db.Column(db.String(64), nullable=True)
    userOpenid = db.Column(db.String(256), nullable=True)
    userPasswordHash = db.Column(db.String(256), nullable=True)

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
    print("loadUser: user_id =", user_id)
    return User.query.filter_by(id=int(user_id)).first()


#############################################################################
# sayLoveU

class sayLoveUDatabase(db.Model):
    __tablename__ = 'sayLoveU'
    fromEmail = db.Column(db.String(64), primary_key=True, unique=True, index=True)
    fromSayText = db.Column(db.String(256), nullable=True)
    toRealname = db.Column(db.String(128), nullable=True)
    userStatus = db.Column(db.Integer, nullable=True)


class sayLoveUForm(FlaskForm):
    toRealname = StringField(" 对方的真实姓名 ", validators=[DataRequired()])
    fromSayText = TextAreaField(" 想给对方的真情告白 ", validators=[DataRequired()])
    submit = SubmitField(" 告白 ")


@app.route('/sayLoveU', methods=['GET', 'POST'])
@fresh_login_required
def sayLoveU():
    if timelimit == 1:
        sign = checkTimeLimit()
        if not sign:
            flash(NOT_START_STRING)
            return redirect(url_for('index'))
    form = sayLoveUForm()
    if current_user.userEmail is None:
        return redirect(url_for('append'))

    if form.validate_on_submit():
        toRealname = form.toRealname.data
        fromSayText = form.fromSayText.data
        fromEmail = current_user.userEmail
        record = sayLoveUDatabase(fromEmail=fromEmail, fromSayText=fromSayText, toRealname=toRealname,
                                  userStatus=current_user.userStatus)
        db.session.add(record)
        db.session.commit()
        flash("告白成功，请静静等待配对，希望对方也喜欢你！")
        return redirect(url_for('sayLoveU'))
    checkSayLoveUstatus = sayLoveUDatabase.query.filter_by(fromEmail=current_user.userEmail).first()
    status = 0
    fromPerson = current_user
    fromPersonLoveinfo = checkSayLoveUstatus
    toPerson = None
    toPersonLoveinfo = None
    pairedStatus = 0
    if checkSayLoveUstatus is None:
        return render_template('sayLoveU.html', form=form, status=status, pairedStatus=pairedStatus,
                               fromPerson=fromPerson, toPerson=toPerson, fromPersonLoveinfo=fromPersonLoveinfo,
                               toPersonLoveinfo=toPersonLoveinfo, userStatus=current_user.userStatus)
    else:
        status = 1
        checkSayLoveUstatus.userStatus = current_user.userStatus
        db.session.add(checkSayLoveUstatus)
        db.session.commit()
        #####################################
        checkSayLoveUstatus = sayLoveUDatabase.query.filter_by(fromEmail=current_user.userEmail).first()
        fromPerson = current_user
        fromPersonLoveinfo = checkSayLoveUstatus
        ######################################
        toName = checkSayLoveUstatus.toRealname
        toUserRecord = User.query.filter_by(userRealName=toName, userStatus=1).first()
        toPerson = toUserRecord
        pairedStatus = 0
        # pairedStatus = 0 未配对 pairedStatus = 1 已配对
        if current_user.userStatus == 0:
            toPerson = None
            toPersonLoveinfo = None
            return render_template('sayLoveU.html', form=form, status=status, pairedStatus=pairedStatus,
                                   fromPerson=fromPerson, toPerson=toPerson, fromPersonLoveinfo=fromPersonLoveinfo,
                                   toPersonLoveinfo=toPersonLoveinfo, userStatus=current_user.userStatus)
        if toUserRecord is None:
            pairedStatus = 0
        else:
            alltoUserRecord = User.query.filter_by(userRealName=toName).count()
            if alltoUserRecord > 1:
                flash("对不起啊同学，你要表白的这个名字的同学不止一个，如果你喜欢 ta 请当面说吧！")
                return redirect(url_for('index'))
            toUserLove = sayLoveUDatabase.query.filter_by(fromEmail=toUserRecord.userEmail, userStatus=1).first()
            toPersonLoveinfo = toUserLove
            if toUserLove is None:
                pairedStatus = 0
            else:
                if toUserLove.toRealname != current_user.userRealName:
                    pairedStatus = 0
                if toUserLove.toRealname == current_user.userRealName:
                    pairedStatus = 1
                    return render_template('sayLoveU.html', form=form, status=status, pairedStatus=pairedStatus,
                                           fromPerson=fromPerson, toPerson=toPerson,
                                           fromPersonLoveinfo=fromPersonLoveinfo,
                                           toPersonLoveinfo=toPersonLoveinfo, userStatus=current_user.userStatus)
        return render_template('sayLoveU.html', form=form, status=status, pairedStatus=pairedStatus,
                               fromPerson=fromPerson, toPerson=toPerson, fromPersonLoveinfo=fromPersonLoveinfo,
                               toPersonLoveinfo=toPersonLoveinfo, userStatus=current_user.userStatus)


#####################################################################################
# 愿望实现

class wishdatebase(db.Model):
    userEmail = db.Column(db.String(64), primary_key=True, unique=True, index=True)
    userStatus = db.Column(db.Integer, nullable=True)
    userSchoolNum = db.Column(db.String(64), nullable=True)
    wishcontent = db.Column(db.String(256), nullable=True)
    wishstatus = db.Column(db.Integer, nullable=True)
    # 0 未选取 1 已选取 2 已完成
    wishid = db.Column(db.Integer, nullable=True)
    girlQQnum = db.Column(db.String(64), nullable=True)
    boyQQnum = db.Column(db.String(64), nullable=True)
    boyEmail = db.Column(db.String(64), nullable=True)
    boySchoolNum = db.Column(db.String(64), nullable=True)


class wishform(FlaskForm):
    wishText = TextAreaField(" 许愿内容 ", validators=[DataRequired()])
    submit = SubmitField("许愿")


class selectform(FlaskForm):
    wishid = RadioField("愿望序号", choices=[(i, "%d 号愿望" % i) for i in range(1, 6)],
                        validators=[], coerce=int)
    submit1 = SubmitField("选择愿望")


class finishform(FlaskForm):
    submit2 = SubmitField("完成愿望")


class updateform(FlaskForm):
    submit3 = SubmitField("刷新愿望")


class selectwishes(db.Model):
    userEmail = db.Column(db.String(64), primary_key=True, unique=True, index=True)
    userSchoolNum = db.Column(db.String(64), nullable=True)
    girlEmail = db.Column(db.String(64), nullable=True)
    girlQQnum = db.Column(db.String(64), nullable=True)
    girlSchoolNum = db.Column(db.String(64), nullable=True)
    wishstatus = db.Column(db.Integer, nullable=True)
    # 0 未完成 1 已完成
    selecttime = db.Column(db.String(64), nullable=True)
    lastviewtime = db.Column(db.String(64), nullable=True)
    lastupdatetime = db.Column(db.String(64), nullable=True)
    cashid = db.Column(db.String(256), nullable=True)
    userStatus = db.Column(db.Integer, nullable=True)


@app.route('/wish', methods=['GET', 'POST'])
@fresh_login_required
def wish():
    sex = 0
    sex = current_user.userSex
    if timelimit == 1:
        sign = checkTimeLimit()
        if not sign:
            flash(NOT_START_STRING)
            return redirect(url_for('index'))
    if current_user.userEmail is None:
        return redirect(url_for('append'))
    wishes = wishdatebase.query.filter_by(userStatus=1).order_by(func.random()).limit(5)
    if wishes.count() == 0:
        flash("还没有可以选择的愿望。")
        return render_template('wish.html', sex=sex, wishes=wishes)
    return render_template('wish.html', sex=sex, wishes=wishes)


@app.route('/girl', methods=['GET', 'POST'])
@fresh_login_required
def girl():
    if current_user.userSex == MALE:
        flash("男同学不能进来啊！")
        return redirect(url_for("index"))
    if timelimit == 1 and not checkTimeLimit():
        flash(NOT_START_STRING)
        return redirect(url_for('index'))
    form = wishform()
    if current_user.userEmail is None:
        return redirect(url_for('append'))
    if form.validate_on_submit():
        wishtext = form.wishText.data
        record = wishdatebase.query.filter_by(userEmail=current_user.userEmail,
                                              userSchoolNum=current_user.userSchoolNum).first()
        if record is None:
            mywish = wishdatebase(userEmail=current_user.userEmail, wishcontent=wishtext, wishstatus=0,
                                  girlQQnum=current_user.userQQnum, userStatus=current_user.userStatus,
                                  userSchoolNum=current_user.userSchoolNum)
            db.session.add(mywish)
            db.session.commit()
            flash("收到你的愿望了!")
            return redirect(url_for('girl'))
        else:
            if record.wishstatus == 0:
                record.wishcontent = wishtext
                db.session.add(record)
                db.session.commit()
                flash("修改愿望成功！")
                return redirect(url_for('girl'))
            flash("对不起，你的愿望已经被选取！")
            return redirect(url_for('girl'))
    mywish = wishdatebase.query.filter_by(userEmail=current_user.userEmail,
                                          userSchoolNum=current_user.userSchoolNum).first()
    if mywish is not None:
        mywish.userStatus = current_user.userStatus
        db.session.add(mywish)
        db.session.commit()
        mywish = wishdatebase.query.filter_by(userEmail=current_user.userEmail,
                                              userSchoolNum=current_user.userSchoolNum).first()
        if mywish.boySchoolNum is not None:
            mywish.boySchoolNum = mywish.boySchoolNum[:-4] + "****"
    return render_template('girl.html', form=form, mywish=mywish, userStatus=current_user.userStatus)


@app.route('/boy', methods=['GET', 'POST'])
@fresh_login_required
def boy():
    if current_user.userSex == FEMALE:
        flash("女同学不能进来哦～")
        return redirect(url_for("index"))
    if timelimit == 1 and not checkTimeLimit():
        flash(NOT_START_STRING)
        return redirect(url_for('index'))
    if current_user.userEmail is None:
        return redirect(url_for('append'))
    myrecord = selectwishes.query.filter_by(userEmail=current_user.userEmail,
                                            userSchoolNum=current_user.userSchoolNum).first()
    selectwishform = selectform()
    finishwishform = finishform()
    updatewishform = updateform()

    # 选择愿望
    if selectwishform.validate_on_submit() and selectwishform.submit1.data:
        wishid = selectwishform.wishid.data
        myrecord = selectwishes.query.filter_by(userEmail=current_user.userEmail,
                                                userSchoolNum=current_user.userSchoolNum).first()
        if current_user.userStatus == 0:
            flash(NOT_ACTIVATE_STRING)
            return redirect(url_for('boy'))
        if myrecord.girlEmail is not None:
            flash("对不起，你已经选取了愿望。")
            return redirect(url_for('boy'))
        mycash = myrecord.cashid.split(";")
        mycash.remove("")
        if wishid > len(mycash) or wishid < 0:
            flash("对不起，选择愿望序号有误。")
            return redirect(url_for("boy"))
        myselectemail = mycash[wishid - 1]
        otherselect = selectwishes.query.filter_by(girlEmail=myselectemail).first()
        if otherselect is not None:
            flash("对不起，该愿望已经被选取。")
            return redirect(url_for('wish'))
        girllog = wishdatebase.query.filter_by(userEmail=myselectemail).first()
        myrecord.wishstatus = 0
        myrecord.girlEmail = myselectemail
        myrecord.girlQQnum = girllog.girlQQnum
        myrecord.girlSchoolNum = girllog.userSchoolNum
        myrecord.selecttime = datetime.now()
        girllog.wishstatus = 1
        girllog.boyQQnum = current_user.userQQnum
        girllog.boyEmail = current_user.userEmail
        girllog.boySchoolNum = current_user.userSchoolNum
        db.session.add(myrecord)
        db.session.add(girllog)
        db.session.commit()
        flash("选取愿望成功！")
        return redirect(url_for('boy'))

    # 完成愿望!
    if finishwishform.validate_on_submit() and finishwishform.submit2.data:
        if current_user.userStatus == 0:
            flash(NOT_ACTIVATE_STRING)
            return redirect(url_for('boy'))
        myrecord = selectwishes.query.filter_by(userEmail=current_user.userEmail,
                                                userSchoolNum=current_user.userSchoolNum).first()
        girllog = wishdatebase.query.filter_by(userEmail=myrecord.girlEmail).first()
        if (myrecord is not None) and (girllog is not None):
            myrecord.wishstatus = 1
            girllog.wishstatus = 2
            db.session.add(myrecord)
            db.session.add(girllog)
            db.session.commit()
            flash("完成愿望成功!")
            return redirect(url_for('boy'))
        return redirect(url_for('boy'))

    # 更新愿望!
    if updatewishform.validate_on_submit() and updatewishform.submit3.data:
        myrecord = selectwishes.query.filter_by(userEmail=current_user.userEmail,
                                                userSchoolNum=current_user.userSchoolNum).first()
        if current_user.userStatus == 0:
            flash(NOT_ACTIVATE_STRING)
            return redirect(url_for('boy'))
        if myrecord.lastupdatetime is None:
            wishes = wishdatebase.query.filter_by(wishstatus=0, userStatus=1).order_by(func.random()).limit(5)
            mystr = ""
            if wishes.count() == 0:
                flash("当前没有可以被选取的愿望。")
                return redirect(url_for('boy'))
            for wish in wishes:
                mystr += wish.userEmail + ";"
            if mystr != "":
                myrecord.cashid = mystr
            myrecord.lastupdatetime = str(datetime.now())
            db.session.add(myrecord)
            db.session.commit()
            flash("刷新愿望成功。")
            return redirect(url_for('boy'))
        nowtime = datetime.now()
        lastupdatetime = datetime.strptime(myrecord.lastupdatetime, "%Y-%m-%d %H:%M:%S.%f")
        if (nowtime - lastupdatetime).days >= 1:
            wishes = wishdatebase.query.filter_by(wishstatus=0, userStatus=1).order_by(func.random()).limit(5)
            if wishes.count() == 0:
                flash("没有可以被选取的愿望。")
                return redirect(url_for('boy'))
            mystr = ""
            for wish in wishes:
                mystr += wish.userEmail + ";"
            if mystr != "":
                myrecord.cashid = mystr
            myrecord.lastupdatetime = str(nowtime)
            db.session.add(myrecord)
            db.session.commit()
            flash("刷新愿望成功。")
            return redirect(url_for('boy'))
        flash("每 24 小时只允许刷新一次。")
        return redirect(url_for('boy'))
    if myrecord is None:
        myrecord = selectwishes(userEmail=current_user.userEmail, userStatus=current_user.userStatus,
                                userSchoolNum=current_user.userSchoolNum)
        db.session.add(myrecord)
        db.session.commit()
        return redirect(url_for('boy'))
    myrecord.userStatus = current_user.userStatus
    db.session.add(myrecord)
    db.session.commit()
    myrecord = selectwishes.query.filter_by(userEmail=current_user.userEmail,
                                            userSchoolNum=current_user.userSchoolNum).first()
    if myrecord.cashid is None:
        wishes = wishdatebase.query.filter_by(wishstatus=0, userStatus=1).order_by(func.random()).limit(5)
        if wishes.count() == 0:
            flash("没有可以被选取的愿望。")
            return redirect(url_for('wish'))
        mystr = ""
        for wish in wishes:
            mystr += wish.userEmail + ";"
        if mystr != "":
            myrecord.cashid = mystr
        myrecord.lastviewtime = str(datetime.now())
        db.session.add(myrecord)
        db.session.commit()
        return redirect(url_for('boy'))
    if myrecord.lastupdatetime is None:
        myrecord.lastupdatetime = "2019-01-01 00:00:00.000000"
        db.session.add(myrecord)
        db.session.commit()
        return redirect(url_for('boy'))
    if current_user.userStatus == 0:
        flash(NOT_ACTIVATE_STRING)
    if myrecord.wishstatus == 0:
        myselectwish = wishdatebase.query.filter_by(userEmail=myrecord.girlEmail).first()
        wishes = []
        magiccode = 0

        return render_template("boy.html", selectwishform=selectwishform, updatewishform=updatewishform,
                               finishwishform=finishwishform, myselectwish=myselectwish, wishes=wishes,
                               magiccode=magiccode, userStatus=current_user.userStatus)
    if myrecord.wishstatus == 1:
        myselectwish = wishdatebase.query.filter_by(userEmail=myrecord.girlEmail).first()
        wishes = []
        magiccode = 0
        myselectwish.userSchoolNum = myselectwish.userSchoolNum[:-4] + "****"
        return render_template("boy.html", selectwishform=selectwishform, updatewishform=updatewishform,
                               finishwishform=finishwishform, myselectwish=myselectwish, wishes=wishes,
                               magiccode=magiccode, userStatus=current_user.userStatus)
    lasttime = datetime.strptime(str(myrecord.lastviewtime), "%Y-%m-%d %H:%M:%S.%f")
    nowtime = datetime.now()
    if (nowtime - lasttime).days >= 1:
        wishes = wishdatebase.query.filter_by(wishstatus=0, userStatus=1).order_by(func.random()).limit(5)
        if wishes.count() == 0:
            flash("没有可以被选取的愿望")
        mystr = ""
        for wish in wishes:
            mystr += wish.userEmail + ";"
        if mystr != "":
            myrecord.cashid = mystr
            myrecord.lastviewtime = str(datetime.now())
        db.session.add(myrecord)
        db.session.commit()
        return redirect(url_for('boy'))
    myselectwish = selectwishes.query.filter_by(userEmail=current_user.userEmail,
                                                userSchoolNum=current_user.userSchoolNum).first()
    wishes = []
    mywishesid = myselectwish.cashid.split(";")
    mywishesid.remove("")
    magiccode = 1
    count = 1
    for peremail in mywishesid:
        if peremail is None:
            continue
        onewish = wishdatebase.query.filter_by(userEmail=peremail).first()
        cpofonewish = onewish
        content = "------这个是第%d号愿望------" % count
        count += 1
        content += cpofonewish.wishcontent
        cpofonewish.wishcontent = content
        wishes.append(cpofonewish)
    return render_template("boy.html", selectwishform=selectwishform, updatewishform=updatewishform,
                           finishwishform=finishwishform, myselectwish=myselectwish, wishes=wishes, magiccode=magiccode,
                           userStatus=current_user.userStatus)


############################################################


class LoginForm(FlaskForm):
    email = StringField("请使用科大校内邮箱注册的用户名登录!\n（以 @mail.ustc.edu.cn或 @ustc.edu.cn 结尾，若无邮箱后缀则默认为 @mail.ustc.edu.cn）",
                        validators=[DataRequired(), Length(1, 256)])
    password = PasswordField("请输入密码", validators=[DataRequired()])
    remember_me = BooleanField("记住登录状态")
    submit = SubmitField("Log In")


class RegisterForm(FlaskForm):
    email = StringField("电子邮箱（中科大校内邮箱，以 @mail.ustc.edu.cn、@ustc.edu.cn 结尾）",
                        validators=[DataRequired(), Length(1, 64), Email()])
    schoolnum = StringField("学号", validators=[DataRequired()])
    realname = StringField("姓名(请输入你的真实姓名，不然你凭实力单身，我们也帮不了你)", validators=[DataRequired()])
    password = PasswordField('请设置密码', validators=[DataRequired(), Length(6, 64)])
    QQnum = StringField(" QQ 号码", validators=[DataRequired()])
    sex = RadioField("性别", choices=[(1, "男"), (0, "女")], validators=[], coerce=int)
    submit = SubmitField('注册')

    def validate_email(self, field):
        if not field.data.endswith("@mail.ustc.edu.cn") and not field.data.endswith("@ustc.edu.cn"):
            raise ValidationError('请使用 @mail.ustc.edu.cn 或者 @ustc.edu.cn')
        user = User.query.filter_by(userEmail=field.data).first()
        if user is not None and user.userStatus == 1:
            raise ValidationError('电子邮箱已经注册')


class ChangePasswordForm(FlaskForm):
    old_password = PasswordField('旧密码', validators=[DataRequired()])
    password = PasswordField('新密码',
                             validators=[DataRequired(), Length(6, 64), EqualTo('password2', message='两次输入的密码必须相等')])
    password2 = PasswordField('确认新密码', validators=[DataRequired()])
    submit = SubmitField('确认修改密码')


class PasswordResetRequestForm(FlaskForm):
    email = StringField('您注册的邮箱', validators=[DataRequired(), Length(1, 64), Email()])
    submit = SubmitField('重置密码')


class PasswordResetForm(FlaskForm):
    password = PasswordField('新的密码', validators=[
        DataRequired(), EqualTo('password2', message='Passwords must match')])
    password2 = PasswordField('确认新的密码', validators=[DataRequired()])
    submit = SubmitField('重置密码')


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
@fresh_login_required
def index():
    if current_user.is_anonymous:
        return render_template('index.html', userStatus=1)
    return render_template('index.html', userStatus=current_user.userStatus)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        if not form.email.data.endswith("@mail.ustc.edu.cn") and not form.email.data.endswith("@ustc.edu.cn"):
            form.email.data += "@mail.ustc.edu.cn"
        user = User.query.filter_by(userEmail=form.email.data).first()
        if user is not None and user.verifyPassword(form.password.data):
            login_user(user, form.remember_me.data)
            next = request.args.get('next')
            if next is None or not next.startswith('/'):
                next = url_for('index')
            return redirect('/')
        flash("邮箱地址或者密码不正确")
    return render_template('auth/login.html', form=form)


@app.route('/logout')
@fresh_login_required
def logout():
    logout_user()
    cas_logout_url = cas_client.get_logout_url(service_url=app_login_url)
    return redirect("https://passport.ustc.edu.cn/logout")


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        newuserpassword = form.password.data
        newuseremail = form.email.data
        newusersex = form.sex.data
        newuserQQnum = form.QQnum.data
        newuserschoolnum = form.schoolnum.data
        newuserrealname = form.realname.data
        if not newuseremail.endswith("@mail.ustc.edu.cn") and newuseremail.endswith("@ustc.edu.cn"):
            flash("用户邮箱请使用 USTC 校内邮箱地址")
            return redirect(url_for("register"))
        user = User.query.filter_by(userEmail=form.email.data).first()
        if user is None:
            user = User(userEmail=newuseremail, userSchoolNum=newuserschoolnum, userQQnum=newuserQQnum,
                        userSex=newusersex, userRealName=newuserrealname)
        else:
            User.query.filter_by(userEmail=form.email.data).delete()
            user = User(userEmail=newuseremail, userSchoolNum=newuserschoolnum, userQQnum=newuserQQnum,
                        userSex=newusersex, userRealName=newuserrealname)
        user.setPassword(newuserpassword)
        user.userStatus = 0
        db.session.add(user)
        db.session.commit()
        token = user.generate_confirmation_token()
        mymsg = mySendMailFormat("Student Union 邀请您激活账户", "system@maglee.me", user.userEmail, "", "auth/email/confirm",
                                 token=token, user=user)
        simpleSendMail(app, mymsg)
        flash("注册成功 , 激活账户的邮件已发往您的 USTC 校内邮箱 ！")
        flash("邮件可能标记为垃圾邮件")
        flash("您现在即可登录！")
        return redirect(url_for("login"))
    return render_template("auth/register.html", form=form)


@app.route('/confirm/<token>')
@fresh_login_required
def confirm(token):
    if current_user.userStatus:
        return redirect(url_for('index'))
    if current_user.confirm(token):
        db.session.commit()
        flash("你已经激活了你的账户，谢谢！")
    else:
        flash("激活链接已经失效！")
    return redirect(url_for("index"))


@app.route('/unconfirmed')
@login_required
def unconfirmed():
    if current_user.is_anonymous or current_user.userStatus:
        return redirect(url_for('index'))
    return render_template('auth/unconfirmed.html')


class checkemailtime(db.Model):
    userEmail = db.Column(db.String(64), primary_key=True, unique=True, index=True)
    timestamp = db.Column(db.String(256), nullable=True)


@app.route('/confirm')
@fresh_login_required
def resend_confirmation():
    stamp = checkemailtime.query.filter_by(userEmail=current_user.userEmail).first()
    if stamp is None:
        newtimestamp = checkemailtime(userEmail=current_user.userEmail, timestamp=str(datetime.now())).first()
        db.session.add(newtimestamp)
        db.session.commit()
        token = current_user.generate_confirmation_token()
        mymsg = mySendMailFormat("Student Union 邀请您激活账户", "system@maglee.me", current_user.userEmail, "",
                                 "auth/email/confirm", token=token, user=current_user)
        simpleSendMail(app, mymsg)
        flash("邮件已经发送，请注意查收！")
        return redirect(url_for('index'))
    nowtime = datetime.now()
    lasttime = datetime.strptime(str(stamp.timestamp), "%Y-%m-%d %H:%M:%S.%f")
    if (nowtime - lasttime).seconds <= 600:
        flash("对不起，您申请激活邮件的次数过于频繁, 10min后再试试吧!")
        return redirect(url_for('index'))
    stamp.timestamp = str(datetime.now())
    db.session.add(stamp)
    db.session.commit()
    token = current_user.generate_confirmation_token()
    mymsg = mySendMailFormat("Student Union 邀请您激活账户", "system@maglee.me", current_user.userEmail, "",
                             "auth/email/confirm", token=token, user=current_user)
    simpleSendMail(app, mymsg)
    flash("邮件已经发送,请注意查收！")
    return redirect(url_for('index'))


@app.route('/change-password', methods=['GET', 'POST'])
@fresh_login_required
def change_password():
    form = ChangePasswordForm()
    if form.validate_on_submit():
        if current_user.verifyPassword(form.old_password.data):
            current_user.setPassword(form.password.data)
            db.session.add(current_user)
            db.session.commit()
            flash('你已经更改密码。')
            return redirect(url_for('index'))
        else:
            flash('Invalid password.')
    return render_template("auth/change_password.html", form=form)


@app.route('/reset', methods=['GET', 'POST'])
def password_reset_request():
    if not current_user.is_anonymous:
        return redirect(url_for('index'))
    form = PasswordResetRequestForm()
    if form.validate_on_submit():
        user = User.query.filter_by(userEmail=form.email.data).first()
        if user:
            token = user.generate_reset_token()
            # send_email(user.email, 'Reset Your Password','auth/email/reset_password', user=user, token=token)
            mymsg = mySendMailFormat("Student Union 更改您的账户密码", "system@maglee.me", user.userEmail, "",
                                     "auth/email/reset_password", token=token, user=user)
            simpleSendMail(app, mymsg)
            flash("邮件已经发送，请注意查收！")
            return redirect(url_for('login'))
        flash('可能哪里有些不对，你确定你注册过账户吗？')
        return redirect(url_for('index'))
    return render_template('auth/reset_password.html', form=form)


@app.route('/reset/<token>', methods=['GET', 'POST'])
def password_reset(token):
    if not current_user.is_anonymous:
        return redirect(url_for('index'))
    form = PasswordResetForm()
    if form.validate_on_submit():
        if User.reset_password(token, form.password.data):
            db.session.commit()
            flash('你已经更新了你的密码。')
            return redirect(url_for('login'))
        else:
            flash('Token 错误')
            return redirect(url_for('index'))
    return render_template('auth/reset_password.html', form=form)


########################################################
# 统一认证接口
class appendUserDataForm(FlaskForm):
    email = StringField("电子邮箱（中科大校内邮箱，以 @mail.ustc.edu.cn、@ustc.edu.cn 结尾）",
                        validators=[DataRequired(), Length(1, 64), Email()])
    realname = StringField("姓名（请输入你的真实姓名，不然你凭实力单身，我们也帮不了你）", validators=[DataRequired()])
    password = PasswordField('请设置密码', validators=[DataRequired(), Length(6, 64)])
    QQnum = StringField(" QQ 号码", validators=[DataRequired()])
    sex = RadioField("性别", choices=[(1, "男"), (0, "女")], validators=[], coerce=int)
    submit = SubmitField('补全资料')

    def validate_email(self, field):
        if not field.data.endswith("@mail.ustc.edu.cn") and not field.data.endswith("@ustc.edu.cn"):
            raise ValidationError('请使用 @mail.ustc.edu.cn 或者 @ustc.edu.cn')
        user = User.query.filter_by(userEmail=field.data).first()
        if user is not None and user.userStatus == 1:
            raise ValidationError('您填写的电子邮箱已经被注册。')


@app.route('/append', methods=['GET', 'POST'])
@fresh_login_required
def append():
    myrecord = User.query.filter_by(userSchoolNum=current_user.userSchoolNum).first()
    if myrecord is None:
        flash("请重新登录！")
        return redirect(url_for('logout'))
    infostatus = 0
    infoform = appendUserDataForm()
    if current_user.userEmail is not None:
        flash("您已完整填写个人信息。")
        return redirect(url_for('index'))
    if infoform.validate_on_submit():
        myrecord.userEmail = infoform.email.data
        myrecord.userRealName = infoform.realname.data
        myrecord.userQQnum = infoform.QQnum.data
        myrecord.userSex = infoform.sex.data
        myrecord.setPassword(infoform.password.data)
        db.session.add(myrecord)
        db.session.commit()
        return redirect(url_for("append"))
    return render_template('append.html', form=infoform)


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
    app.run(host='0.0.0.0', port=5000, debug=True)
