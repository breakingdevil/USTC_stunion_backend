import os
from flask import *
from flask_bootstrap import Bootstrap
from flask_moment import Moment
from flask_wtf import FlaskForm
from wtforms import *
from wtforms.validators import *
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash,check_password_hash
from flask_login import login_required , login_user,login_fresh,login_url,LoginManager,UserMixin,logout_user,current_user
from threading import Thread
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer

basedir = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)
app.config['SECRET_KEY'] = 'cbYSt76Vck*7^%4d'
app.config['SQLALCHEMY_DATABASE_URI'] = "mysql://flask:AAAflask1.2.@localhost/flaskusers?charset=utf8"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SERVER_NAME'] = 'stunion.ustc.edu.cn'
app.config['MAIL_SERVER'] = 'smtp.exmail.qq.com'  #  这里用163邮件服务器
app.config['MAIL_PORT'] = 25
app.config['MAIL_USE_TLS'] = False        # 启用安全传输层协议
app.config['MAIL_USERNAME'] = "system@maglee.me"      # 从系统环境变量加载用户名和密码
app.config['MAIL_PASSWORD'] = "DoYouLoveUSTC1.2."

mail = Mail(app)

login_manager = LoginManager(app)
bootstrap = Bootstrap(app)
moment = Moment(app)
db = SQLAlchemy(app)

# 格式化邮件
def mySendMailFormat(mailSubject,mailSender,mailRecv,mailBody,templates,**kwargs):
    msg = Message(mailSubject, sender=mailSender, recipients=[mailRecv])
    msg.body = render_template(templates+".txt",**kwargs)
    msg.html = render_template(templates+".html",**kwargs)
    return msg

# 异步发送邮件函数
def sendMailSyncFuc(app,msg):
    with app.app_context():
        mail.send(msg)
#
def simpleSendMail(app,msg):
    thr = Thread(target=sendMailSyncFuc,args=[app,msg])
    thr.start()
    return thr




class User(UserMixin,db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, index=True,nullable=True)
    userEmail = db.Column(db.String(64),unique=True, index=True)
    userStatus = db.Column(db.Integer, default=0)
    # userStatus == 0 未激活
    # userStatus == 1 已经激活
    userAccountLevel = db.Column(db.Integer,nullable=True)
    userRealName = db.Column(db.String(128),nullable=True)
    userSchoolNum = db.Column(db.String(64),nullable=True)
    userQQnum = db.Column(db.String(64),nullable=True)
    userSex = db.Column(db.Integer,nullable=True)
    userWeChatNum = db.Column(db.String(64),nullable=True)
    userCellPhoneNum = db.Column(db.String(64),nullable=True)
    userOpenid = db.Column(db.String(256),nullable=True)
    userPasswordHash = db.Column(db.String(256),nullable=True)

    def setPassword(self,password):
        self.userPasswordHash = generate_password_hash(password)
        return

    def verifyPassword(self,password):
        return check_password_hash(self.userPasswordHash,password)

    def generate_confirmation_token(self,expiration=3600):
        s = Serializer(current_app.config['SECRET_KEY'],expiration)
        return s.dumps({'confirm':self.id}).decode('utf-8')

    def confirm(self,token):
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            data = s.loads(token.encode('utf-8'))
        except:
            return False
        if data.get('confirm') != self.id:
            return False
        self.userStatus=1
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
        except:
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
    return User.query.get(int(user_id))




class sayLoveUDatabase(db.Model):
    __tablename__ = 'sayLoveU'
    fromEmail = db.Column(db.String(64),primary_key=True,unique=True, index=True)
    fromSayText = db.Column(db.String(256),nullable=True)
    toRealname = db.Column(db.String(128),nullable=True)


class sayLoveUForm(FlaskForm):
    toRealname = StringField(" 对方的真实姓名 ",validators=[DataRequired()])
    fromSayText = TextAreaField(" 想给对方的真情告白 ",validators=[DataRequired()])
    submit = SubmitField(" 告白 ")


@app.route('/sayLoveU',methods=['GET', 'POST'])
@login_required
def sayLoveU():
    if current_user.userStatus==0:
        flash(" 您还没有认证! ")
        return redirect(url_for('index'))
    form = sayLoveUForm()
    if form.validate_on_submit():
        toRealname = form.toRealname.data
        fromSayText = form.fromSayText.data
        fromEmail = current_user.userEmail
        record = sayLoveUDatabase(fromEmail=fromEmail,fromSayText=fromSayText,toRealname=toRealname)
        db.session.add(record)
        db.session.commit()
        flash(" 告白成功,静静等待配对，希望对方也喜欢你！ ")
        return redirect(url_for('sayLoveU'))
    checkSayLoveUstatus = sayLoveUDatabase.query.filter_by(fromEmail=current_user.userEmail).first()
    status = 0
    fromPerson = current_user
    fromPersonLoveinfo = checkSayLoveUstatus
    toPerson = None
    toPersonLoveinfo = None
    pairedStatus= 0
    if checkSayLoveUstatus is None:
        return render_template('sayLoveU.html',form=form,status=status,pairedStatus=pairedStatus,fromPerson=fromPerson,toPerson=toPerson,fromPersonLoveinfo=fromPersonLoveinfo,toPersonLoveinfo=toPersonLoveinfo)
    else:
        status = 1
        toName = checkSayLoveUstatus.toRealname
        toUserRecord = User.query.filter_by(userRealName=toName).first()
        toPerson = toUserRecord
        pairedStatus = 0
        # pairedStatus = 0 未配对 pairedStatus = 1 已配对
        if toUserRecord is None:
            pairedStatus = 0
        else:
            toUserLove = sayLoveUDatabase.query.filter_by(fromEmail=toUserRecord.userEmail).first()
            toPersonLoveinfo = toUserLove
            if toUserLove is None:
                pairedStatus = 0
            else:
                if toUserLove.toRealname != current_user.userRealName:
                    pairedStatus = 0
                if toUserLove.toRealname == current_user.userRealName:
                    pairedStatus = 1
                    return render_template('sayLoveU.html', form=form, status=status, pairedStatus=pairedStatus,
                                    fromPerson=fromPerson, toPerson=toPerson, fromPersonLoveinfo=fromPersonLoveinfo,
                                    toPersonLoveinfo=toPersonLoveinfo)
        return render_template('sayLoveU.html',form=form,status=status,pairedStatus=pairedStatus,fromPerson=fromPerson,toPerson=toPerson,fromPersonLoveinfo=fromPersonLoveinfo,toPersonLoveinfo=toPersonLoveinfo)





class LoginForm(FlaskForm):
    email = StringField("请使用科大校内邮箱登陆！ @mail.ustc.edu.cn",validators=[DataRequired(),Length(1,256),Email()])
    password = PasswordField("请输入密码", validators=[DataRequired()])
    remember_me = BooleanField("记住登录状态")
    submit = SubmitField("Log In")

    def validate_email(self, field):
        if not field.data.endswith("@mail.ustc.edu.cn") and not field.data.endswith("@ustc.edu.cn"):
            raise ValidationError('请使用 @mail.ustc.edu.cn 或者 @ustc.edu.cn')



class RegisterForm(FlaskForm):
    email = StringField('电子邮箱', validators=[DataRequired(), Length(1, 64),Email()])
    username = StringField(' 用 户 名', validators=[DataRequired(), Length(1, 64),Regexp('^[A-Za-z][A-Za-z0-9_.]*$', 0,'用户名只能含有字母，数字，点或者下划线')])
    schoolnum = StringField(" 学 号 ",validators=[DataRequired()])
    realname = StringField(" 姓 名 ",validators=[DataRequired()])
    password = PasswordField(' 密 码 ', validators=[DataRequired(), Length(6, 64),EqualTo('password2', message='两次输入的密码必须相等')])
    password2 = PasswordField(' 确 认 密 码', validators=[DataRequired()])
    sex = RadioField(" 性 别 ",choices=[(1,"男") , ( 0 ,"女")],validators=[],coerce=int)
    QQnum = StringField(" QQ 号 码", validators=[DataRequired()])
    submit = SubmitField(' 注 册 ')
    def validate_email(self, field):
        if not field.data.endswith("@mail.ustc.edu.cn") and not field.data.endswith("@ustc.edu.cn"):
            raise ValidationError('请使用 @mail.ustc.edu.cn 或者 @ustc.edu.cn')
        user = User.query.filter_by(userEmail=field.data).first()
        if user is not None and user.userStatus == 1:
            raise ValidationError('电子邮箱已经注册')

    def validate_username(self, field):
        if User.query.filter_by(username=field.data).first():
            raise ValidationError('Username already in use.')


class ChangePasswordForm(FlaskForm):
    old_password = PasswordField(' 旧 密 码 ', validators=[DataRequired()])
    password = PasswordField('新 密 码', validators=[DataRequired(),Length(6, 64), EqualTo('password2', message='两次输入的密码必须相等')])
    password2 = PasswordField('确 认 新 密 码',validators=[DataRequired()])
    submit = SubmitField('确认修改密码')


class PasswordResetRequestForm(FlaskForm):
    email = StringField('您 注 册 的 邮 箱', validators=[DataRequired(), Length(1, 64),Email()])
    submit = SubmitField('重 置 密 码')


class PasswordResetForm(FlaskForm):
    password = PasswordField('新 的 密 码', validators=[
        DataRequired(), EqualTo('password2', message='Passwords must match')])
    password2 = PasswordField('确认新的密码', validators=[DataRequired()])
    submit = SubmitField('重置密码')




@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404


@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500

@app.route('/index')
@app.route('/', methods=['GET', 'POST'])
def index():
    if current_user.is_authenticated and current_user.userStatus ==0:
        return redirect(url_for('unconfirmed'))
    return render_template('index.html')


@app.route('/test')
def testFunc():
    # msg = Message("Test mail",sender="system@maglee.me",recipients=["hkcoldmoon@vip.qq.com"])
    # msg.body="这里是邮件的正文部分"
    # mail.send(msg)
    # mymsg = mySendMailFormat("test sync","system","hkcoldmoon@vip.qq.com","666")
    # simpleSendMail(app,mymsg)
    msg = Message("test",["hkcoldmoon@vip.qq.com"],"666",sender="system@maglee.me")
    mail.send(msg)
    return "send ok"

@app.route('/login',methods=['GET','POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(userEmail=form.email.data).first()
        if user is not None and user.verifyPassword(form.password.data):
            login_user(user,form.remember_me.data)
            next = request.args.get('next')
            if next is None or not next.startswith('/'):
                next = url_for('index')
            return redirect('/')
        flash("用户名或者密码不正确")
    return render_template('auth/login.html',form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("你成功登出账户!")
    return redirect(url_for('index'))



@app.route('/register',methods=['GET','POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        newusername = form.username.data
        newuserpassword = form.password.data
        newuserpassword2 = form.password2.data
        newuseremail = form.email.data
        newusersex = form.sex.data
        newuserQQnum = form.QQnum.data
        newuserschoolnum = form.schoolnum.data
        newuserrealname = form.realname.data
        print(type(newuserrealname))
        if not newuseremail.endswith("@mail.ustc.edu.cn") and newuseremail.endswith("@ustc.edu.cn"):
            flash("用户邮箱请使用ustc校内邮箱地址")
            return redirect(url_for("register"))
        if newuserpassword != newuserpassword2 :
            flash("两次输入密码不相等")
            return redirect(url_for("register"))
        user = User.query.filter_by(userEmail=form.email.data).first()
        if user is None:
            user = User(userEmail=newuseremail,username=newusername,userSchoolNum=newuserschoolnum,userQQnum=newuserQQnum,userSex=newusersex,userRealName=newuserrealname)
        else:
            User.query.filter_by(userEmail=form.email.data).delete()
            user = User(userEmail=newuseremail,username=newusername,userSchoolNum=newuserschoolnum,userQQnum=newuserQQnum,userSex=newusersex,userRealName=newuserrealname)
        user.setPassword(newuserpassword)
        user.userStatus=0
        db.session.add(user)
        db.session.commit()
        token = user.generate_confirmation_token()
        mymsg = mySendMailFormat("Student Union 邀请您激活账户","system@maglee.me",user.userEmail,"","auth/email/confirm",token=token,user=user)
        simpleSendMail(app,mymsg)
        flash(" 注册成功 , 激活账户的邮件已发往您的 ustc 校内邮箱 ！")
        flash("邮件可能标记为垃圾邮件")
        flash("请先在本站登录，再打开你的激活链接")
        return redirect(url_for("login"))
    return render_template("auth/register.html",form = form)


@app.route('/confirm/<token>')
@login_required
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



@app.route('/confirm')
@login_required
def resend_confirmation():
    token = current_user.generate_confirmation_token()
    mymsg = mySendMailFormat("Student Union 邀请您激活账户", "system@maglee.me", current_user.userEmail, "", "auth/email/confirm",token=token,user=current_user)
    simpleSendMail(app, mymsg)
    flash("邮件已经发送,请注意查收！")
    return redirect(url_for('index'))


@app.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    form = ChangePasswordForm()
    if form.validate_on_submit():
        if current_user.verifyPassword(form.old_password.data):
            current_user.setPassword(form.password.data)
            db.session.add(current_user)
            db.session.commit()
            flash('你已经更改密码')
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
            # send_email(user.email, 'Reset Your Password','auth/email/reset_password',user=user, token=token)
            mymsg = mySendMailFormat("Student Union 更改您的账户密码", "system@maglee.me", user.userEmail, "","auth/email/reset_password", token=token, user=user)
            simpleSendMail(app, mymsg)
            flash("邮件已经发送,请注意查收！")
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
            flash('你已经更新了你的密码')
            return redirect(url_for('login'))
        else:
            flash('token错误')
            return redirect(url_for('index'))
    return render_template('auth/reset_password.html', form=form)


if __name__ == "__main__":
    app.run(debug=True)
