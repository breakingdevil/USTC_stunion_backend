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
from flask_login import login_required , login_user,login_fresh,login_url,LoginManager,UserMixin,logout_user

basedir = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)
app.config['SECRET_KEY'] = ''
app.config['SQLALCHEMY_DATABASE_URI'] = ""
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False


app.config['MAIL_SERVER'] = ''  #  这里用163邮件服务器
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_TLS'] = True        # 启用安全传输层协议
app.config['MAIL_USERNAME'] = ""      # 从系统环境变量加载用户名和密码
app.config['MAIL_PASSWORD'] = ""

mail = Mail(app)

login_manager = LoginManager(app)
bootstrap = Bootstrap(app)
moment = Moment(app)
db = SQLAlchemy(app)


def mySendMailFormat(mailSubject,mailSender,mailRecv,mailBody):
    msg = Message(mailSubject, sender=mailSender, recipients=[mailRecv])
    msg.body = mailBody
    return msg


class User(UserMixin,db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, index=True)
    userEmail = db.Column(db.String(64),unique=True, index=True)
    userAccountLevel = db.Column(db.Integer,nullable=True)
    userRealName = db.Column(db.String(64),nullable=True)
    userSchoolNum = db.Column(db.String(64),nullable=True)
    userQQnum = db.Column(db.String(64),nullable=True)
    userSex = db.Column(db.String(64),nullable=True)
    userWeChatNum = db.Column(db.String(64),nullable=True)
    userCellPhoneNum = db.Column(db.String(64),nullable=True)
    userOpenid = db.Column(db.String(256),nullable=True)
    userPasswordHash = db.Column(db.String(256),nullable=True)
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'))

    def setPassword(self,password):
        self.userPasswordHash = generate_password_hash(password)
        return

    def verifyPassword(self,password):
        return check_password_hash(self.userPasswordHash,password)

    def __repr__(self):
        return '<User %r>' % self.username


@login_manager.user_loader
def loadUser(user_id):
    return User.query.get(int(user_id))



class NameForm(FlaskForm):
    name = StringField('What is your name?', validators=[DataRequired()])
    submit = SubmitField('Submit')


class LoginForm(FlaskForm):
    email = StringField("请使用科大校内邮箱登陆！ @mail.ustc.edu.cn",validators=[DataRequired(),Length(1,256),Email()])
    password = PasswordField("请输入密码", validators=[DataRequired()])
    remember_me = BooleanField("记住登录状态")
    submit = SubmitField("Log In")


@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404


@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500


@app.route('/', methods=['GET', 'POST'])
def index():
    return render_template('index.html')

@app.route('/test')
def testFunc():
    # msg = Message("Test mail",sender="system@maglee.me",recipients=["hkcoldmoon@vip.qq.com"])
    # msg.body="这里是邮件的正文部分"
    # mail.send(msg)
    return "send ok"

@app.route('/login',methods=['GET','POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
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
    return redirect(url_for('/'))

if __name__ == "__main__":
    app.run()