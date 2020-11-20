from flask import Flask, render_template, redirect, url_for, flash
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm, RecaptchaField 
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import InputRequired, Email, Length, EqualTo, ValidationError, DataRequired
from flask_sqlalchemy  import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_mail import Mail, Message
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from flask_bcrypt import Bcrypt

login_app = Flask(__name__)
login_app.config['SECRET_KEY'] = 'Thisissupposedtobesecret!'
login_app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///data.db'
login_app.config['RECAPTCHA_PUBLIC_KEY'] = '6Ld1XNsZAAAAAAfW-9sNXt0ysjVwQ5lsXfPkYzbF'
login_app.config['RECAPTCHA_PRIVATE_KEY'] = '6Ld1XNsZAAAAAJfIz-vaqXtiEuFN0s8AjJObqVXU'

login_app.config['MAIL_SERVER'] = 'smtp.gmail.com'
login_app.config['MAIL_PORT'] = 587
login_app.config['MAIL_USE_TLS'] = True
login_app.config['MAIL_USERNAME'] = 'pednekar37419@gmail.com'
login_app.config['MAIL_PASSWORD'] = 'Sona4999'

bootstrap = Bootstrap(login_app)
db = SQLAlchemy(login_app)
login_manager = LoginManager()
login_manager.init_app(login_app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

mail = Mail(login_app)
bcrypt = Bcrypt(login_app)



###################### models.py ##########################


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80))


    def get_reset_token(self, expires_sec= 1800):
        s = Serializer(login_app.config["SECRET_KEY"], expires_sec)
        return s.dumps({'user_id': self.id}).decode('utf-8')

    @staticmethod
    def verify_reset_token(token):
        s = Serializer(login_app.config["SECRET_KEY"])
        try:
            user_id = s.loads(token)['user_id']
        except:
            print("None!!!!!!!!!!!!!!!!!!!!!!!!")
            return None
        print("User is chill!!!!!!!!!!!!!!!!!!!")
        return User.query.get(user_id)

    def __repr__(self):
        return f'User({self.id}, {self.username})'
     
    #def get_reset_token(self, expires_sec=1800):
    #    s = Serializer(login_app.config['SECRET_KEY'], expires_sec)
    #    return s.dumps({'user_id': self.id}).decode('utf-8')
      

    #@staticmethod
    #def verify_reset_token(token):
    #    s = Serializer(login_app.config['SECRET_KEY'])
    #    try:
    #        user_id = s.loads(token)['user_id']
    #    except:
    #        return None
    #    return User.query.get(user_id)

    #def __repr__(self):
    #    return f"User('{self.username}', '{self.email}')"


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))



###################### forms.py #########################


class LoginForm(FlaskForm):
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])
    remember = BooleanField('remember me')
    recaptcha = RecaptchaField()
    

class RegisterForm(FlaskForm):
    email = StringField('email', validators=[InputRequired(), Email(message='Invalid email'), Length(max=50)])
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])
    recaptcha = RecaptchaField()
    def validate_username(self, username):
        if User.query.filter_by(username=username.data).first():
            raise ValidationError("This username is taken! Choose another")
    def validate_email(self, email):
        if User.query.filter_by(email=email.data).first():
            raise ValidationError("This email already exists! Please log in!")


class RequestResetForm(FlaskForm):
    email = StringField('email', validators=[InputRequired(), Email(message='Invalid email'), Length(max=50)])
    submit = SubmitField('Request Password Reset')

    def validate_email(self,email):
        user = User.query.filter_by(email = email.data).first()
        if user is None:
            raise ValidationError('There is no account with that email. You must register first.')


class ResetPasswordForm(FlaskForm):
    password = PasswordField('New Password', validators=[DataRequired(), Length(min=8, max=80)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), Length(min=8, max=80)])
    submit = SubmitField('Reset Password')




########################## routes.py ###########################


@login_app.route('/')
def home():
    return render_template('home.html')


@login_app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user, remember=form.remember.data)
                return redirect(url_for('profile'))

        return '<h1>Invalid username or password</h1>'
        #return '<h1>' + form.username.data + ' ' + form.password.data + '</h1>'

    return render_template('login.html', form=form)

@login_app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        new_user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return '<h1>New user has been created!</h1>'
        #return '<h1>' + form.username.data + ' ' + form.email.data + ' ' + form.password.data + '</h1>'

    return render_template('signup.html', form=form)

@login_app.route('/profile')
@login_required
def profile():
    return render_template('profile.html', name=current_user.username,id=current_user.id)

@login_app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))


@login_app.route("/user/<string:username>")

def send_reset_email(user):
    token = user.get_reset_token()
    msg = Message('Password Reset Request',
                  sender='pednekar37419@gmail.com',
                  recipients=[user.email])
    msg.body = f'''To reset your password, visit the following link:
{url_for('reset_token', token=token, _external=True)}
If you did not make this request then simply ignore this email and no changes will be made.
'''
    mail.send(msg)


@login_app.route("/reset_password", methods=['GET', 'POST'])
def reset_request():
    form = RequestResetForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        send_reset_email(user)
        flash('An email has been sent with instructions to reset your password.','info')
        return redirect(url_for('login'))
    return render_template('reset_request.html', title = 'Reset Password', form = form)


@login_app.route("/reset_password/<token>", methods=['GET', 'POST'])
def reset_token(token):
    #if current_user.is_authenticated: #User needs to be logged out to change password...
    #    return redirect(url_for('home'))
    user = User.verify_reset_token(token)

    if user is None:
        flash(F"Invalid or expired token", "warning")
        return redirect(url_for("reset_request"))
    else:
        form = ResetPasswordForm()
        if form.validate_on_submit():
            # hashing the password...
            hashed_pass = bcrypt.generate_password_hash(form.password.data).decode('utf-8')

            # Adding to database...
            user.password = hashed_pass
            db.session.commit()

            flash(f'Password is updated ! Login Now!!', 'success')
            return redirect(url_for('login'))
        return render_template('reset_token.html', title="Reset Password", form =form)


#def reset_token(token):    
#    user = User.verify_reset_token(token)
#    if user is None:
#        flash('That is an invalid or expired token', 'warning')
#        return redirect(url_for('reset_request'))
#    form = ResetPasswordForm()
#    if form.validate_on_submit():
#        hashed_password = generate_password_hash(form.password.data, method='sha256')
#        user.password = hashed_password
#        db.session.commit()
#        flash('Your password has been updated! You are now able to log in', 'success')
#        return redirect(url_for('login'))
#    else:
#        return render_template('reset_token.html', title='Reset Password', form=form)



    #if form.validate_on_submit():
    #    hashed_password = generate_password_hash(form.password.data, method='sha256')
    #    user.password = hashed_password
    #    db.session.commit()
    #    flash('Your password has been updated! You are now able to log in', 'success')
    #    return redirect(url_for('login'))

    #return render_template('reset_token.html', title='Reset Password', form=form)
    
if __name__ == '__main__':
    login_app.run(debug=True)