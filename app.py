from flask import Flask, render_template, redirect, url_for, flash
from werkzeug.security import generate_password_hash, check_password_hash
from flask.ext.sqlalchemy import SQLAlchemy
from flask.ext.login import LoginManager, UserMixin, login_user, logout_user, \
    current_user
from flask.ext.bootstrap import Bootstrap
from flask.ext.wtf import Form
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import Required, Length, EqualTo


# create application instance
app = Flask(__name__)
app.config.from_object('config')

# initialize extensions
bootstrap = Bootstrap(app)
db = SQLAlchemy(app)
lm = LoginManager(app)


class User(UserMixin, db.Model):
    """User model."""
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), index=True)
    password_hash = db.Column(db.String(128))

    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)


@lm.user_loader
def load_user(user_id):
    """User loader callback for Flask-Login."""
    return User.query.get(int(user_id))


class RegisterForm(Form):
    """Registration form."""
    username = StringField('Username', validators=[Required(), Length(1, 64)])
    password = PasswordField('Password', validators=[Required()])
    password_again = PasswordField('Password again',
                                   validators=[Required(), EqualTo('password')])
    submit = SubmitField('Register')


class LoginForm(Form):
    """Login form."""
    username = StringField('Username', validators=[Required(), Length(1, 64)])
    password = PasswordField('Password', validators=[Required()])
    submit = SubmitField('Login')


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    """User registration route."""
    if current_user.is_authenticated():
        # if user is logged in we get out of here
        return redirect(url_for('index'))
    form = RegisterForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is not None:
            flash('Username already exists.')
            return redirect(url_for('register'))
        # add new user to the database
        user = User(username=form.username.data, password=form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('You are now registered!')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login route."""
    if current_user.is_authenticated():
        # if user is logged in we get out of here
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is None or not user.verify_password(form.password.data):
            flash('Invalid username or password.')
            return redirect(url_for('login'))
        # log user in
        login_user(user)
        flash('You are now logged in!')
        return redirect(url_for('index'))
    return render_template('login.html', form=form)


@app.route('/logout')
def logout():
    """User logout route."""
    logout_user()
    return redirect(url_for('index'))


# create database tables if they don't exist yet
db.create_all()


if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)
