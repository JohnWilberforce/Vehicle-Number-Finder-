from flask import Flask, render_template, request, redirect, url_for, flash, Response
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import Length, InputRequired, ValidationError, Email, EqualTo
from flask_login import login_user, UserMixin, LoginManager, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt

app = Flask(__name__)
db = SQLAlchemy(app)
app.secret_key = "Secret Key"
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+mysqlconnector://root:' '@localhost/achie'
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.init_app(app)
login_manager.login_view = "login"


@login_manager.user_loader
def load_user(user_id):
    return Data.query.get(int(user_id))


class Data(db.Model, UserMixin):
    __table_name__ = 'data'
    __table_args__ = {'extend_existing': True}
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(30), unique=True)
    email = db.Column(db.String(40), unique=True)
    password_hash = db.Column(db.String(30))
    veh_number = db.Column(db.String(12), unique=True)
    contact = db.Column(db.String(12))

    def __init__(self, username, email, password_hash, veh_number, contact):
        self.username = username
        self.email = email
        self.password_hash = password_hash
        self.veh_number = veh_number
        self.contact = contact


class RegisterForm(FlaskForm):
    def validate_username(self, username_to_check):
        user = Data.query.filter_by(username=username_to_check.data).first()
        if user:
            raise ValidationError('username already exists! Please try a different username')

    def validate_email(self, email_to_check):
        user = Data.query.filter_by(email=email_to_check.data).first()
        if user:
            raise ValidationError('email already exists! Please try a different email')

    def validate_vehnumber(self, veh_number):
        user = Data.query.filter_by(veh_number=veh_number).first()
        if user:
            raise ValidationError('Vehicle number already exists! Please try a different vehicle number')

    username = StringField(label='User Name', validators=[Length(min=2, max=30), InputRequired()])
    email = StringField(label='Email Address', validators=[Email(), InputRequired()])
    password = PasswordField(label='Password', validators=[Length(min=6), InputRequired()])
    password2 = PasswordField(label='Confirm Password', validators=[EqualTo('password'), InputRequired()])
    veh_number = StringField(label='Vehicle number plate')
    contact = StringField(label='Contact Number')
    submit = SubmitField(label='Create Account')


class LoginForm(FlaskForm):
    username = StringField(label='User Name', validators=[InputRequired()])
    password = PasswordField(label='Password', validators=[InputRequired()])
    submit = SubmitField(label='Sign in')


@app.route('/')
def home_page():
    return render_template('home.html')


@app.route('/return', methods=["GET", "POST"])
def return_page():
    render_template('number.html')


@app.route('/register', methods=["GET", "POST"])
def register_page():
    form = RegisterForm()
    if form.validate_on_submit():
        # hashed_password = bcrypt.generate_password_hash(form.password.data).decode()
        user_to_create = Data(username=form.username.data, email=form.email.data,
                              password_hash=form.password.data,
                              veh_number=form.veh_number.data, contact=form.contact.data)
        db.session.add(user_to_create)
        db.session.commit()
        return redirect(url_for('login_page'))
    if form.errors != {}:
        for err_msg in form.errors.values():
            flash(f'There was an error with creating user: {err_msg}', category='danger')

    return render_template('register.html', form=form)


@app.route('/number', methods=["GET", "POST"])
@login_required
def number_page():
    req1 = request.form.get('vehicle')
    if request.method == "POST":
        req = request.form
        vehicle_no = req.get("vehicle")  # the key is the name'vehicle' in the
        # home.html forms which returns what user input
        # req1 = request.form.get('vehicle')
        # if req1.islower():
        #     flash("Letters must be in Uppercase")
        # elif req1.__contains__('.'):
        #     flash("Vehicle Number Must have hyphen '-' ")
        # elif req1.__contains__('.') and req1.islower:
        #     flash("Vehicle Number Must have hyphen '-' ")
        #     flash("Letters must be in Uppercase")
        # elif req1 != ['A-Z']:
        #     flash("Vehicle Number Must have Letters")

    for item in Data.query.filter_by(veh_number=req1):
        response = (item.username + item.contact)
        if item.username or item.contact:
            return render_template('number.html', res=response)
        else:
            read = '--NOT FOUND YET--'
            return render_template('number.html', read=read)

    return render_template('number.html')


@app.route('/login', methods=["POST", "GET"])
def login_page():
    form = LoginForm()
    if form.validate_on_submit():
        attempted_user = Data.query.filter_by(username=form.username.data).first()
        if attempted_user:
            # if bcrypt.check_password_hash(attempted_user.password_hash, form.password.data):
            if attempted_user.password_hash == form.password.data:
                login_user(attempted_user)
                flash(f'You have successfully logged in as: {attempted_user.username}', category='success')
                return redirect(url_for('number_page'))
            flash('Login unsuccessful. Please check email and password', category='danger')

    return render_template('login.html', form=form)


@app.route('/logout', methods=["POST", "GET"])
@login_required
def logout_page():
    logout_user()
    return redirect(url_for('login_page'))


if __name__ == '__main__':
    app.run(debug=True)
