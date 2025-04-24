from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, FileField
from wtforms.validators import DataRequired, Length
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///forum.db'
app.config['UPLOAD_FOLDER'] = 'static/avatars'

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    avatar = db.Column(db.String(120))
    role = db.Column(db.String(20), default='user')

class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)

class Topic(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    body = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    category_id = db.Column(db.Integer, db.ForeignKey('category.id'), nullable=False)

    user = db.relationship('User', backref='topics')
    category = db.relationship('Category', backref='topics')

class RegisterForm(FlaskForm):
    username = StringField('Логин', validators=[DataRequired(), Length(min=3, max=80)])
    password = PasswordField('Пароль', validators=[DataRequired(), Length(min=4)])
    avatar = FileField('Аватар')
    submit = SubmitField('Зарегистрироваться')

class LoginForm(FlaskForm):
    username = StringField('Логин', validators=[DataRequired()])
    password = PasswordField('Пароль', validators=[DataRequired()])
    submit = SubmitField('Войти')

class CategoryForm(FlaskForm):
    title = StringField('Название категории', validators=[DataRequired()])
    submit = SubmitField('Создать')

class TopicForm(FlaskForm):
    title = StringField('Название', validators=[DataRequired()])
    body = TextAreaField('Сообщение', validators=[DataRequired()])
    submit = SubmitField('Создать')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def index():
    categories = Category.query.all()
    return render_template('index.html', categories=categories)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data)
        avatar_filename = None
        if form.avatar.data:
            avatar_filename = secure_filename(form.avatar.data.filename)
            form.avatar.data.save(os.path.join(app.config['UPLOAD_FOLDER'], avatar_filename))
        user = User(username=form.username.data, password=hashed_password, avatar=avatar_filename)
        db.session.add(user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect(url_for('index'))
        flash('Неверный логин или пароль')
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/create_category', methods=['GET', 'POST'])
@login_required
def create_category():
    if current_user.role != 'admin':
        return redirect(url_for('index'))
    form = CategoryForm()
    if form.validate_on_submit():
        c = Category(title=form.title.data)
        db.session.add(c)
        db.session.commit()
        return redirect(url_for('index'))
    return render_template('create_category.html', form=form)

@app.route('/category/<int:category_id>')
def view_category(category_id):
    category = Category.query.get_or_404(category_id)
    topics = Topic.query.filter_by(category_id=category.id).order_by(Topic.created_at.desc()).all()
    return render_template('category.html', category=category, topics=topics)

@app.route('/category/<int:category_id>/create_topic', methods=['GET', 'POST'])
@login_required
def create_topic(category_id):
    form = TopicForm()
    category = Category.query.get_or_404(category_id)
    if form.validate_on_submit():
        t = Topic(
            title=form.title.data,
            body=form.body.data,
            user_id=current_user.id,
            category_id=category.id
        )
        db.session.add(t)
        db.session.commit()
        return redirect(url_for('view_category', category_id=category.id))
    return render_template('create_topic.html', form=form, category=category)

if __name__ == '__main__':
    app.run(debug=True)
