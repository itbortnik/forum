import os
from datetime import datetime
from flask import Flask, render_template, redirect, url_for, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, FileField, SelectField, BooleanField
from wtforms.validators import DataRequired, ValidationError
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///forum.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static', 'avatars')
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), index=True, unique=True)
    password_hash = db.Column(db.String(128))
    role = db.Column(db.String(32), default='user')
    avatar = db.Column(db.String(128))
    banned = db.Column(db.Boolean, default=False)
    muted = db.Column(db.Boolean, default=False)
    topics = db.relationship('Topic', backref='author', lazy='dynamic')
    comments = db.relationship('Comment', backref='author', lazy='dynamic')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128), unique=True)
    description = db.Column(db.String(256))
    topics = db.relationship('Topic', backref='category', lazy='dynamic', cascade='all, delete-orphan')


class Topic(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(128))
    content = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    category_id = db.Column(db.Integer, db.ForeignKey('category.id'))
    comments = db.relationship('Comment', backref='topic', lazy='dynamic')


class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    topic_id = db.Column(db.Integer, db.ForeignKey('topic.id'))


@login_manager.user_loader
def load_user(id):
    return User.query.get(int(id))


class RegistrationForm(FlaskForm):
    username = StringField('Имя пользователя', validators=[DataRequired()])
    password = PasswordField('Пароль', validators=[DataRequired()])
    avatar = FileField('Аватар')
    submit = SubmitField('Зарегистрироваться')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user is not None:
            raise ValidationError('Имя пользователя уже занято')


class LoginForm(FlaskForm):
    username = StringField('Имя пользователя', validators=[DataRequired()])
    password = PasswordField('Пароль', validators=[DataRequired()])
    submit = SubmitField('Войти')


class CategoryForm(FlaskForm):
    name = StringField('Название категории', validators=[DataRequired()])
    description = TextAreaField('Описание')
    submit = SubmitField('Создать категорию')


class TopicForm(FlaskForm):
    title = StringField('Заголовок', validators=[DataRequired()])
    content = TextAreaField('Содержание', validators=[DataRequired()])
    submit = SubmitField('Создать тему')


class CommentForm(FlaskForm):
    content = TextAreaField('Сообщение', validators=[DataRequired()])
    submit = SubmitField('Отправить')


class UserEditForm(FlaskForm):
    role = SelectField('Роль',
                       choices=[
                           ('user', 'Пользователь'),
                           ('moderator', 'Модератор'),
                           ('admin', 'Администратор')
                       ],
                       validators=[DataRequired()],
                       render_kw={'disabled': False}
                       )
    banned = BooleanField('Заблокировать аккаунт')
    muted = BooleanField('Ограничить права на публикацию')
    submit = SubmitField('Сохранить изменения')


@app.route('/')
def index():
    categories = Category.query.all()
    return render_template('index.html', categories=categories)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data)
        user.set_password(form.password.data)

        if form.avatar.data:
            file = form.avatar.data
            if allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                user.avatar = filename

        db.session.add(user)
        db.session.commit()
        flash('Регистрация прошла успешно!', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is None or not user.check_password(form.password.data):
            flash('Неверное имя пользователя или пароль', 'danger')
            return redirect(url_for('login'))
        if user.banned:
            flash('Ваш аккаунт заблокирован', 'danger')
            return redirect(url_for('login'))
        login_user(user)
        return redirect(url_for('index'))
    return render_template('login.html', form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.route('/profile/<int:user_id>')
@login_required
def profile(user_id):
    user = User.query.get_or_404(user_id)
    return render_template('profile.html', user=user)


@app.route('/my_profile')
@login_required
def my_profile():
    return redirect(url_for('profile', user_id=current_user.id))


@app.route('/create_category', methods=['GET', 'POST'])
@login_required
def create_category():
    if current_user.role != 'admin':
        return redirect(url_for('index'))
    form = CategoryForm()
    if form.validate_on_submit():
        category = Category(name=form.name.data, description=form.description.data)
        db.session.add(category)
        db.session.commit()
        flash('Категория создана!', 'success')
        return redirect(url_for('index'))
    return render_template('create_category.html', form=form)


@app.route('/category/<int:category_id>/create_topic', methods=['GET', 'POST'])
@login_required
def create_topic(category_id):
    if current_user.banned or current_user.muted:
        flash('Ваш аккаунт ограничен в правах', 'danger')
        return redirect(url_for('index'))
    form = TopicForm()
    category = Category.query.get_or_404(category_id)
    if form.validate_on_submit():
        topic = Topic(
            title=form.title.data,
            content=form.content.data,
            author=current_user,
            category=category
        )
        db.session.add(topic)
        db.session.commit()
        flash('Тема создана!', 'success')
        return redirect(url_for('index'))
    return render_template('create_topic.html', form=form, category=category)


@app.route('/topic/<int:topic_id>', methods=['GET', 'POST'])
def topic(topic_id):
    topic = Topic.query.get_or_404(topic_id)
    form = CommentForm()

    if form.validate_on_submit():
        if not current_user.is_authenticated:
            flash('Для комментирования необходимо войти в систему', 'warning')
            return redirect(url_for('login'))

        if current_user.banned or current_user.muted:
            flash('Ваш аккаунт ограничен в правах', 'danger')
            return redirect(url_for('topic', topic_id=topic_id))

        comment = Comment(
            content=form.content.data,
            author=current_user,
            topic=topic
        )
        db.session.add(comment)
        db.session.commit()
        return redirect(url_for('topic', topic_id=topic_id))

    comments = topic.comments.order_by(Comment.created_at.desc()).all()
    return render_template('topic.html',
                           topic=topic,
                           form=form,
                           comments=comments)


@app.route('/delete_topic/<int:topic_id>')
@login_required
def delete_topic(topic_id):
    topic = Topic.query.get_or_404(topic_id)
    if current_user.role in ['admin', 'moderator']:
        db.session.delete(topic)
        db.session.commit()
        flash('Тема удалена', 'success')
    return redirect(url_for('index'))


@app.route('/delete_category/<int:category_id>')
@login_required
def delete_category(category_id):
    if current_user.role != 'admin':
        flash('Недостаточно прав', 'danger')
        return redirect(url_for('index'))

    category = Category.query.get_or_404(category_id)
    db.session.delete(category)
    db.session.commit()
    flash('Категория удалена', 'success')
    return redirect(url_for('index'))


@app.route('/admin/users')
@login_required
def admin_users():
    if current_user.role not in ['admin', 'moderator']:
        return redirect(url_for('index'))
    users = User.query.all()
    return render_template('admin_users.html', users=users)


@app.route('/admin/edit_user/<int:user_id>', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    if current_user.role not in ['admin', 'moderator']:
        return redirect(url_for('index'))

    user = User.query.get_or_404(user_id)
    form = UserEditForm(obj=user)

    if current_user.role == 'moderator' and user.role in ['admin', 'moderator']:
        flash('Недостаточно прав', 'danger')
        return redirect(url_for('admin_users'))

    if form.validate_on_submit():
        if user.id == current_user.id:
            if form.role.data != current_user.role or form.banned.data or form.muted.data:
                flash('Вы не можете изменять свою роль или блокировать себя', 'danger')
                return redirect(url_for('edit_user', user_id=user_id))

        if user.role == 'admin' and user.id != current_user.id:
            flash('Нельзя редактировать других администраторов', 'danger')
            return redirect(url_for('admin_users'))

        if current_user.role == 'admin' and user.role != 'admin':
            user.role = form.role.data
            user.banned = form.banned.data
            user.muted = form.muted.data

        db.session.commit()
        flash('Изменения сохранены', 'success')
        return redirect(url_for('admin_users'))

    return render_template('edit_user.html', form=form, user=user)


def allowed_file(filename):
    return '.' in filename and \
        filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']


with app.app_context():
    db.create_all()
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

if __name__ == '__main__':
    app.run(debug=True)
