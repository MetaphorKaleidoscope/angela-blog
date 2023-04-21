from flask import Flask, render_template, redirect, url_for, flash
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor, request
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
from flask_gravatar import Gravatar
import os  # Issues with take data for db table file
from functools import wraps
from flask import abort  # Like AY



basedir = os.path.abspath(os.path.dirname(__file__))  # Issues with take data for db table file
app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)

# #CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] =\
        'sqlite:///' + os.path.join(basedir, 'blog.db')  # Issues with take data for db table file
# app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
# login_manager.login_view = 'login'

gravatar = Gravatar(app, size=100, rating='g', default='retro', force_default=False, force_lower=False, use_ssl=False,
                    base_url=None)


@login_manager.user_loader
def load_user(user_id):
    return RegisterUser.query.get(int(user_id))


# like AY
def admin_only(f):
    @wraps(f)
    def decorate_function(*args, **kwargs):
        if current_user.id is not 1:
            return abort(403)
        # Otherwise continue with the route function
        return f(*args, **kwargs)
    return decorate_function


# #CONFIGURE TABLES
class RegisterUser(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(250), unique=True, nullable=False)
    password = db.Column(db.String(250), nullable=False)
    name = db.Column(db.String(250), nullable=False)
    posts = relationship('BlogPost', back_populates='users')
    comments = relationship('CommentUser', back_populates='users')


class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    author = db.Column(db.String(250), db.ForeignKey('users.name'))
    users = relationship('RegisterUser', back_populates='posts')
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    comments = relationship('CommentUser', back_populates='blog_posts')


class CommentUser(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    post_id = db.Column(db.Integer,  db.ForeignKey('blog_posts.id'))
    comment = db.Column(db.Text, nullable=False)
    author = db.Column(db.String(250), db.ForeignKey('users.name'))
    users = relationship('RegisterUser', back_populates='comments')
    blog_posts = relationship('BlogPost', back_populates='comments')


with app.app_context():  # Add before add a table  or tablename
    db.create_all()
    db.session.commit()


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts)


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        password_hash = generate_password_hash(form.password.data, method='pbkdf2:sha256', salt_length=8)
        email = form.email.data
        user = RegisterUser.query.filter_by(email=email).first()
        if not user:
            with app.app_context():
                db.create_all()
                new_user = RegisterUser(email=email, password=password_hash, name=form.name.data)
                db.session.add(new_user)
                db.session.commit()
                # Log and authenticate user after adding details to database
                login_user(new_user)
                return redirect(url_for("get_all_posts"))
        else:
            flash("You've already signed up with that email, log in instead!")
            return render_template("login.html", form=form)
    return render_template("register.html", form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = request.form.get('email')
        password = request.form.get('password')
        user = RegisterUser.query.filter_by(email=email).first()
        if user:
            if check_password_hash(user.password, password):
                login_user(user)
                return redirect(url_for("get_all_posts"))
            else:
                flash("Wrong password -Try Again!")
        else:
            flash("That email doesn't Exist! -Try Again!")
            return render_template("login.html", form=form)
    return render_template("login.html", form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=['GET', 'POST'])
def show_post(post_id):
    form_comment = CommentForm()
    requested_post = BlogPost.query.get(post_id)
    requested_comments = requested_post.comments
    if form_comment.validate_on_submit():
        if 'UserMixin' not in str(current_user):
            # print(current_user.email)
            with app.app_context():
                db.create_all()
                new_comment = CommentUser(post_id=post_id, comment=request.form.get('comment'), users=current_user)
                db.session.add(new_comment)
                db.session.commit()
                return redirect(url_for("get_all_posts"))
        else:
            flash("You need to login or register to comment.")
            return redirect(url_for("login"))
        # comment(post_id)
    return render_template("post.html", post=requested_post, form=form_comment, comments=requested_comments)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post", methods=['GET', 'POST'])
@login_required
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        with app.app_context():
            db.create_all()
            new_post = BlogPost(
                title=form.title.data,
                subtitle=form.subtitle.data,
                img_url=form.img_url.data,
                author=current_user.name,  # form.author.data,  # current_user, #this when be login
                body=form.body.data,
                date=date.today().strftime("%B %d, %Y")
            )
            db.session.add(new_post)
            db.session.commit()
            return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>", methods=['GET', 'POST'])
@login_required
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = request.form.get('title')
        post.subtitle = request.form.get('subtitle')
        post.img_url = request.form.get('img_url')
        post.author = request.form.get('author')
        post.body = request.form.get('body')
        db.session.commit()
        return redirect(url_for("show_post", post_id=post_id))

    return render_template("make-post.html", form=edit_form)


@app.route("/delete/<int:post_id>")
@login_required
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)
