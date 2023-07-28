from flask import Flask, render_template, redirect, url_for, flash, request
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
from functools import wraps
from flask import abort
from flask_gravatar import Gravatar

from mail import Message
import smtplib

# Constants
MY_EMAIL = "EMAIL"
PASSWORD = "PASSWORD"
ADMIN_ACCOUNT = "EMAIL"

# -------------------- Initialization ------------------------------#
app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)
# ICON FOR USER
gravatar = Gravatar(app, size=100, rating='g',
                    default='retro', force_default=False,
                    force_lower=False, use_ssl=False, base_url=None)

# -------------------- Connect To Database------------------------------#
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# -------------------- Login Manager ------------------------------#
login_manager = LoginManager()
login_manager.init_app(app)


# You will need to provide a user_loader callback.
# This callback is used to reload the user object from the user ID stored in the session.
# It should take the str ID of a user, and return the corresponding user object.
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# ---------------- Models For Database--------------------#


# Model for posts
class BlogPost(db.Model):
    # Name for table
    __tablename__ = "blog_posts"
    # ID
    id = db.Column(db.Integer, primary_key=True)
    # Create Foreign Key, "users.id" the users refers to the tablename of User.
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    # Create reference to the User object, the "posts" refers to the posts property in the User class.
    author = relationship("User", back_populates="posts")
    # Title of the post
    title = db.Column(db.String(250), unique=True, nullable=False)
    # Subtitle of the post
    subtitle = db.Column(db.String(250), nullable=False)
    # Date when the post will be written
    date = db.Column(db.String(250), nullable=False)
    # Text of the post
    body = db.Column(db.Text, nullable=False)
    # Image for the post
    img_url = db.Column(db.String(250), nullable=False)
    # Lis of the comments for post
    comments = relationship("Comment", back_populates="comment_post")


# Model for users
class User(UserMixin, db.Model):
    # Name for table
    __tablename__ = "users"
    # ID of the user
    id = db.Column(db.Integer, primary_key=True)
    # Email of the user
    email = db.Column(db.String(100), unique=True)
    # Password of the user
    password = db.Column(db.String(100))
    # Name of the user
    name = db.Column(db.String(1000))
    # List of comments of the user
    comments = relationship("Comment", back_populates="comment_author")
    # List of the posts of the user
    posts = relationship("BlogPost", back_populates="author")


# Model for comments
class Comment(db.Model):
    # Name for table
    __tablename__ = "comments"
    # ID for comment
    id = db.Column(db.Integer, primary_key=True)
    # Create Foreign Key, "users.id" the users refers to the tablename of User.
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    # Create reference to the User object, the "posts" refers to the posts property in the User class.
    comment_author = relationship("User", back_populates="comments")
    # Text of the comment
    text = db.Column(db.Text, nullable=False)
    # Refer to post
    # Every post has own list of comments
    post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"))
    comment_post = relationship("BlogPost", back_populates="comments")


# Creating database
db.create_all()


# Python decorator
# It helps to recognize if the user is admin(ID = 1)
# Only admin can do specific task
def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # If id is not 1 then return abort with 403 error
        if current_user.get_id() != "1":
            return abort(403)
        # Otherwise continue with the route function
        return f(*args, **kwargs)
    return decorated_function

# ---------------- Function for navbar item --------------------#


# Function for home page
# It shows all post on webpage
@app.route('/')
def get_all_posts():
    # Get all post from database
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts,
                           logged_in=current_user.is_authenticated,
                           user_id=current_user.get_id())


# Function for about page
@app.route("/about")
def about():
    return render_template("about.html", logged_in=current_user.is_authenticated)


# Function for contact page
@app.route("/contact", methods=["POST", "GET"])
def contact():
    if request.method == "POST":
        with smtplib.SMTP("smtp.gmail.com") as connection:
            connection.starttls()
            connection.login(user=MY_EMAIL, password=PASSWORD)
            connection.sendmail(from_addr=MY_EMAIL, to_addrs=ADMIN_ACCOUNT,
                                msg=f"Subject:MESSAGE FROM PAGE\n\n Name: {request.form.get('username')}\n Email address: { request.form.get('email')}\n Phone:{request.form.get('phone')}\n Message: {request.form.get('message')}")
        text = 'Succefully send your message'
        return render_template("contact.html", text_h1=text)
    text = "Contact Me"

    return render_template("contact.html", logged_in=current_user.is_authenticated, text_h1=text)


# ---------------- Function for users --------------------#

# Register user
@app.route('/register', methods=["GET", "POST"])
def register():
    # Form for register new user
    user_form = RegisterForm()
    # POST METHOD, send a form
    if user_form.validate_on_submit():
        # Check if the potential new user not in database
        user = User.query.filter_by(email=user_form.email.data).first()
        if user:
            # If user is in database, send message and redirect to login page
            flash("You've already signed up with that email, log in instead!")
            # Redirect to /login route.
            return redirect(url_for('login'))

        # -----------------Adding new user-----------------------
        # Hashed password
        hash_and_salted_password = generate_password_hash(user_form.password.data, method='pbkdf2:sha256',
                                                          salt_length=8)
        # New instance from User class
        new_user = User(
            email=user_form.email.data,
            password=hash_and_salted_password,
            name=user_form.name.data
        )
        # Adding new user into database
        db.session.add(new_user)
        db.session.commit()

        # Log in and authenticate user after adding details to database.
        login_user(new_user)

        # Redirect to page with all posts
        return redirect(url_for("get_all_posts"))
    # Get method
    return render_template("register.html", form=user_form)


# Loging in for user
@app.route('/login', methods=["GET", "POST"])
def login():
    # Form for logging user
    log_in_form = LoginForm()
    # Post method
    if log_in_form.validate_on_submit():
        password = log_in_form.password.data
        # Check if the user is in database
        user = User.query.filter_by(email=log_in_form.email.data).first()
        if user:
            # Check if the password is correct
            if check_password_hash(user.password, password):
                # Login user
                login_user(user)
                # Redirect to page with all posts
                return redirect(url_for('get_all_posts'))
            else:
                # If the password is wrong, redirect to login page with message
                flash("The password is incorrect, try again!")
                return redirect(url_for('login'))
        else:
            # If the email is wrong, redirect to login page with message
            flash("The email does not exist, try again!")
            return redirect(url_for('login'))
    # Get method
    return render_template("login.html", form=log_in_form)


# Logout user
@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))

# ---------------- Function for posts --------------------#


# Show specific post
@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    # Get post from database by id
    requested_post = BlogPost.query.get(post_id)
    # Form for new comment under post
    comment_form = CommentForm()
    # Post method
    if comment_form.validate_on_submit():
        # If the use is not logged in, he cant add new comment, so he will be redirected to login page with message
        if not current_user.is_authenticated:
            flash("You need to login or register to comment.")
            return redirect(url_for('login'))
        # If user is logged in, he can add new comment
        # Instance of new comment
        new_comment = Comment(
            text=comment_form.body.data,
            comment_author=current_user,
            comment_post=requested_post
        )
        # Adding to new comment into database
        db.session.add(new_comment)
        db.session.commit()
    # Get method
    return render_template("post.html", post=requested_post, logged_in=current_user.is_authenticated,
                           user_id=current_user.get_id(), form=comment_form)


# Add new post
# Only Admin add new post
@app.route("/new-post", methods=["GET", "POST"])
@admin_only
def add_new_post():
    # Form for creating new post
    form = CreatePostForm()
    # Post method
    if form.validate_on_submit():
        # New instance of the post
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        # Adding new post into database
        db.session.add(new_post)
        db.session.commit()
        # redirect to page with all post
        return redirect(url_for("get_all_posts"))

    # Get method
    return render_template("make-post.html", form=form, logged_in=current_user.is_authenticated)


# Edit post
@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@admin_only
def edit_post(post_id):
    # Get post from database by its id
    post = BlogPost.query.get(post_id)
    # Form for editing post
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    # Post method
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = edit_form.author.data
        post.body = edit_form.body.data
        # Update changes in database
        db.session.commit()
        # Redirect to page with the post
        return redirect(url_for("show_post", post_id=post.id))

    # Get method
    return render_template("make-post.html", form=edit_form, logged_in=current_user.is_authenticated)


# Delete post by its id
# Only Admin can delete posts
@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    # Get post from database by id
    post_to_delete = BlogPost.query.get(post_id)
    # Delete post
    db.session.delete(post_to_delete)
    # Commit
    db.session.commit()
    # Redirect to home page with all posts
    return redirect(url_for('get_all_posts'))


# The main function for program
if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5003, debug=True)
