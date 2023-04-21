from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, EmailField
from wtforms.validators import DataRequired, URL
from flask_ckeditor import CKEditorField
from wtforms import validators


# #WTForm
class CreatePostForm(FlaskForm):
    title = StringField("Blog Post Title", validators=[DataRequired()])
    subtitle = StringField("Subtitle", validators=[DataRequired()])
    img_url = StringField("Blog Image URL", validators=[DataRequired(), URL()])
    author = StringField("author", validators=[DataRequired()])
    body = CKEditorField("Blog Content", validators=[DataRequired()])
    submit = SubmitField("Submit Post")


class RegisterForm(FlaskForm):
        email = EmailField(label='Email', validators=[DataRequired(), validators.Email()])
        password = PasswordField("Password", validators=[DataRequired()])
        name = StringField("Name", validators=[DataRequired()])
        submit = SubmitField(label="SING ME UP!")


class LoginForm(FlaskForm):
    email = EmailField(label='Email', validators=[DataRequired(), validators.Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    name = StringField("Name", validators=[DataRequired()])
    submit = SubmitField(label="LET ME IN!")


class CommentForm(FlaskForm):
    comment = CKEditorField("Comment", validators=[DataRequired()])
    submit = SubmitField(label="SUBMIT COMMENT")