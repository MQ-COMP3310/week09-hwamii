from flask import Blueprint, render_template, request, flash, redirect, url_for
from flask_login import login_user, login_required, logout_user
from sqlalchemy import text
from .models import User
from werkzeug.security import generate_password_hash, check_password_hash
from . import db, app

auth = Blueprint('auth', __name__)

@auth.route('/login')
def login():
    return render_template('login.html')

@auth.route('/login', methods=['POST'])
def login_post():
    email = request.form.get('email')
    password = request.form.get('password') #this is bad because it is plaintext, one should first hash the password and then compare it with the stored hash
    remember = True if request.form.get('remember') else False 

    user = User.query.filter_by(email=email).first()

    # check if the user actually exists
    # take the user-supplied password and compare it with the stored password
    if not user or (user.password != password):  #changed from user.password == password to user.password != password
        flash('Please check your login details and try again.')
        app.logger.warning("User login failed")
        return redirect(url_for('auth.login')) # if the user doesn't exist or password is wrong, reload the page

    # if the above check passes, then we know the user has the right credentials
    login_user(user, remember=remember)
    return redirect(url_for('main.profile'))

@auth.route('/signup')
def signup():
    return render_template('signup.html')

@auth.route('/signup', methods=['POST'])
def signup_post():
    email = request.form.get('email')
    name = request.form.get('name')
    password = request.form.get('password') #this is bad because it is plaintext, one should first hash the password and then compare it with the stored hash

    # this is unsafe because its concatenating user input directly
    # user = db.session.execute(text('select * from user where email = "' + email +'"')).all()

    # instead, use parameterised queries
    # user = db.session.execute(text('select * from user where email = :email'), {'email': email}).all()
    # or
    statement = text("SELECT * FROM user WHERE email = :email")
    user = db.session.execute(statement, {'email': email}).all()


    if len(user) > 0: # if a user is found, we want to redirect back to signup page so user can try again
        flash('Email address already exists')  # 'flash' function stores a message accessible in the template code.
        app.logger.debug("User email already exists")
        return redirect(url_for('auth.signup'))

    # create a new user with the form data. TODO: Hash the password so the plaintext version isn't saved.
    hash_password = generate_generate_password_hash(password, method='pbkdf2:sha256', salt_length=16)
    new_user = User(email=email, name=name, password=hash_password)
    # old unsafe method
    # new_user = User(email=email, name=name, password=password)

    # add the new user to the database
    db.session.add(new_user)
    db.session.commit()

    return redirect(url_for('auth.login'))

@auth.route('/logout')
@login_required
def logout():
    logout_user();
    return redirect(url_for('main.index'))

# See https://www.digitalocean.com/community/tutorials/how-to-add-authentication-to-your-app-with-flask-login for more information
