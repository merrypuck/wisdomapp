#--------------------

    # routes.py is a Flask server script for routing wisdom.ly v1.1
    # created at Tiger Labs - Princeton, NJ 
    # on Monday June 17, 2013

#--------------------
import os, re
import datetime
from flask import Flask, render_template, session, request, flash, url_for, redirect
import flask.views 

# forms.py handles form creation and validation 
from forms import ContactForm, SignUp, SignIn, CreateSeminar

# handles automatic mail service
from flask.ext.mail import Message, Mail 

# handles password hashing
from flaskext.bcrypt import Bcrypt

# python + mongo
import pymongo 
from pymongo import MongoClient
#--------------------------------------------------------------------------
app = Flask(__name__)

# initiates mongo within python
client = MongoClient('localhost')

# set our users collection to users_collection
users_collection = client.wisdom.users

#initiate password hashing
bcrypt = Bcrypt(app)

# key for POST security
app.secret_key = "dylan"

# automatic mail configuration
mail = Mail()
app.config["MAIL_SERVER"] = "smtp.gmail.com"
app.config["MAIL_PORT"] = 465
app.config["MAIL_USE_SSL"] = True
app.config["MAIL_USERNAME"] = 'aaron@wisdom.ly'
app.config["MAIL_PASSWORD"] = 'lastmorning123'
mail.init_app(app)

#----------------------------------
    # userAuth
    # function for user authentication
    # accepts user id, password as parameters
    # and returns userData if successfull
#----------------------------------

def userAuth(user, password):
    if re.match("[^@]+@[^@]+\.[^@]+", user):
        if users_collection.find({'email': user}).limit(1).count() == 1:
            userData = users_collection.find({'email':user})
            for field in userData:
                if bcrypt.check_password_hash(field['password'], password):
                    return userData

    elif user.__len__() > 0:
        if users_collection.find({'username': user}).limit(1).count() == 1:
            userData = users_collection.find({'username': user})
            for field in userData:
                if field['username'] == user:
                    if bcrypt.check_password_hash(field['password'], password):
                        return userData
    else:
        flash('Username or password is invalid.')
        return render_template('signin.html', form=form)

@app.route('/', methods=['GET','POST'])
def home():
    form = SignIn()
    if request.method == 'GET':
        return render_template('home.html', form=form)

    elif request.method == 'POST':
        if form.validate() == False:
            flash('All fields are required')
            return render_template('signin.html', form=form)

        else:
            userData = userAuth(form.username.data, form.password.data)
            for field in userData:
                session['email'] = field['email']
            return redirect(url_for('profile'))
    else:
        flash('Your username/email or password is incorrect')
        return render_template('signin.html')
                

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = SignUp()
    if request.method == 'GET':
        if 'email in session:':
            return redirect(url_for('myprofile'))
    elif request.method == 'POST':
        if form.validate() == False:
            flash('All fields are required')
            return render_template('signup.html', form=form)
            # finds if a user exists with specificed email
        elif users_collection.find({'email': form.email.data}).limit(1).count() == 1:
            flash("This email has already been used.")
            return render_template('signup.html', form=form)
            # finds if a user exists with specificed username
        elif users_collection.find({'username':form.username.data}).limit(1).count() == 1:
            flash("Sorry, that username is already taken.")
            return render_template('signup.html', form=form)

        # adds new user to database, sends email, initiates new session,
        # redirects to myprofile.html
        else:
            #hash password
            pw_hash = bcrypt.generate_password_hash(form.password.data)
            # add user to wisdom.users db
            users_collection.insert({'firstName' : form.firstName.data, 'lastName' : form.lastName.data, 'email' : form.email.data, 'username' : form.username.data, 'password':pw_hash, 'createdAt':datetime.datetime.now()})
            
            # creates new cookie session based on email
            session['email'] = form.email.data

            msg = Message(
                'Wisdom.ly account confirmation',
                # sender
                sender='aaron@thecompassmag.com',
                # recipient
                recipients=[form.email.data]
                )

            msg.body = """
            %s, 
                Please authenticate your email by pressing this 'link'
                
            """ % (form.firstName.data)
            mail.send(msg)

            # redirects to custom profile based on session
            userData = users_collection.find({'email':session['email']})
            return redirect(url_for('myprofile', userData = userData))


@app.route('/signin', methods=['GET', 'POST'])
def signin():
    form = SignIn()
    if request.method == 'GET':
        if 'email' in session:
            userData = users_collection.find({'email':session['email']})
            return render_template('myprofile.html', userData = userData))
        else:
            return render_template('signin.html', form=form)

    elif request.method == 'POST':
        if form.validate() == False:
            flash('All fields are required')
            return render_template('signin.html', form=form)
        # checking if username is email
        else:
            userData = userAuth(form.username.data, form.password.data)
            for field in userData:
                session.pop('email', None)
                session['email'] = field['email']
            return redirect(url_for('myprofile', userData = userData))

@app.route('/roundtable', methods=['GET', 'POST'])
def roundtable():
    if request.method == 'GET':
        return render_template('roundtable.html')

@app.route('/newseminar', methods=['GET', 'POST'])
def newseminar():
    form = CreateSeminar()
    if request.method == 'GET':
        return render_template('newseminar.html', form=form)
    elif request.method == 'POST':
        if form.validate == False:
            return render_template('signin.html', form=form)

@app.route('/myprofile')
def myprofile():
    try:
        userData = users_collection.find({'email':session['email']})
    except:
        return;
    if 'email' not in session:
        return redirect(url_for('signin'))

    elif userData is None:
        return redirect(url_for('signin'))
    else:
        return render_template('myprofile.html', userData=userData)

@app.route('/user/<username>')
def user(username):
    if 'email' not in session:
        return redirect(url_for('signin'))
    else: 
        if users_collection.find({'username':username}).limit(1).count() == 1:
            userProfile = users_collection.find({'username':username})
            return render_template('user.html', userProfile = userProfile)
        else:
            return redirect(url_for('error404'))
            flash('Sorry, this users profile was not found')

@app.route('/error404')
def error404():
    return render_template('404.html')



if __name__ == '__main__':
    # Bind to PORT if defined, otherwise default to 5000.
    port = int(os.environ.get('PORT', 5000))
    app.debug = True
    app.run(host='0.0.0.0', port=port)

