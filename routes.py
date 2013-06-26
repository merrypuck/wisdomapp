#--------------------

    # routes.py is a Flask server script for routing wisdom.ly v1.1
    # created at Tigerlabs - Princeton, NJ 
    # on Monday June 17, 2013

#--------------------
import os, re
import datetime
from flask import Flask, render_template, session, request, flash, url_for, redirect
import flask.views 

# forms.py handles form creation and validation 
from forms import ContactForm, SignUp, SignIn, newrt

# handles automatic mail service
from flask.ext.mail import Message, Mail 

# handles password hashing
from flaskext.bcrypt import Bcrypt

# handles user login management
from flask.ext.login import LoginManager

# user authentication with oauth
from flask_oauth import OAuth

# python + mongo
import pymongo 
from pymongo import MongoClient

# tornado web sockets with python
import tornado
import tornado.websocket
import tornado.wsgi

#openTok
import OpenTokSDK

#--------------------------------------------------------------------------
app = Flask(__name__)

#-----------------------------------
# initiates mongo within python
client = MongoClient('localhost')

# set our users collection to users_collection
users_collection = client.wisdom.users

# set rtSessions collection to rts_collection
rts_collection = client.wisdom.rtSessions

#------------------------------------

#initiate password hashing
bcrypt = Bcrypt(app)

#initiate opentok and define api_key
api_key = "32153182"
api_secret = "6274a324e6e616d13fd0623c4ba051aa2ce79ba9"
opentok_sdk = OpenTokSDK.OpenTokSDK(api_key, api_secret)

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

    #Oauth  -- Facebook

#----------------------------------

DEBUG = True
FACEBOOK_APP_ID = '188879964608233'
FACEBOOK_APP_SECRET = '45cd267a90d70fb997692fc003cef1e5'
oauth = OAuth()

facebook = oauth.remote_app('facebook',
    base_url='https://graph.facebook.com/',
    request_token_url=None,
    access_token_url='/oauth/access_token',
    authorize_url='https://www.facebook.com/dialog/oauth',
    consumer_key=FACEBOOK_APP_ID,
    consumer_secret=FACEBOOK_APP_SECRET,
    request_token_params={'scope': 'email'}
)

@app.route('/login')
def login():
    return facebook.authorize(callback=url_for('facebook_authorized',
        next=request.args.get('next') or request.referrer or None,
        _external=True))

@app.route('/login/authorized')
@facebook.authorized_handler
def facebook_authorized(resp):
    if resp is None:
        return 'Access denied: reason=%s error=%s' % (
            request.args['error_reason'],
            request.args['error_description']
        )
    session['oauth_token'] = (resp['access_token'], '')
    me = facebook.get('/me')
    return 'Logged in as id=%s name=%s redirect=%s' % \
        (me.data['id'], me.data['name'], request.args.get('next'))


@facebook.tokengetter
def get_facebook_oauth_token():
    return session.get('oauth_token')


#----------------------------------
    # userAuth
    # function for user authentication
    # accepts user id, password as parameters
    # and returns userData if successfull
#----------------------------------
def userAuth(user, password):
    if re.match("[^@]+@[^@]+\.[^@]+", user):
        if users_collection.find_one({'email': user}) != None:
            userData = users_collection.find_one({'email':user})
            if bcrypt.check_password_hash(userData['password'], password):
                return userData

    elif user.__len__() > 0:
        if users_collection.find_one({'username': user}) != None:
            userData = users_collection.find_one({'username': user})
            if bcrypt.check_password_hash(userData['password'], password):
                 return userData
    else:
        flash('Username or password is invalid.')
        return render_template('signin.html', form=form)

#-----------------------------------
    
    # Generate sessions and tokens for opentok

#-----------------------------------

def newSession():
    session_address = None
    session_properties = {
    OpenTokSDK.SessionProperties.p2p_preference: "disabled"
    }
    session = opentok_sdk.create_session(session_address, session_properties)
    return session
def newToken(session):
    token = opentok_sdk.generate_token(session.session_id)
    return token
"""
@app.route('/', methods=['GET','POST'])
def index():
    return flask.render_template('chat1.html')
 
class ChatWebSocket(tornado.websocket.WebSocketHandler):
    clients = []
 
    def open(self):
        ChatWebSocket.clients.append(self)
 
    def on_message(self, message):
        for client in ChatWebSocket.clients:
            client.write_message(message)
 
    def on_close(self):
        ChatWebSocket.clients.remove(self)
 
tornado_app = tornado.web.Application([
    (r'/websocket', ChatWebSocket),
    (r'.*', tornado.web.FallbackHandler, {'fallback': tornado.wsgi.WSGIContainer(app)})
])
 
tornado_app.listen(5000)
tornado.ioloop.IOLoop.instance().start()
"""
@app.route('/')
def inlineedit():
    return render_template('inlineedit.html')
class ChatWebSocket(tornado.websocket.WebSocketHandler):
    clients = []
 
    def open(self):
        ChatWebSocket.clients.append(self)
 
    def on_message(self, message):
        for client in ChatWebSocket.clients:
            client.write_message(message)
 
    def on_close(self):
        ChatWebSocket.clients.remove(self)
 
tornado_app = tornado.web.Application([
    (r'/websocket', ChatWebSocket),
    (r'.*', tornado.web.FallbackHandler, {'fallback': tornado.wsgi.WSGIContainer(app)})
])

tornado_app.listen(5000)
tornado.ioloop.IOLoop.instance().start()    

@app.route('/bc', methods=['GET','POST'])
def wisdom1():
    if 'email' in session:
        try:
            userData = users_collection.find_one({'email':sessions['email']})
        except:
            return;
    return render_template('chat.html')

class ChatWebSocket(tornado.websocket.WebSocketHandler):
    clients = []
 
    def open(self):
        ChatWebSocket.clients.append(self)
 
    def on_message(self, message):
        for client in ChatWebSocket.clients:
            client.write_message(message)
 
    def on_close(self):
        ChatWebSocket.clients.remove(self)
 
tornado_app = tornado.web.Application([
    (r'/websocket', ChatWebSocket),
    (r'.*', tornado.web.FallbackHandler, {'fallback': tornado.wsgi.WSGIContainer(app)})
])
 
tornado_app.listen(5000)
tornado.ioloop.IOLoop.instance().start()


@app.route('/wisdom1', methods=['GET','POST'])
def home():
    form = SignIn()
    if request.method == 'GET':
        return render_template('home.html', form=form)

    elif request.method == 'POST':
        if form.validate() == True:
            userData = userAuth(form.username.data, form.password.data)
            session['email'] = userData['email']
            return redirect(url_for('myprofile'))
        elif form.validate() == False:
            flash('All fields are required')
            return render_template('signin.html', form=form,)

    else:
        flash('Your username/email or password is incorrect')
        return render_template('signin.html')
            
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = SignUp()
    if request.method == 'GET':
        if 'email' in session:
            return redirect(url_for('myprofile'),)
        else:
            return render_template('signup.html', form=form)
    elif request.method == 'POST':
        if form.validate() == False:
            flash('All fields are required')
            return render_template('signup.html', form=form)
            # finds if a user exists with specificed email
        elif users_collection.find_one({'email': form.email.data}) != None:
            flash("This email has already been used.")
            return render_template('signup.html', form=form)
            # finds if a user exists with specificed username
        elif users_collection.find_one({'_id':form.username.data}) != None:
            flash("Sorry, that username is already taken.")
            return render_template('signup.html', form=form)

        # adds new user to database, sends email, initiates new session,
        # redirects to myprofile.html
        else:
            #hash password
            pw_hash = bcrypt.generate_password_hash(form.password.data)
            # add user to wisdom.users db
            users_collection.insert({'_id' : form.username.data,
                                    'firstName' : form.firstName.data,
                                    'lastName' : form.lastName.data,
                                    'email' : form.email.data,
                                    'password' : pw_hash,
                                    'createdAt' : datetime.datetime.now()
                                    })
            # creates new cookie session based on email
            session['email'] = form.email.data

            msg = Message(
                'Wisdom.ly account confirmation',
                # sender
                sender='aaron@wisdom.ly',
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
            return redirect(url_for('myprofile'))


@app.route('/signin', methods=['GET', 'POST'])
def signin():
    form = SignIn()
    if request.method == 'GET':
        if 'email' in session:
            userData = users_collection.find({'email':session['email']})
            return redirect(url_for('myprofile'))
        else:
            return render_template('signin.html', form=form)

    elif request.method == 'POST':
        if form.validate_on_submit():
            if userAuth(form.username.data, form.password.data) != None:
                userData = userAuth(form.username.data, form.password.data)
                session.pop('email', None)
                session['email'] = userData['email']
                return redirect(url_for('myprofile'))
            else:
                flash('Your username or password was incorrect')
                return render_template('signin.html', form=form)
        else:
            flash('All fields are required')
            return render_template('signin.html', form=form)

@app.route('/signout', methods=['GET', 'POST'])
def signout():
    session.pop('email', None)                            
    flash('You were logged out')
    return redirect(url_for('home'))

@app.route('/roundtable/<sessionID>', methods=['GET', 'POST'])
def roundtable():
    if 'email' in session or 'email' is None:
        flash('You must be signed in to enter this page.')
        redirect(url_for('signin'))
    else:
        if request.method == 'GET':
            userData = users_collection.find_one({'email':session['email']})
            currentSession = rts_collection.find_one({'sessionID':sessionID})

            if len(currentSession['participants']) < 9:
                if userData['_id'] in currentSession['participants']:
                    render_template('roundtable.html')
class ChatWebSocket(tornado.websocket.WebSocketHandler):
    clients = []
 
    def open(self):
        ChatWebSocket.clients.append(self)
 
    def on_message(self, message):
        for client in ChatWebSocket.clients:
            client.write_message(message)
 
    def on_close(self):
        ChatWebSocket.clients.remove(self)
 
tornado_app = tornado.web.Application([
    (r'/websocket', ChatWebSocket),
    (r'.*', tornado.web.FallbackHandler, {'fallback': tornado.wsgi.WSGIContainer(app)})
])
 
tornado_app.listen(5000)
tornado.ioloop.IOLoop.instance().start()



"""
@app.route('/newroundtable', methods=['GET', 'POST'])
def newroundtable():
    form = newrt()
    if 'email' in session or 'email' is None:
        if request.method == 'GET':
            return render_template('newroundtable.html', form=form)
        elif request.method == 'POST':
            if form.validate == False:
                flash('All fields are required')
                return render_template('newroundtable.html', form=form)
            else:
                userData = users_collection.find_one({'email':session['email']})
                session = newSession()
                rts_collection.insert({ 'rt_id':datetime.datetime.now(),
                                        'sessionID':session,
                                        'title':form.title.data,
                                        'description':form.description.data,
                                        'expert_ID' : userData['_id'],
                                        'createdAt' : datetime.datetime.now()
                    })
                return redirect(url_for('roundtable/' + str(_id))
    #else:
    #    flash('Sorry, you must be logged in to see this page.')
    #    return redirect(url_for('signin'))

"""
@app.route('/myprofile', methods=['GET', 'POST'])
def myprofile():
    if 'email' not in session or 'email' is None:
        flash('Sorry, you must be logged in to see this page.')
        return redirect(url_for('signin'))
    else:
        try:
            userData = users_collection.find_one({'email':session['email']})
        except:
            return;
        return render_template('myprofile.html', userData = userData)

#if 'email' not in session or 'email' is None:
@app.route('/user/<username>')
def user(username):
    if 'email' not in session:
        flash('Sorry, you must be logged in to see this page.')
        return redirect(url_for('signin'))
    else:
        if users_collection.find_one({'_id':username}) != None:
            userData= users_collection.find_one({'_id':username})
            return render_template('user.html', userData = userData)
        else:
            return render_template('404.html')


@app.errorhandler(404)
def error404(e):
    return render_template('404.html'), 404


@app.route('/chat')
def chat():
    return flask.render_template('chat.html')
"""
class ChatWebSocket(tornado.websocket.WebSocketHandler):
    clients = []
 
    def open(self):
        ChatWebSocket.clients.append(self)
 
    def on_message(self, message):
        for client in ChatWebSocket.clients:
            client.write_message(message)
 
    def on_close(self):
        ChatWebSocket.clients.remove(self)
 
tornado_app = tornado.web.Application([
    (r'/websocket', ChatWebSocket),
    (r'.*', tornado.web.FallbackHandler, {'fallback': tornado.wsgi.WSGIContainer(app)})
])
 
tornado_app.listen(5000)
tornado.ioloop.IOLoop.instance().start()
"""
if __name__ == '__main__':
    # Bind to PORT if defined, otherwise default to 5000.
    port = int(os.environ.get('PORT', 5000))
    app.debug = True
    app.run(host='0.0.0.0', port=port)

