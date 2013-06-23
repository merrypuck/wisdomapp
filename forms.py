from flask.ext.wtf import Form, TextField, TextAreaField, SubmitField, validators, ValidationError, PasswordField
from flask.ext.wtf.html5 import NumberInput
class ContactForm(Form):
  name = TextField("Name")
  email = TextField("Email")
  subject = TextField("Subject")
  message = TextAreaField("Message")

class SignUp(Form):
    firstName = TextField("First Name",  [validators.Required("Please enter your first name.")])
    lastName = TextField("Last Name",  [validators.Required("Please enter your last name.")])
    email = TextField("Email",  [validators.Required(), validators.Email("Please enter a valid email address.")])
    username = TextField("Username",  [validators.Required("Sorry this username is not valid or already taken.")])
    password = PasswordField('Password', [validators.Required("Please enter a password.")])
    submit = SubmitField("Sign Up")

class SignIn(Form):
    username = TextField("Email or Username", [validators.Required("Please enter your email or username")])
    password = PasswordField("Password", [validators.Required("Please enter your password.")])
    submit = SubmitField("Sign In")

class resetPassword(Form):
    username = TextField("Email or Username")
    submit = SubmitField("Reset Password")

class CreateSeminar(Form):
	 seminarName = TextField("Seminar Name",  [validators.Required("Please enter a seminar name")])
	 attendeeAmt = NumberInput("Number of attendees (10 max)")
	 sessionTopic1 = TextField("Session Topic1")
	 sessionTopic2 = TextField("Session Topic2")
	 sessionTopic3 = TextField("Session Topic3")
	 sessionTopic4 = TextField("Session Topic4")
	 sessionTopic5 = TextField("Session Topic5")



