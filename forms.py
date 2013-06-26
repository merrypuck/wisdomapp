from flask.ext.wtf import Form, TextField, TextAreaField, DateField, SubmitField, validators, ValidationError, PasswordField
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

class newrt(Form):
   title = TextField("Title",  [validators.Required("Please enter a roundtable title")])
   description = TextField("Description",  [validators.Required("Please enter a roundtable description")])
   submit = SubmitField("Create Roundtable")

