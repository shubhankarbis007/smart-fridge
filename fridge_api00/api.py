from flask import make_response
from flask_sqlalchemy import SQLAlchemy
import uuid
from werkzeug.security import generate_password_hash,check_password_hash
import twilio
from twilio.rest import Client
import random
from flask_mail import Mail,Message
import datetime
import jwt
from functools import wraps
from authy.api import AuthyApiClient
from flask import (Flask, Response, request, redirect,
    render_template, session, url_for,jsonify)


app=Flask(__name__)
mail=Mail(app)
app.config["MAIL_SERVER"]='smtp.gmail.com'
app.config["MAIL_PORT"]=465
app.config["MAIL_USERNAME"]='shubhankarbiswas804@gmail.com'   #the email id from where otp will be sent
app.config['MAIL_PASSWORD']='somu@1999'                    #you have to give your password of gmail account
app.config['MAIL_USE_TLS']=False
app.config['MAIL_USE_SSL']=True
mail=Mail(app)


app.config['SECRET_KEY']='thisissecret'
app.config['SQLALCHEMY_DATABASE_URI']='sqlite:////home/frosted/Music/new_api/fridge_api/app.db'   #location of the database
app.config.from_object('config')
app.secret_key = app.config['SECRET_KEY']


api = AuthyApiClient(app.config['AUTHY_API_KEY'])

api = AuthyApiClient(app.config['AUTHY_API_KEY'])
#change the sql alchemy route to the location where your .db file is stored
db=SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(60), nullable=False)
    phone_no = db.Column(db.String(22), nullable=False)
    unique_id = db.Column(db.String(60), nullable=False, unique=True)
    data = db.relationship('Data', backref='user', lazy='dynamic')

class Data(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    image = db.Column(db.LargeBinary)
    prediction_id = db.Column(db.Integer, db.ForeignKey('predictions.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class Predictions(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    belong_to_class = db.Column(db.String(40), unique=True, nullable=False)
    confidence = db.Column(db.Float)
    count = db.Column(db.Integer)
    coordinates = db.Column(db.String(100))
    data = db.relationship('Data', backref='predictions', lazy='dynamic')

def token_required(f):    #decorator function
    @wraps(f)
    def decorated(*args,**kwargs):
        token=None
        if 'x-access-token' in request.headers:
            token=request.headers["x-access-token"]
        if not token:
            return jsonify({"message1":"token is missing"}),401
        try:
            data=jwt.decode(token,"thisissecret")
            current_user=User.query.filter_by(username=data["username"])
        except:
            return jsonify({"message2":"token is missing","token":token}),401
        return f(current_user,*args,**kwargs)
    return decorated

@app.route('/user/signup',methods=['POST','GET'])  #route for generating otp in phone number and mail
def get_otp():
    data=request.get_json()
    #global otp
    global otp1
    #otp = random.randint(1000,9999)
    otp1=random.randint(10000,20000)
    #print("Your OTP is - ",otp)
    # Your Account Sid and Auth Token from twilio.com/console
    # DANGER! This is insecure. See http://twil.io/secure
    account_sid = 'ACf1cad3ffb3a4511871d635ecd8733667'
    auth_token = '4e7f7f5a57d3d701c4d20201b944ce3d'
    #client = Client(account_sid, auth_token)
    #message = client.messages.create(
     #    body='Your Secure Device OTP is - ' + str(otp),
      #   from_='+16692576919',
       #  to=data["number"]
     #)
    email=data["email"]
    msg=Message(subject='OTP',sender='shubhankarbiswas804@gmail.com',recipients=[email])
    msg.body=str(otp1)
    mail.send(msg)
    country_code = data["country_code"]
    phone_number = data["phone_number"]
    method = data["method"]

    session['country_code'] = country_code
    session['phone_number'] = phone_number

    api.phones.verification_start(phone_number, country_code, via=method)

    '''return redirect(url_for("verify"))'''
    return jsonify({"message":"otps sent"})

   

@app.route('/user',methods=['GET'])   #route for getting all the users in the database
@token_required
def get_all_users1(current_user):
    users=User.query.all()
    output=[]
    for user in users:
        user_data={}
        user_data["id"]=user.id
        user_data["username"]=user.username
        user_data["email"]=user.email
        user_data["password"]=user.password_hash
        user_data["phone number"]=user.phone_number
        user_data["unique_id"]=user.unique_id
        output.append(user_data)
    return jsonify({"users":output})

@app.route('/user/<public_id>',methods=['POST'])#route for getting one particular user
@token_required
def get_one_user(current_user,public_id):
    user=User.query.filter_by(id=public_id).first()
    if not user:
        return jsonify({"message":"no user found"})
    user_data={}
    user_data["id"]=user.id
    user_data["username"]=user.username
    user_data["email"]=user.email
    user_data["password"]=user.password_hash
    user_data["phone number"]=user.phone_number
    user_data["unique_id"]=user.unique_id
    return jsonify({"user":user_data})

@app.route('/user/log',methods=['POST','GET'])  #route for verifying otps and unique_id and for creating the user in the database
def create_user():
    data=request.get_json()
    token = data["token"]
    phone_number = session.get("phone_number")
    country_code = session.get("country_code")

    verification = api.phones.verification_check(phone_number,
                                                         country_code,
                                                         token)
    if data["mail_otp"]!=otp1 or verification.ok() is False:
        return jsonify({"message":"wrong otp"})
    password_hash=generate_password_hash(data["password"],method="sha256")
    new_user=User(id=data["id"],username=data["username"],email=data["email"],password_hash=password_hash,phone_no=data["number"],unique_id=data["unique_id"])
    db.session.add(new_user)
    db.session.commit()
    return jsonify({"message":"new user created"})

@app.route('/user/<user_id>',methods=['PUT'])
def promote_user():
    return ''

@app.route('/user/<user_id>',methods=['DELETE'])   #route for deleting any user
@token_required
def delete_user():
    user=User.query.filter_by(id=user_id).first()
    if not user:
        return jsonify({"message":"no user found"})
    db.session.delete(user)
    db.session.commit()
    return jsonify({"message":"user deleted"})


@app.route("/user/login")    #route for logging in and getting the token
def login():
    auth=request.authorization

    if not auth or not auth.username or not auth.password:
        return make_response("Could not not verify",401,{"www-authenticate":"Basic realm Login required"})
    user=User.query.filter_by(username=auth.username).first()
    if not user:
        return jsonify({"message":"no user found"})
    if check_password_hash(user.password_hash,auth.password):
        token=jwt.encode({"public_id":user.id,"exp":datetime.datetime.utcnow()+datetime.timedelta(minutes=30)},app.config["SECRET_KEY"])
        return jsonify({"token":token.decode("UTF-8")})
    return make_response("Could not not verify",401,{"www-authenticate":"Basic realm Login required"})

@app.route("/user/latest",methods=["POST","GET"])    #route for getting the latest data
@token_required
def latest_update(current_user):
    user=Data.query.filter_by(id=current_user.id)
    if not user:
        return jsonify({"message":"user data not available"})
    

if __name__=="__main__":
    app.run(debug=True)
