# from crypt import methods
from email import header
from flask import Flask, jsonify, make_response, request
from werkzeug.security import generate_password_hash,check_password_hash
from flask_sqlalchemy import SQLAlchemy
from functools import wraps
import requests
import uuid
import jwt
import datetime
import sys


app = Flask(__name__)
 
BAD_VERIFICATION = False
KID_INJECTION = False
JKU_HOSTED = False

app.config['SECRET_KEY']='secretKey'
app.config['SQLALCHEMY_DATABASE_URI']='sqlite:///bookstore.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
 
db = SQLAlchemy(app)

# PRIVATE KEY USED FOR AWS https://jwt-vulnarabilities-demo.s3.eu-west-3.amazonaws.com/public_key.pub
PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIBOwIBAAJBAJmA7HWYirhEduRgLDffZZb3LyBoLP4b1hBcv4lk69v18YKCij3b
x6JLGxtY/ug2xFQLSIvvXT51+GeXpA79DLcCAwEAAQJAGBoIBobG8Ru+1yjKiJNI
7iUtfxccSWGxgKwvXrE73zNFLb4lSAeJQ5x/AOaThheGh/qj/HDYUVSnpGww1prj
UQIhAPAEJVVPzVk7yF8tTwHHY9LmE61MrUXmmqRp1UwID2olAiEAo7nj7GE5PWk0
GkjBrmVc9CD2wu0jbAZ60zF1/DScrqsCIQDAHuFvX3iFJAhovxDN4Lez+jzn7EeK
e2NvldOJj64fDQIhAKLaDKabUhcOZJ/cTKIN+rZtb2UWAQy7KUKWSPgS0OI/AiB+
3gWlmdpxh4F6cY6G6Qy3XewBjZWhXvHxQSAmF4Gnvg==
-----END RSA PRIVATE KEY-----
"""

# Models
class Users(db.Model):
   id = db.Column(db.Integer, primary_key=True)
   public_id = db.Column(db.Integer)
   name = db.Column(db.String(50))
   password = db.Column(db.String(50))
   admin = db.Column(db.Boolean)


class Jwt(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    secret = db.Column(db.String(20))

db.create_all()

def get_secret_from_net(address):
    response = requests.get(address)
    return response.text

def get_secret_from_db(kid):
    result = db.engine.execute("SELECT secret FROM Jwt Where Id = " + kid)
    secret = [row[0] for row in result][0]
    return secret

def get_secret_from_db_secure(kid):
    return Jwt.query.filter_by(id=kid).first().secret

def secret_to_db(secret):
    jwt_token = Jwt(secret=secret)
    db.session.add(jwt_token)
    db.session.commit()
    return (str(jwt_token.id), jwt_token.secret)

def token_required(f):
    @wraps(f)
    def decorator(*args, **kwargs):
        if 'Authorization' in request.headers and request.headers['Authorization'].startswith("Bearer "):
            token = request.headers['Authorization'][7:]
            secret = app.config['SECRET_KEY']
            if KID_INJECTION:
                kid = jwt.get_unverified_header(token)['kid']
                secret = get_secret_from_db(kid)
            if JKU_HOSTED:
                jku = jwt.get_unverified_header(token)['jku']
                secret = get_secret_from_net(jku)
            try:
                print("secret:", secret)
                data = jwt.decode(token, secret, algorithms=["HS256", "RS256"])
            except:
                if BAD_VERIFICATION:
                    try:
                        data = jwt.decode(token, options={"verify_signature": False})
                    except:
                        return jsonify({'message': 'token is invalid'})
                else:
                    return jsonify({'message': 'token is invalid'})
        else:
            return jsonify({'message': 'a valid token is missing'})
        return f(data['is_admin'], *args, **kwargs)
    return decorator


@app.route('/register', methods=['POST'])
def signup_user(): 
    data = request.get_json()
    hashed_password = generate_password_hash(data['password'], method='sha256')
 
    new_user = Users(public_id=str(uuid.uuid4()), name=data['name'], password=hashed_password, admin=False)
    db.session.add(new_user) 
    db.session.commit()   
    return jsonify({'message': 'registered successfully'})


@app.route('/login', methods=['POST']) 
def login_user():
    auth = request.authorization
    if not auth or not auth.username or not auth.password: 
       return make_response('could not verify', 401, {'Authentication': 'login required"'})  

    user = Users.query.filter_by(name=auth.username).first()

    if check_password_hash(user.password, auth.password): 
        id, secret = "NOT_USED_ID", app.config['SECRET_KEY']
        token =  token = jwt.encode({'is_admin': user.admin, 'name' : user.name},
                                secret, algorithm="HS256")
        if KID_INJECTION:
            id, secret = secret_to_db(auth.username + auth.password)
            token = jwt.encode({'is_admin': user.admin, 'name' : user.name},
                                secret, algorithm="HS256", headers={"kid": id})
        if JKU_HOSTED:
             token = jwt.encode({'is_admin': user.admin, 'name' : user.name},
                                PRIVATE_KEY, algorithm="RS256", headers={"jku": "https://jwt-vulnarabilities-demo.s3.eu-west-3.amazonaws.com/public_key.pub"})
        return jsonify({'token' : token})

    return make_response('could not verify',  401, {'Authentication': '"login required"'})


@app.route('/users', methods=['GET'])
@token_required
def get_all_users(is_admin):
    if not is_admin:
        return make_response('Insufficient permissions',  401, {'Authentication': '"Insufficient permissions"'})
    users = Users.query.all()
    result = []  
    for user in users:  
        user_data = {}  
        user_data['public_id'] = user.public_id 
        user_data['name'] = user.name
        user_data['password'] = user.password
        user_data['admin'] = user.admin
        
        result.append(user_data)  
    return jsonify({'users': result})    


if  __name__ == '__main__':
    if len(sys.argv) > 1:
        if 'kid' in sys.argv:
            KID_INJECTION = True
        if 'verify' in sys.argv:
            BAD_VERIFICATION = True
        if 'jku' in sys.argv:
            JKU_HOSTED = True

    app.run(debug=True)

# PRIVATE KEY used for the custom made pair at - https://jwt-vulnarabilities-demo.s3.eu-west-3.amazonaws.com/public_key_made_by_attacker.pub
"""-----BEGIN RSA PRIVATE KEY-----
MIIBOgIBAAJBAJ/KVF40mfnT+3wEl5KqoTVOCkNkfuzBBWcjH11iSU4N/M0Astrg
9g9wpcIqxMEYFyErRkMhV6oIeqdIlaxVIjMCAwEAAQJAHQqB0OlQfsZXM5AGGELo
r65yURNHujHOkJMilS9S0VuRuiuqxfHAGcuyjbkc8ty0/oIu4FozDnCPHorozi9o
QQIhANmrpDv6gs66/UMaeL/9tiUnnJRqPDDRnueewoqxSTvhAiEAu+2DIYmBHxCf
vSblhbLcsX3y6DZdi5buqrdSy/Y/wJMCIFPUnvPajvY/XbqyPz7x32x/zPX71CKZ
GLHrmtD/Zk0BAiEAk5frSBilV0+IFVeKJeIe4Ctp7iRcfbgxg9Rs65Ff6o8CIHOz
cqrfzSxyny2RVh+N9bXE4vRgLQ8HUv6VBa/3WiE1
-----END RSA PRIVATE KEY-----"""