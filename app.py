# from crypt import methods
from email import header
from flask import Flask, jsonify, make_response, request
from werkzeug.security import generate_password_hash,check_password_hash
from flask_sqlalchemy import SQLAlchemy
from functools import wraps
import uuid
import jwt
import datetime
import sys


app = Flask(__name__)
 
BAD_VERIFICATION = False
KID_INJECTION = False

app.config['SECRET_KEY']='secretKey'
app.config['SQLALCHEMY_DATABASE_URI']='sqlite:///bookstore.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
 
db = SQLAlchemy(app)

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
            if KID_INJECTION == True:
                kid = jwt.get_unverified_header(token)['kid']
                secret = get_secret_from_db(kid)
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
        if KID_INJECTION:
            id, secret = secret_to_db(auth.username + auth.password)
        token = jwt.encode({'is_admin': user.admin, 'name' : user.name},
                            secret, algorithm="HS256", headers={"kid": id})
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
        print(sys.argv)
        if 'kid' in sys.argv:
            KID_INJECTION = True
        if 'verify' in sys.argv:
            BAD_VERIFICATION = True

    app.run(debug=True)