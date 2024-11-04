from flask import Flask, jsonify, request
from database import ConnectDB
from dotenv import load_dotenv
from flask_jwt_extended import JWTManager, create_access_token
from model import Users
from helper import validateEmail, ErrorResponse, SuccessResponse
from flask_bcrypt import Bcrypt
from datetime import timedelta
import os

app = Flask(__name__)

load_dotenv()

db = ConnectDB(app)
bcrypt = Bcrypt(app)

app.config['JWT_SECRET_KEY'] = os.getenv("JWT_SECRET")
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(minutes=15)
jwt = JWTManager(app)


@app.route("/")
def hello_world():
    return jsonify("API is alive!")


@app.route("/login", methods=['POST'])
def login():
    data = request.get_json()
    email = data.get("email") if data else None
    password = data.get("password") if data else None

    if not email and not password:
        return ErrorResponse("Some fields are missing", 400)

    try:
        user = db.session.execute(db.select(Users).filter_by(
            email=email)).scalar_one_or_none()
    except Exception:
        return ErrorResponse("Server error, please try again later", 500)

    if user is None or not bcrypt.check_password_hash(user.password, password):
        return ErrorResponse("Invalid email or password", 400)

    access_token = create_access_token(identity={'email': user.email})

    return SuccessResponse(
        "Login success!",
        {
            "token": access_token
        },
        200
    )


@app.route("/register", methods=['POST'])
def register():
    data = request.get_json()
    username = data.get("username") if data else None
    email = data.get("email") if data else None
    password = data.get("password") if data else None

    if not username or not email or not password:
        return ErrorResponse("Some fields are missing", 400)

    if not validateEmail(email):
        return ErrorResponse("Invalid email", 400)

    try:
        user = db.session.execute(db.select(Users).filter_by(
            email=email)).scalar_one_or_none()
    except Exception:
        return ErrorResponse("Server error, please try again later", 500)

    if user is not None:
        return ErrorResponse("Email already exist", 400)

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    new_user = Users(username=username, email=email, password=hashed_password)

    db.session.add(new_user)
    db.session.commit()

    return SuccessResponse(
        "Register success!",
        {
            "username": new_user.username,
            "email": new_user.email
        },
        201
    )


if __name__ == "__main__":
    app.run()
