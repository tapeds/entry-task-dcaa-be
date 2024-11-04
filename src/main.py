from flask import Flask, jsonify, request
from database import ConnectDB
from dotenv import load_dotenv
from model import Users
from helper import validateEmail, ErrorResponse, SuccessResponse
from flask_bcrypt import Bcrypt

app = Flask(__name__)

load_dotenv()

db = ConnectDB(app)
bcrypt = Bcrypt(app)


@app.route("/")
def hello_world():
    return jsonify("API is alive!")


@app.route("/register", methods=['post'])
def login():
    data = request.get_json()
    username = data.get("username") if data else None
    email = data.get("email") if data else None
    password = data.get("password") if data else None

    if not username or not email or not password:
        return ErrorResponse("Some fields are missing", 400)

    if not validateEmail(email):
        return ErrorResponse("invalid email", 400)

    user = db.session.execute(db.select(Users).filter_by(
        email=email)).scalar_one_or_none()

    if user is not None:
        return ErrorResponse("email already exist", 400)

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
