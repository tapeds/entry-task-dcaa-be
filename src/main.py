from flask import Flask, jsonify, request
from database import ConnectDB
from dotenv import load_dotenv
from flask_jwt_extended import JWTManager
from flask_jwt_extended import create_access_token
from flask_jwt_extended import jwt_required
from model import Users
from helper import validateEmail, ErrorResponse, SuccessResponse
from flask_bcrypt import Bcrypt
from datetime import timedelta
import os
from authentication import get_user_from_token
from werkzeug.utils import secure_filename
import uuid
from flask_cors import CORS

app = Flask(__name__)
CORS(app)
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

    if not validateEmail(email):
        return ErrorResponse("Invalid email", 400)

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

    if not len(password) >= 8:
        return ErrorResponse("Password is too short", 400)

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


@app.route("/me", methods=["GET"])
@jwt_required()
def me():
    user, err = get_user_from_token(db)

    if err is not None:
        return err

    return SuccessResponse(
        "Get Me success!",
        {
            "username": user.username,
            "email": user.email,
            "profile_picture": user.profile_picture,
        },
        200
    )


@app.route("/profile_picture", methods=["PATCH"])
@jwt_required()
def update_profile_picture():
    if 'image' not in request.files:
        return ErrorResponse("No image provided", 400)

    user, err = get_user_from_token(db)

    if err is not None:
        return err

    image = request.files["image"]

    secure_name = secure_filename(image.filename)
    unique_id = uuid.uuid4()
    file_extension = os.path.splitext(secure_name)[1]
    filename = f"{unique_id}{file_extension}"

    storage_path = os.path.join('storage', filename)
    os.makedirs('storage', exist_ok=True)

    os.chmod('storage', 0o755)

    try:
        image.save(storage_path)
    except Exception as e:
        print(e)
        return ErrorResponse("Failed to save image, try again later", 500)

    # TODO: Implement delete image from previous user profile picture
    # to save storage

    user.profile_picture = storage_path
    db.session.commit()

    return SuccessResponse(
        'Image uploaded successfully',
        {'path': storage_path},
        201
    )


@app.route("/update_profile", methods=["PATCH"])
@jwt_required()
def update_profile():
    data = request.get_json()

    user, err = get_user_from_token(db)

    if err is not None:
        return err

    username = data.get("username") if data else None
    email = data.get("email") if data else None
    password = data.get("password") if data else None

    if not email and not username and not password:
        return ErrorResponse("At least one of the field must be filled", 400)

    if email is not None:
        if not validateEmail(email):
            return ErrorResponse("Invalid email", 400)

        user.email = email

    if username is not None:
        user.username = username

    if password is not None:
        if not len(password >= 8):
            return ErrorResponse("Password is too short", 400)

        hashed_password = bcrypt.generate_password_hash(
            password).decode('utf-8')
        user.password = hashed_password

    db.session.commit()

    return SuccessResponse("Profile updated successfully", {}, 200)


if __name__ == "__main__":
    app.run()
