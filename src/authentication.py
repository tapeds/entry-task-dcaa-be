from flask_jwt_extended import get_jwt_identity
from model import Users
from helper import ErrorResponse


def get_user_from_token(db):
    user_info = get_jwt_identity()
    user_email = user_info.get("email") if user_info else None

    try:
        user = db.session.execute(db.select(Users).filter_by(
            email=user_email)).scalar_one_or_none()
    except Exception:
        return None, ErrorResponse("Server error, please try again later", 500)

    if not user:
        return None, ErrorResponse("Token is invalid", 401)

    return user, None
