import re

from flask import jsonify


def validateEmail(email):
    email_regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    return re.match(email_regex, email) is not None


def ErrorResponse(error, code):
    return jsonify({
        "error": error
    }), code


def SuccessResponse(message, data, code):
    return jsonify({
        "data": data,
        "message": message,
    }), code
