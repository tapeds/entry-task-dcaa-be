from flask import Flask
from db import ConnectDB

app = Flask(__name__)

ConnectDB(app)


@app.route("/")
def hello_world():
    return "<p>Hello, World!</p>"
