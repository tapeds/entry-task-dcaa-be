from flask import Flask
from database import ConnectDB

app = Flask(__name__)

ConnectDB(app)


@app.route("/")
def hello_world():
    return "<p>Hello, World!</p>"


if __name__ == "__main__":
    app.run()
