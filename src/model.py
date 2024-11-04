from database import db


class Users(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    profile_picture = db.Column(db.String(100), nullable=True)
    password = db.Column(db.String(100), nullable=False)

    def __repr__(self):
        return f"Username : {self.username}, Age: {self.age}"
