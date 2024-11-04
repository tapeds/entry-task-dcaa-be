from dotenv import load_dotenv
import os
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


def ConnectDB(app):
    load_dotenv()
    dbUser = os.getenv('DB_USERNAME')
    dbPass = os.getenv('DB_PASSWORD')
    dbName = os.getenv('DB_DATABASE')
    dbPort = os.getenv('DB_PORT')
    dbHost = os.getenv('DB_HOST')

    if not all([dbUser, dbPass, dbHost, dbName, dbPort]):
        raise ValueError(
            "Database configuration is missing in the environment variables")

    databaseURI = f"mysql://{dbUser}:{dbPass}@{dbHost}:{dbPort}/{dbName}"
    app.config["SQLALCHEMY_DATABASE_URI"] = databaseURI
    db.init_app(app)

    with app.app_context():
        import model
        db.create_all()
