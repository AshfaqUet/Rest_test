from flask import Flask
from config import Config
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate


app = Flask(__name__)
app.config.from_object(Config)
db = SQLAlchemy(app)
migrate = Migrate(app, db)

from app_package import routes

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000, debug=True)
