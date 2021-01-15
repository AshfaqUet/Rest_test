from app_package import db
from sqlalchemy.orm import relationship


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    Username = db.Column(db.String(200), nullable=False, unique=True)
    Password = db.Column(db.String(200), nullable=False)
    Email = db.Column(db.String(64), nullable=False, unique=True)
    Login = db.Column(db.String(64), nullable=False, default="False")

    def __repr__(self):
        return '<Username {}>'.format(self.Username)

    def user_information(self):
        return {
            "Username": self.Username,
            "Email": self.Email,
            "Id": self.id        # delete
        }

    def self_information(self):
        return {
            "Username": self.Username,
            "Password": self.Password,
            "Email": self.Email,
            "Login": self.Login,
            "Id": self.id        # delete
        }


class Device(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user = relationship("User")
    User = db.Column(db.String(200), nullable=False)
    Username = db.Column(db.String(200), db.ForeignKey('user.Username'), nullable=False)
    Password = db.Column(db.String(200), nullable=False)
    Address = db.Column(db.String(64), nullable=False, unique=True)

    def __repr__(self):
        return '{} {} {} {} {}'.format(self.id, self.User, self.Username, self.Password, self.Password)

    def to_json(self):
        return {
            "Username": self.Username,
            "Password": self.Password,
            "Address": self.Address,
            "User":self.User,
            "id": self.id
        }
