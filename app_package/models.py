from app_package import db


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
            "Password": self.Password,  # delete
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
