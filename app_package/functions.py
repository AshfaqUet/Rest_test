from app_package import db
from app_package.models import User
from flask import abort, jsonify, make_response


def registration(user):
    """
    Registeration of new user
    :param user:
    :return:
    """
    new_user = User(Username=user['Username'], Password=user['Password'], Email=user['Email'])
    try:
        db.session.add(new_user)
        db.session.commit()
        return True
    except:  # ########################### Unique Constraint breaks ##################################
        return False


def users():
    """
    Listing down all the information of users
    :param None:
    :return List containing all the users from User Model:
    """
    users = list()
    for user in User.query.all():
        users.append(user.user_information())
    return jsonify(users)


def get_user(user_data):
    """
    Getting one user(only self) information
    :param user_data:
    :return (Error message if user not found in database) or (Information of user in the form of dictionary):
    """
    user = User.query.filter_by(Username=user_data['Username'], Password=user_data['Password']).first()
    if user is not None:
        return user.self_information()
    else:
        return make_response(jsonify({'Error': 'User not found'}), 201)


def login(user_data):
    """
    Login the existing user
    :param user_data:
    :return Success report (if credential matched then True else False):
    """
    user = User.query.filter_by(Username=user_data['Username'], Password=user_data['Password']).first()
    if user is not None:
        user.Login = "True"
        db.session.add(user)
        db.session.commit()
        return True
    else:
        return False


def logout(user_data):
    """
        Logout the existing user
        :param user_data:
        :return Success report (if credential matched then True else False):
    """
    user = User.query.filter_by(Username=user_data['Username'], Password=user_data['Password']).first()
    if user is not None:
        user.Login = "False"
        db.session.add(user)
        db.session.commit()
        return True
    else:
        return False


def delete_user(user_data):
    """
    Delete the user
    :param user_data:
    :return Success report (if credential matched then True else False):
    """
    user = User.query.filter_by(Username=user_data['Username'], Password=user_data['Password']).first()
    if user is not None:
        db.session.delete(user)
        db.session.commit()
        return True
    else:
        return False
