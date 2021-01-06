from flask import jsonify, abort, make_response, request
from app_package import app
from app_package import functions
import jwt
import yaml
from ssh_manager import utilities
import os
import datetime
from functools import wraps
from ssh_manager.ssh_class import SshClass
app.config['SECRET_KEY'] = "thisisthesecretkey"


# ############################################ Utilities ###############################################################
def login_required(f):
    """ Login required decorator
        param : function on which we want to apply authorization(user logged in for access)
        return : functionality of the decoratored function
    """

    @wraps(f)  # explanation at https://www.geeksforgeeks.org/python-functools-wraps-function/
    def decorator(*args, **kwargs):
        """ Docstring of decorator function"""
        token = request.args.get('token')  # taking token as an argument
        if not token:
            return jsonify({'message': "Token is missing"}), 403  # if token not provided in the url
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])  # check if token decoded successfully
            user = functions.get_user(data)
            if user['Login'] == "False":
                return jsonify({'message': 'Token is expired'}), 403
        except:
            return jsonify({'message': 'Token is invalid'}), 403  # if token not decoded that means token is invalid
        return f(*args, **kwargs)

    return decorator
# ######################################################################################################################


# #################### Just for Testing the @login_required decorator ###################################
# @app_package.route('/unprotected')  # Public url                                                            ##
# def unprotected():                                                                                  ##
#     return jsonify({'message': 'Anyone can view this!'})                                            ##
#                                                                                                     ##
#                                                                                                     ##
# @app_package.route('/protected')    # Private url (required authorization)                                  ##
# @login_required    # Applying decorator for user to be logged in before accessing the function      ##
# def protected():                                                                                    ##
#     """ Docstring of protected function"""                                                          ##
#     return jsonify({'message' : 'This is only available for people with valid tokens.'})            ##
# #######################################################################################################

# ############################################## Routes of API #########################################################

# Register the new user
@app.route('/register', methods=['POST'])  # Registration
def register_user():
    """ Register new user
        params: we take user information in the POST request from the user
        return: success report if user registered successfully

        one thing to implement in how to handle the db constraints error, unique constrant error in this case
    """
    if (not request.json) or ('username' not in request.json) or ('password' not in request.json) or (
            'email' not in request.json):
        abort(400)
    user = {
        'Username': request.json['username'],
        'Email': request.json['email'],
        'Password': request.json['password']
    }
    functions.registration(user)
    return jsonify({'User': user}), 201


# Login the registered user
@app.route('/login', methods=['POST'])  # Login
def login_user():
    """ Login the user
        params: Get (Username, Password) in the POST request
        return: success information if the user logged in successfully
    """
    user = {
        'Username': request.json['username'],
        'Password': request.json['password']
    }
    permit = functions.login(user)
    if permit:
        token = jwt.encode({"Username": user['Username'], "Password": user['Password'],
                            "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=30)},
                           app.config['SECRET_KEY'], algorithm='HS256')
        return jsonify({'Token': token.decode('UTF-8')})
    else:
        return make_response(jsonify({'Login Failed': 'Username or Password not match'}), 201)


# Delete the logined user
@app.route('/user', methods=['DELETE'])  # Delete User Account
@login_required
def delete_user():
    """ Delete the existing user
        params : Valid token Token for authorization purpose
        return : Success Report
    """
    token = request.args.get('token')
    data = jwt.decode(token, app.config['SECRET_KEY'])

    permit = functions.delete_user(data)
    if permit:
        return make_response(jsonify({'Delete': 'User Deleted Successfully'}), 201)
    else:
        return make_response(jsonify({'Delete Failed': 'Credentials not match or the user not exist'}), 201)


# Get all Users
@app.route('/users', methods=['GET'])  # Get all the Users Data
@login_required
def get_users():
    """ Getting all the users information
        params : Valid token Token for authorization purpose
        return : User all information (Username,Password etc)
    """
    users = functions.users()
    return users


# Get a single User
@app.route('/user', methods=['GET'])  # Get a single user data
@login_required
def get_user():
    """ Getting own information
        params : Valid token Token for authorization purpose
        return : User all information (Username, Password, Email, Login etc)
    """
    token = request.args.get('token')
    data = jwt.decode(token, app.config['SECRET_KEY'])
    user = functions.get_user(data)
    return user


# Logout the Logined user
@app.route('/logout', methods=['GET'])
@login_required
def logout():
    """ Logout the existing user
        params : Valid token Token for authorization purpose
        return : Success Report
    """
    token = request.args.get('token')
    data = jwt.decode(token, app.config['SECRET_KEY'])
    logged_out = functions.logout(data)
    if logged_out:
        return jsonify({'message': 'Logout Successfully'})
    else:
        return jsonify({'message': 'Logout Failed'})


@app.route('/ssh/connect', methods=['POST'])
# @login_required
def connect():
    """
    Connect with the device having IP address as provided by using the Username and Password parameter
    :param: This function take 3 argument as POST request i-e Username, Address, Password
    :return: Message1 = Connection build successfully
             Message2 = Server side coneection error
             Message3 = SSH connection failed
    """
    credentials = {
        'Username': request.json['username'],
        'Address': request.json['address'],
        'Password': request.json['password']
    }
    device = SshClass()
    connected = device.connect(credentials)
    if connected:
        device_credentials = [{credentials['Address']: [credentials['Username'], credentials['Password']]}]
        utilities.delete_known_old_credentials(credentials['Address'])
        with open(r'./ssh_manager/store_connection.yaml', "a") as file:
            documents = yaml.dump(device_credentials, file)
        disconnected = device.disconnect()
        if disconnected:
            return jsonify({'message': 'SSH connection build successfully successfully'})
        else:
            return jsonify({'Message': 'Server side error while building the connection'})
    else:
        return jsonify({'message': 'Device ssh connection  Failed'})

@app.route('/ssh/command', methods=['POST'])
def command():
    """
    :param: it takes 2 argument i-e IP and command
    :return: Message1 = result of the command
             Message2 = Device not connected yet to run the command
    """
    ip_address = request.json['address']
    command_to_run = request.json['command']
    credentials = utilities.credential_of_device(ip_address)
    if credentials is not None:
        device = SshClass()
        device.connect(credentials)
        result = device.run_command(command_to_run)
        return result
    else:
        return jsonify({'Message': 'Device not connected yet first connect with device by using /ssh/connect api'})

@app.route('/ssh/close',methods=['POST'])
def close_ssh():
    ip_address = request.json['address']
    utilities.delete_known_old_credentials(ip_address)
    return jsonify({'Message':"Connection closed Successfully"})