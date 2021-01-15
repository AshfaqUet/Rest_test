from flask import jsonify, abort, make_response, request
from ssh_manager import utilities
from app_package import app
from app_package import functions
import jwt
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


###############################################################################################################


# Register the new user
@app.route('/users', methods=['POST'])  # Registration
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
    registered = functions.registration(user)
    if registered:
        return jsonify({'User': user}), 201
    else:
        return jsonify({"Message": "User already registered"})


# Login the registered user
@app.route('/users/login', methods=['POST'])  # Login
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
                            "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=60)},
                           app.config['SECRET_KEY'], algorithm='HS256')
        return jsonify({'Token': token.decode('UTF-8')})
    else:
        return make_response(jsonify({'Login Failed': 'Username or Password not match'}), 201)


# Delete the logined user
@app.route('/users', methods=['DELETE'])  # Delete User Account
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
# @login_required
def get_users():
    """ Getting all the users information
        params : Valid token Token for authorization purpose
        return : User all information (Username,Password etc)
    """
    users = functions.users()
    return users


# Get a single User
@app.route('/users/<string:username>', methods=['GET'])  # Get a single user data
@login_required
def get_user(username):
    """ Getting own information
        params : Valid token Token for authorization purpose
        return : User all information (Username, Password, Email, Login etc)
    """
    token = request.args.get('token')
    data = jwt.decode(token, app.config['SECRET_KEY'])
    if (username[0] == "\"" and username[-1] == "\"") or (username[0] == "\'" and username[-1] == "\'"):  # handling "1.2.3.4" should be equal to 1.2.3.4 for further process
        username = username[1:-1]
    print(data["Username"])
    if data['Username'] == username:
        user = functions.get_user(data)
        all_devices = utilities.get_devices(user['Username'])
        if all_devices:  # If user have some devices
            result = dict()
            for index, device in enumerate(all_devices):
                result[f'Device {index + 1}'] = device.to_json()
                user["User Devices "]= result
        else:  # if user have no device in db
            user["User Devices "] = "No Devices Yet"
        return user
    else:
        return jsonify({"Message":"Username and login user Not matched"})


# Logout the Logined user
@app.route('/logout', methods=['GET'])  # logout the user
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


"""
############################################ Credential related routes for a device ####################################
    /device/<string:ip_addr>         GET              get credential of the device (receive ip as url path)
    /device/<string:ip_addr>         POST             save credential of the device (
                                                            receive ip as url path
                                                            receive credential in post request
                                                            )
    /device/<string:ip_addr>         DELETE           delete credential of the device (receive ip as url path)
########################################################################################################################
"""


@app.route('/devices', methods=["GET"])  # get credential of device having this ip
@login_required
def get_devices():
    token = request.args.get('token')
    data = jwt.decode(token, app.config['SECRET_KEY'])
    user = functions.get_user(data)
    all_devices = utilities.get_devices(user['Username'])
    if all_devices:         # If user have some devices
        result = dict()
        for index, device in enumerate(all_devices):
            result[f'Device {index+1}'] = device.to_json()
        return jsonify({"Devices ": result})
    else:                   # if user have no device in db
        return jsonify({"Message": "NO DEVICE SAVED"})


@app.route('/devices/<string:device_id>', methods=["GET"])  # get credential of device having this ip
@login_required
def get_device(device_id):
    if (device_id[0] == "\"" and device_id[-1] == "\"") or (device_id[0] == "\'" and device_id[-1] == "\'"):  # handling "1.2.3.4" should be equal to 1.2.3.4 for further process
        device_id = device_id[1:-1]
    credentials = utilities.get_device_credential(device_id)
    if credentials is not None:
        return credentials
    else:
        return jsonify({"Message": "No device saved with this id"})


@app.route('/devices', methods=["POST"])  # save credential of device having this ip
@login_required
def post_credential():
    """
    This function get ip from url and credential as a post method. verify the credential if the credential are connect
    save the credential in yaml file else return message to the user
    :param id: IP for which you want to store ssh credential
    :return: message
    """
    token = request.args.get('token')
    data = jwt.decode(token, app.config['SECRET_KEY'])

    credentials = {
        'Username': request.json['username'],
        'Address': request.json['address'],
        'Password': request.json['password'],
        'User': data['Username']
    }
    device = SshClass()
    connected = device.connect(credentials)
    if connected:
        device_saved = utilities.save_device_credential(credentials)
        if device_saved is True:
            return jsonify({'Message': 'Device credential saved successfully'})
        else:
            return jsonify({'Message': 'This device is already registered'})

    else:
        return jsonify({'Message': 'Please double check your credentials'})


@app.route('/devices/<string:device_id>', methods=["DELETE"])  # delete the credential of the device
@login_required
def delete_credential(device_id):
    """
    Delete the credential from the yaml file against the providing ip
    :param device_id: delete credential of this ip
    :return: message
    """
    if (device_id[0] == "\"" and device_id[-1] == "\"") or (device_id[0] == "\'" and device_id[-1] == "\'"):  # handling "1.2.3.4" should be equal to 1.2.3.4 for further process
        device_id = device_id[1:-1]
    device_deleted = utilities.delete_device(device_id)
    if device_deleted:
        return jsonify({'Message': "Credential deleted Successfully"})
    else:
        return jsonify({'Message': "No device saved with this id"})



"""

#########################################SSH route to run the command##########################################
    /device/<string:ip_addr>/ssh     POST             run command on the device (
                                                            receive ip address as url path
                                                            receive command as url parameter
                                                            receive device credential from database 
                                                            )
###############################################################################################################
"""


@app.route('/devices/<string:device_id>/ssh', methods=['GET'])  # run ssh command on device having following ip
@login_required
def run_command(device_id):
    """
    This function first check the credential if the credential is correct, ssh the device and run the command
    but if credentials are wrong, return a message that credential are wrong
    :param: it takes 2 argument i-e IP and command
    :return: Message1 = result of the command
             Message2 = Wrong credentials
    """
    command_to_run = request.args.get('command')
    if (device_id[0] == "\"" and device_id[-1] == "\"") or (device_id[0] == "\'" and device_id[-1] == "\'"):  # handling "1.2.3.4" should be equal to 1.2.3.4 for further process
        device_id = device_id[1:-1]
    credentials = utilities.get_device_credential(device_id)
    if credentials is None:
        return jsonify({"Message": "Unknown Device"})
    credentials["Command"] = command_to_run
    device = SshClass()
    connected = device.connect(credentials)
    if connected:
        result = device.run_command(command_to_run)
        device.disconnect()
        return result
    else:
        return jsonify({"Message": "Wrong credential or device is not up"})
