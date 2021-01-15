from app_package.models import Device
from app_package.models import db


def save_device_credential(device):
    """
    Registeration of new device
    :param device: take device information to save in the database
    :return: True: if device credential saved successfully
             False: if device not saved in database
    """
    new_device = Device(Username=device['Username'], Password=device['Password'],User= device['User'], Address=device['Address'])
    try:
        db.session.add(new_device)
        db.session.commit()
        return True
    except:  # ########################### Unique Constraint breaks ##################################
        print("This device is already registered")
        return False


def get_devices(user):
    """
    Getting all the devices of logged in user
    :param user: username / userid which we used to maintain sessions
    :return (Error message if user not found in database) or (id's of logged in user devices):
    """
    devices = db.session.query(Device).filter_by(User=user).all()
    return devices


def get_device_credential(device_id):
    """
    Getting one device information
    :param device_id: get id for searching in database
    :return (None if device not found in database) or (Information of user in the form of dictionary):
    """
    device = Device.query.filter_by(id=device_id).first()
    if device is not None:
        return device.to_json()
    else:
        return None


def delete_device(device_id):
    """
    Delete the user
    :param device_id: receive id to delete device
    :return Success report (if credential true then True else False):
    """
    device = Device.query.filter_by(id=device_id).first()
    if device is not None:
        db.session.delete(device)
        db.session.commit()
        return True
    else:
        return False
