import yaml
from app_package.models import Device
from app_package.models import db


def save_device_credential(device):
    """
    Registeration of new user
    :param user:
    :return:
    """
    new_device = Device(Username=device['Username'], Password=device['Password'],User= "Ashfaq", Address=device['Address'])
    try:
        db.session.add(new_device)
        db.session.commit()
        return True
    except:  # ########################### Unique Constraint breaks ##################################
        print("This device is already registered")
        return False

def get_device_credential(ip_addr):
    """
    Getting one user(only self) information
    :param user_data:
    :return (Error message if user not found in database) or (Information of user in the form of dictionary):
    """
    device = Device.query.filter_by(Address=ip_addr).first()
    if device is not None:
        return device.information()
    else:
        return None


def delete_device(ip_addr):
    """
    Delete the user
    :param device_data:
    :return Success report (if credential matched then True else False):
    """
    device = Device.query.filter_by(Address=ip_addr).first()
    if device is not None:
        db.session.delete(device)
        db.session.commit()
        return True
    else:
        return False
