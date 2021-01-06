import yaml

def delete_known_old_credentials(ip_address):
    """

    :param ip_address: IP address to check if the credential already save in store_connection.yaml file
    :return:
    """
    with open(r'./ssh_manager/store_connection.yaml','r') as file:
        connection_list = yaml.load(file, Loader=yaml.FullLoader)
        kept = list()
        if connection_list is not None:         # already saved atleast one credential in yaml file
            for device in connection_list:      # extract one by one each device credential
                if not str(device.keys()).find(ip_address):  # other devices (Mismatching the ip address provided)
                    kept.append(device)  # append other device credentials in the list to keep in the yaml file
    with open(r'./ssh_manager/store_connection.yaml', 'w') as file:  # open file in writing mode
        if len(kept):   # if we have some information to keep in the yaml file which we already retrieved other than
            # provided ip credential
            yaml.dump(kept, file)   # append the devices credentials again in the yaml file
        return True

def credential_of_device(ip_address):
    """

    :param ip_address: IP address for which you want credential to which you have already connected
    :return: credentials = return credentials of the proved ip
             None =  if no credential saved in the
    """
    with open(r'./ssh_manager/store_connection.yaml', 'r') as file:
        connection_list = yaml.load(file, Loader=yaml.FullLoader)
        if connection_list is not None:     # some credential saved in file and its not empty
            for device in connection_list:  # traversing one by one device credentials which are saved
                if str(device.keys()).find(ip_address):  # getting credential of the provide ip address
                    credential = {
                        "Username": device[ip_address][0],  # username according to yaml file data
                        "Address": ip_address,              # ip address fo the device by parameter
                        "Password": device[ip_address][1]   # password according to yaml file data
                    }
                    return credential   # return all the credential to the user
    return None    # if no credential are saved for provided ip

