import paramiko


class SshClass:
    def __init__(self):
        self.client = None
        self.ip_addr = None
        self.command = None
        self.username = None
        self.password = None
        self.result = ""        # Not used

    def connect(self,credentials):
        """
        :param username: Username of the device which you want to ssh/connect
        :param ip_address: IP address of the device which you want to ssh/connect
        :param password: Password of the device which you want to ssh/connect
        :return: True / False
        """
        self.username = credentials['Username']
        self.ip_addr = credentials['Address']
        self.password = credentials['Password']
        client = paramiko.SSHClient()  # paramiko client object
        client.load_system_host_keys()  # this loads any local ssh keys
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(self.ip_addr, username=self.username, password=self.password)  # connecting to server
            self.client = client
            return True
        except:
            # return json.loads(json.dumps({'message': 'Connection not established'})), 403
            print("Connection not build successfully")
            return False

    def run_command(self, command):
        """
        :param command: command that you run on the device which you have sshed and already connected by using connect funtion
        :return:
        """
        if self.client is None:
            print("First Build the connection by using connect function")
            return False
        else:
            try:
                _, ss_stdout, ss_stderr = self.client.exec_command(command)  # executing command on server and return
                # result
                r_out, r_err = ss_stdout.readlines(), ss_stderr.read()  # ss_stderr for error and ss_stdout for
                # result of command
                result = ""     # to save result of the command
                if len(r_err) > 5:
                    result = r_err.decode("utf-8")
                else:
                    for line in r_out:
                        result = str(result) + str(line)
                # self.client.close()  # closing connection
            except IOError:  # if host/server is not up or for any other issue
                print("host is not up")
                return "host not up", 500
            return result

    def disconnect(self):
        """
        :return: True if the
        """
        try:
            if self.client is not None:
                self.client.close()
                self.client = None
                return True
            else:
                return False

        except:
            return False
