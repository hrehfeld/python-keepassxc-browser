import win32file


class WinSock:
    """ A basic socket wrapper for Windows named pipes """

    def __init__(self, desired_access, creation_disposition, share_mode=0,
                 security_attributes=None, flags_and_attributes=0, input_nullok=None):
        self.desired_access = desired_access
        self.creation_disposition = creation_disposition
        self.share_mode = share_mode
        self.security_attributes = security_attributes
        self.flags_and_attributes = flags_and_attributes
        self.input_nullok = input_nullok
        self.handle = None

    def connect(self, address):
        try:
            self.handle = win32file.CreateFile(
                r'\\.\pipe\%s' % address,
                self.desired_access,
                self.share_mode,
                self.security_attributes,
                self.creation_disposition,
                self.flags_and_attributes,
                self.input_nullok
            )
        except Exception as e:
            raise Exception(
                "Could not connect to pipe {addr}".format(addr=address), e
            )

    def close(self):
        if self.handle:
            self.handle.close()

    def send(self, message: str):
        win32file.WriteFile(self.handle, message)

    def recvfrom(self, buff_size):
        response_code, data = win32file.ReadFile(self.handle, buff_size)
        return data, response_code
