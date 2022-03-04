import json
import os.path
import platform
import socket
from base64 import b64decode, b64encode
from pathlib import Path

import pysodium

if platform.system() == "Windows":
    import win32file
    from .connection_win import WinSock

else:
    from .connection_posix import DefaultSock

from .exceptions import ProtocolError

BUFF_SIZE = 1024 * 1024
DEFAULT_SOCKET_TIMEOUT = 60

DEFAULT_SOCKET_NAME = "org.keepassxc.KeePassXC.BrowserServer"


def create_keypair():
    """Return (public key, private key)"""
    return pysodium.crypto_box_keypair()


def create_nonce():
    return pysodium.randombytes(pysodium.crypto_box_NONCEBYTES)


def create_public_key():
    return pysodium.randombytes(pysodium.crypto_box_PUBLICKEYBYTES)


def create_nonces(nonce=None, next_nonce=None):
    if nonce is None:
        nonce = create_nonce()
        assert next_nonce is None, next_nonce
    if next_nonce is None:
        next_nonce = increment_nonce(nonce)
    return nonce, next_nonce


def increment_nonce(nonce):
    next_nonce = list(nonce)
    assert isinstance(nonce, bytes)

    c_state = 1
    for i, x in enumerate(next_nonce):
        c_state += x
        next_nonce[i] = c_state % 256
        c_state >>= 8

    return bytes(next_nonce)


def encrypt(message, nonce, serverKey, secretKey):
    return pysodium.crypto_box(message, nonce, serverKey, secretKey)


def decrypt(message, nonce, serverKey, secretKey):
    return pysodium.crypto_box_open(message, nonce, serverKey, secretKey)


def binary_to_b64(binary):
    assert isinstance(binary, bytes), binary
    return b64encode(binary).decode()


def binary_from_b64(s):
    assert isinstance(s, str), s
    return b64decode(s.encode())


def check_nonces(response, expected_nonce):
    assert isinstance(response, dict), response
    nonce_key = 'nonce'
    assert nonce_key in response, repr(response)
    response_nonce = binary_from_b64(response[nonce_key])
    assert response_nonce == expected_nonce


def create_command(action, **data):
    command = {"action": action, "triggerUnlock": 'true'}
    command.update(data)
    return command


def create_message(action, **data):
    command = {"action": action, "triggerUnlock": 'true'}
    command.update(data)
    return command


def create_encrypted_command(crypto, action, message):
    nonce = create_nonce()
    command = create_command(
        action, message=binary_to_b64(crypto.encrypt_message(message, nonce))
    )
    return command, nonce


class Connection:
    def __init__(self, socket_name=DEFAULT_SOCKET_NAME):
        # TODO: darwin is untested
        tmpdir = os.getenv('TMPDIR')
        if tmpdir:
            tmpdir = Path(tmpdir)
            tmpdir_socket_path = tmpdir / socket_name

        xdg_runtime_dir = os.getenv('XDG_RUNTIME_DIR')
        if xdg_runtime_dir:
            xdg_runtime_dir = Path(xdg_runtime_dir)
            runtime_socket_path = xdg_runtime_dir / socket_name

        if platform.system() == "Windows":
            server_address = f"{DEFAULT_SOCKET_NAME}_{os.getenv('USERNAME')}"
            sock = WinSock(win32file.GENERIC_READ | win32file.GENERIC_WRITE, win32file.OPEN_EXISTING)
        elif platform.system() == "Darwin" and tmpdir and tmpdir_socket_path.exists():
            server_address = tmpdir_socket_path
            sock = DefaultSock(DEFAULT_SOCKET_TIMEOUT, BUFF_SIZE)
        elif xdg_runtime_dir and runtime_socket_path.exists():
            server_address = runtime_socket_path
            # TODO: tmpdir is untested
            sock = DefaultSock(DEFAULT_SOCKET_TIMEOUT, BUFF_SIZE)
        elif tmpdir and tmpdir_socket_path.exists():
            server_address = tmpdir_socket_path
            sock = DefaultSock(DEFAULT_SOCKET_TIMEOUT, BUFF_SIZE)
        else:
            raise OSError('Unknown path for keepassxc socket.')

        self.server_address = server_address
        self.connection = sock

    def connect(self):
        self.connection.connect(str(self.server_address))

    def disconnect(self):
        self.connection.close()

    def send(self, command):
        assert isinstance(command, str)
        self.connection.send(command.encode())

        resp, server = self.connection.recvfrom(BUFF_SIZE)
        r = resp.decode()
        return r

    def send_json(self, command):
        return json.loads(self.send(json.dumps(command)))

    def send_command(self, identity, command, nonce=None, next_nonce=None):
        nonce, next_nonce = create_nonces(nonce, next_nonce)

        identity.sign_command(command, nonce)
        resp = self.send_json(command)
        if 'error' in resp:
            raise ProtocolError(resp['error'])
        check_nonces(resp, next_nonce)
        return resp

    def send_encrypted_command(self, identity, command, nonce=None, next_nonce=None):
        nonce, next_nonce = create_nonces(nonce, next_nonce)
        resp = self.send_command(identity, command, nonce, next_nonce)
        resp_message = identity.decrypt_message(resp['message'], next_nonce)
        return resp_message

    def encrypt_message_send_command(self, identity, action, message):
        command, nonce = create_encrypted_command(identity, action, message)
        return self.send_encrypted_command(identity, command, nonce)

    def change_public_keys(self, identity):
        nonce, next_nonce = create_nonces()

        command = create_command(
            'change-public-keys', publicKey=binary_to_b64(identity.publicKey)
        )
        resp = self.send_command(identity, command)

        assert 'publicKey' in resp, resp
        server_public_key = binary_from_b64(resp['publicKey'])
        identity.serverPublicKey = server_public_key

    def get_database_hash(self, identity):
        action = 'get-databasehash'
        message = create_message(action)
        resp_message = self.encrypt_message_send_command(identity, action, message)
        return resp_message['hash']

    def associate(self, identity):
        action = 'associate'
        message = create_message(
            action,
            key=binary_to_b64(identity.publicKey),
            idKey=binary_to_b64(identity.associated_id_key),
        )
        resp_message = self.encrypt_message_send_command(identity, action, message)
        assert 'id' in resp_message
        associated_name = resp_message['id']
        identity.associated_name = associated_name
        return associated_name

    def test_associate(self, identity):
        action = 'test-associate'
        assert identity.associated_id_key is not None, identity.associated_id_key

        message = create_message(
            action,
            id=identity.associated_name,
            key=binary_to_b64(identity.associated_id_key),
        )
        try:
            self.encrypt_message_send_command(identity, action, message)
        except ProtocolError:
            return False
        return True

    def create_password(self, identity):
        action = 'generate-password'
        command = create_command(action)
        nonce = create_nonce()
        resp = self.send_encrypted_command(identity, command, nonce)

        assert 'entries' in resp
        entries = resp['entries']
        assert len(entries) == 1, resp
        entry = entries[0]
        return entry['login'], entry['password']

    def get_logins(self, identity, url, submit_url=None, http_auth=None):
        action = 'get-logins'
        message = create_message(
            action,
            id=identity.associated_name,
            url=url,
            keys=[
                dict(
                    id=identity.associated_name,
                    key=binary_to_b64(identity.associated_id_key),
                )
            ],
        )
        if submit_url:
            message['submitUrl'] = submit_url
        if http_auth:
            message['httpAuth'] = http_auth

        resp_message = self.encrypt_message_send_command(identity, action, message)
        return resp_message['entries']

    def set_login(
        self, identity, url, login=None, password=None, entry_id=None, submit_url=None
    ):
        if not (url.startswith('mailto:') or url.startswith('https:')):
            raise Exception('Url needs to start with "mailto:" or "https:"')
        action = 'set-login'
        message = create_message(action, id=identity.associated_name, url=url)

        def fill_message(k, v):
            if v is not None:
                message[k] = v

        fill_message('login', login)
        fill_message('password', password)
        fill_message('uuid', entry_id)
        fill_message('submit_url', submit_url)

        resp_message = self.encrypt_message_send_command(identity, action, message)
        assert resp_message['success']

    def create_database_group(self, identity, name):
        assert name, 'Group name must not be empty.'
        action = 'create-new-group'
        message = create_message(action, id=identity.associated_name)
        message['groupName'] = name
        resp_message = self.encrypt_message_send_command(identity, action, message)
        assert resp_message['success']
        return dict(name=resp_message['name'], uuid=resp_message['uuid'])

    def lock_database(self, identity):
        action = 'lock-database'
        message = create_message(action)
        resp_message = self.encrypt_message_send_command(identity, action, message)
        assert resp_message['success']

    def is_database_open(self, identity):
        # Yeah, that's really hacky, FIXME when https://github.com/keepassxreboot/keepassxc-browser/issues/594 is closed
        try:
            self.get_database_hash(identity)
            return True
        except ProtocolError:
            return False

    def wait_for_unlock(self):
        """
        This will listen to all messages until {'action': 'database-unlocked'}
 is received.
        If the database is already open, it will wait until it is unlocked the next time. This
        will not time out. If the database was unlocked while connected, and this method is called
        afterwards, it will return even if the database has been closed again in the meantime.
        """
        while True:
            try:
                action = json.loads(self.connection.recvfrom(BUFF_SIZE)[0].decode())['action']
                if action == "database-unlocked":
                    break
            except socket.timeout:
                pass


class Identity:
    VERSION = 1
    VERSION_KEY = 'version'
    BINARY_KEY = 'binary'
    TEXT_KEY = 'text'

    def __init__(
        self,
        client_id,
        id_key=None,
        associated_name=None,
    ):
        self.client_id = client_id
        public_key, private_key = create_keypair()

        if not id_key:
            id_key = create_public_key()
        self.publicKey = public_key
        self.secretKey = private_key
        self.associated_id_key = id_key
        self.associated_name = associated_name
        self.serverPublicKey = None

    def sign_command(self, command, nonce):
        command.setdefault('nonce', binary_to_b64(nonce))
        command.setdefault('clientID', self.client_id)

    def encrypt_message(self, message, nonce):
        message = json.dumps(message)
        message = message.encode()
        assert self.serverPublicKey
        message = encrypt(message, nonce, self.serverPublicKey, self.secretKey)
        return message

    def decrypt_message(self, resp_message, expected_nonce):
        resp_message = binary_from_b64(resp_message)
        resp_message = decrypt(
            resp_message, expected_nonce, self.serverPublicKey, self.secretKey
        )
        resp_message = json.loads(resp_message)
        check_nonces(resp_message, expected_nonce)
        return resp_message

    def serialize(self):
        binary_data = (self.associated_id_key,)
        text_data = (self.associated_name,)
        binary_data = [binary_to_b64(d) for d in binary_data]
        s = json.dumps({
            self.VERSION_KEY: self.VERSION,
            self.BINARY_KEY: list(binary_data),
            self.TEXT_KEY: list(text_data),
        })
        return s

    @classmethod
    def unserialize(cls, client_id, s):
        data = json.loads(s)
        if isinstance(data, list):
            return cls.unserialize_v0(client_id, data)

        unserializers = {
            1: cls.unserialize_v1,
        }

        version = data[cls.VERSION_KEY]
        assert version in unserializers, 'unknown version %s' % version
        return unserializers[version](client_id, data)

    @classmethod
    def unserialize_v1(cls, client_id, data):
        binary_data = data[cls.BINARY_KEY]
        binary_data = [binary_from_b64(d) for d in binary_data]
        text_data = data[cls.TEXT_KEY]
        (id_key,) = binary_data
        (associated_name,) = text_data
        return cls(
            client_id=client_id,
            id_key=id_key,
            associated_name=text_data[0],
        )

    @classmethod
    def unserialize_v0(cls, client_id, data):
        """The first version unserialize, maintained for backwards compatability."""

        assert isinstance(data, list)

        BINARY_SIZE = 4
        TEXT_SIZE = 1
        DATA_SIZE = BINARY_SIZE + TEXT_SIZE

        assert len(data) == DATA_SIZE, data
        binary_data = data[:BINARY_SIZE]
        text_data = data[BINARY_SIZE:]

        binary_data = [binary_from_b64(d) for d in binary_data]
        public_key, private_key, id_key, server_public_key = binary_data
        (associated_name,) = text_data
        # public_key, private_key, server_public_key ignored, will be regenerated every time
        return cls(
            client_id=client_id,
            id_key=id_key,
            associated_name=associated_name,
        )
