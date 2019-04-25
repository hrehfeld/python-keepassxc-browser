from base64 import b64decode, b64encode
import json
import os.path
import platform
import pysodium
import socket
from pathlib import Path

BUFF_SIZE = 1024 * 1024
DEFAULT_SOCKET_TIMEOUT = 60

DEFAULT_SOCKET_NAME = 'kpxc_server'


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
    assert(isinstance(nonce, bytes))

    c_state = 1
    for i, x in enumerate(next_nonce):
        c_state += x
        c_state %= 256
        next_nonce[i] = c_state
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
    command = {
        "action": action,
        "triggerUnlock": 'true'
    }
    command.update(data)
    return command


def create_message(action, **data):
    command = {
        "action": action,
        "triggerUnlock": 'true'
    }
    command.update(data)
    return command


def create_encrypted_command(crypto, action, message):
    nonce = create_nonce()
    command = create_command(
        action
        , message=binary_to_b64(crypto.encrypt_message(message, nonce))
    )
    return command, nonce


class ProtocolError(Exception):
    pass


class Connection:
    def __init__(self):
        # TODO: darwin is untested
        tmpdir = os.getenv('TMPDIR')
        if tmpdir:
            tmpdir = Path(tmpdir)
            tmpdir_socket_path = (tmpdir / DEFAULT_SOCKET_NAME)
        xdg_runtime_dir = os.getenv('XDG_RUNTIME_DIR')

        if platform.system() == "Darwin" and tmpdir and tmpdir_socket_path.exists():
            server_address = tmpdir_socket_path
        elif xdg_runtime_dir:
            server_address = Path(xdg_runtime_dir) / DEFAULT_SOCKET_NAME
            # TODO: tmpdir is untested
        elif tmpdir and tmpdir_socket_path.exists():
            server_address = tmpdir_socket_path
        else:
            raise OSError('Unknown path for keepassxc socket.')

        self.server_address = server_address

        self.sock = None

    def connect(self):
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(DEFAULT_SOCKET_TIMEOUT)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, BUFF_SIZE)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, BUFF_SIZE)

        try:
            sock.connect(str(self.server_address))
        except socket.error as message:
            sock.close()
            raise Exception("Could not connect to {addr}".format(addr=self.server_address))

        self.sock = sock


    def disconnect(self):
        self.sock.close()

    def send(self, command):
        assert(isinstance(command, str))
        self.sock.send(command.encode())

        resp, server = self.sock.recvfrom(BUFF_SIZE)
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
            'change-public-keys',
            publicKey=binary_to_b64(identity.publicKey)
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
            action
            , key=binary_to_b64(identity.publicKey)
            , idKey=binary_to_b64(identity.associated_id_key)
        )
        resp_message = self.encrypt_message_send_command(identity, action, message)
        assert 'id' in resp_message
        associated_name = resp_message['id']
        identity.associated_name = associated_name
        return associated_name

    def test_associate(self, identity):
        action = 'test-associate'
        assert identity.associated_id_key is not None, identity.associated_id_key

        message = create_message(action
                                      , id=identity.associated_name
                                      , key=binary_to_b64(identity.associated_id_key)
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
            action
            , url=url
            , keys=[dict(key=binary_to_b64(identity.publicKey)
                         , idKey=binary_to_b64(identity.associated_id_key))]
        )
        if submit_url:
            message['submitUrl'] = submit_url
        if http_auth:
            message['httpAuth'] = http_auth

        resp_message = self.encrypt_message_send_command(identity, action, message)
        return resp_message['entries']

    def set_login(self, identity, url, login=None, password=None, entry_id=None, submit_url=None):
        if not (url.startswith('mailto:') or url.startswith('https:')):
            raise Exception('Url needs to start with "mailto:" or "https:"')
        action = 'set-login'
        message = create_message(
            action
            , url=url
        )
        for k in 'login password entry_id submit_url'.split():
            v = locals()[k]
            if v is not None:
                message[k] = v
        resp_message = self.encrypt_message_send_command(identity, action, message)
        assert resp_message['success']

    def lock_database(self, identity):
        action = 'lock-database'
        message = create_message(action)
        resp_message = self.encrypt_message_send_command(identity, action, message)
        assert resp_message['success']


class Identity:
    def __init__(self, client_id, public_key=None, private_key=None, id_key=None, associated_name=None, server_public_key=None):
        self.client_id = client_id
        if not public_key:
            assert not private_key
        if not private_key:
            assert not public_key
        if not public_key:
            public_key, private_key = create_keypair()

        if not id_key:
            id_key = create_public_key()
        self.publicKey = public_key
        self.secretKey = private_key
        self.associated_id_key = id_key
        self.associated_name = associated_name
        self.serverPublicKey = server_public_key

    def sign_command(self, command, nonce):
        command.setdefault('nonce', binary_to_b64(nonce))
        command.setdefault('clientID', self.client_id)

    def encrypt_message(self, message, nonce):
        message = json.dumps(message)
        message = message.encode()
        message = encrypt(message, nonce, self.serverPublicKey, self.secretKey)
        return message

    def decrypt_message(self, resp_message, expected_nonce):
        resp_message = binary_from_b64(resp_message)
        resp_message = decrypt(resp_message, expected_nonce, self.serverPublicKey, self.secretKey)
        resp_message = json.loads(resp_message)
        check_nonces(resp_message, expected_nonce)
        return resp_message

    def serialize(self):
        binary_data = self.publicKey, self.secretKey, self.associated_id_key, self.serverPublicKey
        text_data = self.associated_name,
        binary_data  = [binary_to_b64(d) for d in binary_data]
        s = json.dumps(list(binary_data) + list(text_data))
        return s

    @classmethod
    def unserialize(cls, client_id, s):
        data = json.loads(s)
        binary_data = data[:4]
        text_data = data[4:]
        binary_data = [binary_from_b64(d) for d in binary_data]
        public_key, private_key, id_key, server_public_key = binary_data
        associated_name, = text_data
        return cls(
            client_id=client_id
            , public_key=public_key
            , private_key=private_key
            , id_key=id_key
            , associated_name=associated_name
            , server_public_key=server_public_key
        )
