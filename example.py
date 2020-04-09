from pathlib import Path

from keepassxc_browser import Connection, Identity, ProtocolError


def main():
    client_id = 'python-keepassxc-browser'

    state_file = Path('.assoc')
    if state_file.exists():
        with state_file.open('r') as f:
            data = f.read()
        id = Identity.unserialize(client_id, data)
    else:
        id = Identity(client_id)

    c = Connection()
    c.connect()
    c.change_public_keys(id)
    try:
        c.get_database_hash(id)
    except ProtocolError as ex:
        print(ex)
        exit(1)

    if not c.test_associate(id):
        print('Not associated yet, associating now...')
        assert c.associate(id)
        data = id.serialize()
        with state_file.open('w') as f:
            f.write(data)
        del data

    c.create_password(id)
    c.set_login(
        id,
        url='https://python-test123',
        login='test-user',
        password='test-password',
        entry_id=None,
        submit_url=None,
    )
    c.get_logins(id, url='https://python-test123')
    # c.lock_database(id)
    c.disconnect()


if __name__ == "__main__":
    main()
