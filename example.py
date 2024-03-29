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
        db_hash = c.get_database_hash(id)
    except ProtocolError as ex:
        print(ex)
        exit(1)
    print(db_hash)

    if not c.test_associate(id):
        print('Not associated yet, associating now...')
        assert c.associate(id)
        data = id.serialize()
        with state_file.open('w') as f:
            f.write(data)
        del data

    login = {}
    try:
        logins = c.get_logins(id, url='https://python-test123')
        print(logins)
        assert len(logins) == 1, logins
        login = logins[0]
    except ProtocolError:
        print('Creating entry')
        c.create_password(id)

    print('setting password')
    uuid = login.get('uuid', None)
    c.set_login(
        id,
        url='https://python-test123',
        login='test-user',
        password=login.get('password', '') + '_1',
        entry_id=uuid,
        submit_url=None,
    )
    # c.lock_database(id)

    # group = c.create_database_group(id, 'keepassxc-rocks')
    # assert group['name'] == 'keepassxc-rocks' and len(group['uuid']) == 32

    c.disconnect()


if __name__ == "__main__":
    main()
