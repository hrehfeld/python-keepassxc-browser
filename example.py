from keepassxc_browser import Connection, Identity, ProtocolError
from pathlib import Path

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
        associated_name = c.associate(id)
        assert c.test_associate(id)
        data = id.serialize()
        with state_file.open('w') as f:
            f.write(data)
        del data

    c.create_password(id)
    groups = c.get_database_groups(id)
    root = groups[0] # {name: 'AAAA', uuid: 'BBBB', children: [...]}
    foo = c.create_database_group(id, 'foo')
    assert foo['uuid'] == c.find_group_uuid(id, 'foo')
    
    c.set_login(id, 
                url='https://python-test123', 
                login='test-user', 
                password='test-password', 
                group_uuid=foo['uuid'], 
                submit_url=None)
    
    c.get_logins(id, url='https://python-test123')
    # c.lock_database(id)
    c.disconnect()

if __name__ == "__main__":
    main()
