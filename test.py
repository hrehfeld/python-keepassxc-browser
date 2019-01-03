from keepassxc_http import Connection, Identity
from pathlib import Path


client_id = 'python-keepassxc-http'

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
c.get_database_hash(id)

if not c.test_associate(id):
    associated_name = c.associate(id)
    assert c.test_associate(id)
    data = id.serialize()
    with state_file.open('w') as f:
        f.write(data)
    del data

c.create_password(id)
c.set_login(id, url='https://python-test123', login='test-user', password='test-password', entry_id=None, submit_url=None)
c.get_logins(id, url='https://python-test123')
# c.lock_database(id)
c.disconnect()
