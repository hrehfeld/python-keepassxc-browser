from keepassxc_browser import Connection, Identity
from pathlib import Path


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
c.get_database_hash(id)

if not c.test_associate(id):
    associated_name = c.associate(id)
    assert c.test_associate(id)
    data = id.serialize()
    with state_file.open('w') as f:
        f.write(data)
    del data

login, password = c.create_password(id)
url = 'https://python-test123'
c.set_login(id, url=url, login='test-user', password=password, entry_id=None, submit_url=None)
c.get_logins(id, url=url)
# c.lock_database(id)
c.disconnect()
