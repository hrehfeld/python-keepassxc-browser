from pathlib import Path

from keepassxc_browser import Connection, Identity, ProtocolError


def main():
    client_id = "python-keepassxc-browser"

    state_file = Path(".assoc")
    if state_file.exists():
        with state_file.open("r") as f:
            data = f.read()
        identity = Identity.unserialize(client_id, data)
    else:
        identity = Identity(client_id)

    c = Connection()
    c.connect()
    c.change_public_keys(identity)
    try:
        c.get_database_hash(identity)
    except ProtocolError as ex:
        print(ex)
        exit(1)

    if not c.test_associate(identity):
        c.associate(identity)
        assert c.test_associate(identity)
        data = identity.serialize()
        with state_file.open("w") as f:
            f.write(data)
        del data

    c.create_password(identity)
    c.set_login(
        identity,
        url="https://python-test123",
        login="test-user",
        password="test-password",
        entry_id=None,
        submit_url=None,
    )
    c.get_logins(identity, url="https://python-test123")
    # c.lock_database(id)
    c.disconnect()


if __name__ == "__main__":
    main()
