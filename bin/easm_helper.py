import os
import csv


def get_password(service, realm):
    settings = None
    storage_passwords = service.storage_passwords
    for k in storage_passwords:
        p = str(k.content.get("clear_password"))
        pw_realm = str(k.content.get("realm"))
        if pw_realm == realm:
            settings = p
            break

    return settings


def read_lookup_file(lookup_file_name: str):
    csv_file_path = os.path.join(
        os.path.dirname(__file__), "..", "lookups", lookup_file_name
    )

    if not os.path.exists(csv_file_path):
        return []

    with open(csv_file_path, newline="") as csvfile:
        reader = csv.DictReader(csvfile)
        return list(reader)
