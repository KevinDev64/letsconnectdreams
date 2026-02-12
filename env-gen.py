#!/usr/bin/env python3

import string
import secrets

alphabet = string.ascii_letters + string.digits

def generate_secret(l):
    return ''.join(secrets.choice(alphabet) for i in range(l))
    
env_file = open(".env", "w")

env_file.write("# This file generated AUTOMATICALLY. DONT'T CHANGE THIS!\n")
env_file.write("# If you want to add/remove/change any strings, you should rewrite env-gen.py!\n")

password = generate_secret(64)

env_file.write("POSTGRES_USER=postgres\n")
env_file.write("POSTGRES_PASSWORD={}\n".format(password))
env_file.write("POSTGRES_DB=postgres\n")
env_file.write("POSTGRES_HOST=db\n")
env_file.write("DATABASE_URL=postgres://postgres:{}@localhost/postgres\n".format(password))

env_file.close()
print("Done.")
