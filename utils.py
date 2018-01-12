from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import AES, PKCS1_OAEP
import os
import uuid
import random
import hashlib
import sqlite3
import binascii

def get_full_password(password, salt) -> str:
    salted_pass = salt + password
    return hashlib.md5(salted_pass.encode('utf8')).hexdigest()


def RSA_encrypt_salt(salt, users_uuid, app) -> str:
    if not os.path.isdir(os.path.join(app.root_path, "pkey")):
        os.mkdir(os.path.join(app.root_path, "pkey"))
    private =RSA.generate(1024)
    public = private.publickey()
    with open(os.path.join(app.root_path, "pkey", "{}.pkey".format(users_uuid)), "wb") as f:
        f.write(private.exportKey())
    cipher_rsa = PKCS1_OAEP.new(public)
    crypto = cipher_rsa.encrypt(salt.encode('utf8'))
    return binascii.hexlify(crypto).decode('utf8')


def decrypt_salt(uuid, crypted_salt, app) -> str:
    with open(os.path.join(app.root_path, "pkey", "{}.pkey".format(uuid)), "rb") as f:
        keydata = f.read()
    private_key = RSA.import_key(keydata)
    cipher_rsa = PKCS1_OAEP.new(private_key)
    decrypro = cipher_rsa.decrypt(binascii.unhexlify(crypted_salt.encode('utf8')))
    return decrypro.decode('utf8')


def is_password_valid(username, password, db_connection, app) -> bool:
    db_resp = db_connection.execute("SELECT uuid, password, salt FROM users WHERE username is ?",
                                    [username])
    resp = db_resp.fetchall()[0]
    salt = decrypt_salt(uuid=resp['uuid'], crypted_salt=resp['salt'], app=app)
    original = resp['password']
    getted = get_full_password(password=password, salt=salt)
    return original == getted


def get_uuid() -> str:
    return str(uuid.uuid1()).replace('-', '')


def get_users_props(username, password, db_connection) -> dict:
    db_resp = db_connection.execute("SELECT * FROM users WHERE username is ?", [username])
    creds = dict(db_resp.fetchall()[0])
    for key in ('age', 'email','fullname','country'):
        creds[key] = AES_decrypt(creds[key],password)
    return creds


def is_user(username, db_connections) -> bool:
    db_resp = db_connections.execute("SELECT username from users WHERE username is ?",
                                     [username])
    users = db_resp.fetchall()
    return bool(users)

def AES_encrypt(msg, key) -> str:

    key_32 = key.rjust(32, '*') if len(key) <= 32 else key[:32]
    key_32_b = key_32.encode('utf-8')
    cipher = AES.new(key_32_b, AES.MODE_CFB,b'This is an IV456')
    return binascii.hexlify(cipher.encrypt(msg.encode('utf-8'))).decode('utf8')


def AES_decrypt(encrypted_msg, key) -> str:
    key_32 = key.rjust(32, '*') if len(key) <= 32 else key[:32]
    key_32_b = key_32.encode('utf-8')
    cipher = AES.new(key_32_b, AES.MODE_CFB,b'This is an IV456')
    return cipher.decrypt(binascii.unhexlify(encrypted_msg.encode('utf-8'))).decode('utf8')


def get_db_connect(app) -> sqlite3.connect:
    rv = sqlite3.connect(app.config['DATABASE'])
    rv.row_factory = sqlite3.Row
    return rv

def handle_signup_request(form_content, db_connection, app) -> None:
    salt = ''.join(chr(random.randint(33, 126)) for i in range(10))
    users_uuid = get_uuid()
    sql_req = "INSERT INTO users (uuid, username, password, age,fullname,country, email, salt) " \
              "values (:uuid, :username, :password, :age, :fullname, :country, :email, :salt)"
    kwargs = {"uuid": users_uuid,
              "username": form_content['username'],
              "password": get_full_password(password=form_content['password'], salt=salt),
              "age": AES_encrypt(msg=form_content['age'], key=form_content['password']),
              "fullname": AES_encrypt(msg=form_content['fullname'], key=form_content['password']),
              "country": AES_encrypt(msg=form_content['country'], key=form_content['password']),
              "email": AES_encrypt(msg=form_content['email'], key=form_content['password']),
              "salt": RSA_encrypt_salt(salt=salt, users_uuid=users_uuid, app=app)}
    db_connection.execute(sql_req, kwargs)
    db_connection.commit()
