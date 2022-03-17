import random
import os
from settings import *
from Crypto.PublicKey import RSA
import json
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP


def get_rand_pass(len_pas):
    pas = ""
    ascii_codes = set(i for i in range(35, 127))
    ascii_codes.difference_update(EXCLUDED_CHARACTERS)

    for i in range(len_pas):
        symb = chr(random.choice(list(ascii_codes)))
        pas += symb

    return pas


def save_enc_data(password, login, f, name):
    json_data = str(json.dumps({"password": password, "login": login})).encode("utf-8")

    recipient_key = RSA.import_key(
        open(DIR_KEYS + "/" + name + "/" + PUBLIC_RSA_KEY).read()
    )

    session_key = get_random_bytes(16)

    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    f.write(cipher_rsa.encrypt(session_key))

    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    cipher_text, tag = cipher_aes.encrypt_and_digest(json_data)

    f.write(cipher_aes.nonce)
    f.write(tag)
    f.write(cipher_text)


def decrypt_data(f, code, name):
    private_key = RSA.import_key(
        open(DIR_KEYS + "/" + name + "/" + PRIVATE_RSA_KEY).read(),
        passphrase=code
    )

    enc_session_key, nonce, tag, cipher_text = [
        f.read(x) for x in (private_key.size_in_bytes(), 16, 16, -1)
    ]

    cipher_rsa = PKCS1_OAEP.new(private_key)
    session_key = cipher_rsa.decrypt(enc_session_key)

    cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
    data = cipher_aes.decrypt_and_verify(cipher_text, tag)

    json_data = json.loads(data)

    return json_data


if __name__ == '__main__':
    random.seed()

    if os.path.exists(NAME_DIR) is False:
        os.mkdir(NAME_DIR)
        
    if os.path.exists(DIR_KEYS) is False:
       os.mkdir(DIR_KEYS)
    mode = int(input("Выберите:\n1)Создать новую запсись\n2)Открыть существующую\n"))

    if mode == 1:
        while True:
            name_base = input('Введите имя записи: ') + ".bin"
            files = os.listdir(NAME_DIR)

            if name_base is files:
                print('Данное имя уже существует')
            else:
                break

        len_pas = int(input('Введите длину: '))
        login = input('Введите логин: ').strip()
        code = input('Введите код для расшифрования: ').strip()

        os.mkdir(DIR_KEYS + "/" + name_base[0:-4])

        key = RSA.generate(2048)
        encrypted_key = key.exportKey(
            passphrase=code,
            pkcs=8,
            protection="scryptAndAES128-CBC"
        )
        with open(DIR_KEYS + "/" + name_base[0:-4] + "/" + PRIVATE_RSA_KEY, 'wb') as f:
            f.write(encrypted_key)

        with open(DIR_KEYS + "/" + name_base[0:-4] + "/" + PUBLIC_RSA_KEY, 'wb') as f:
            f.write(key.public_key().exportKey())
            
        pas = get_rand_pass(len_pas)

        print("Ваш пароль: " + pas)

        with open(NAME_DIR + "/" + name_base, 'wb') as f:
            save_enc_data(pas, login, f, name_base[0:-4])
            
    elif mode == 2:
        while True:
            name_base = input('Введите имя записи: ') + ".bin"
            files = os.listdir(NAME_DIR)
            if name_base is files:
                print('Данная запись не существует')
            else:
                break
                
        code = input('Введите код для расшифрования: ').strip()
        
        with open(NAME_DIR + "/" + name_base, 'rb') as f:
            decrypted = decrypt_data(f, code, name_base[0:-4])
            print("Пароль: " + decrypted['password'])
            print("Логин: " + decrypted['login'])
