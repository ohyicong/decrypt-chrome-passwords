# Full Credits to LimerBoy
import os
import re
import sys
import json
import base64
import sqlite3
from Cryptodome.Cipher import AES
import shutil
import csv

# HOW TO RUN
# python script.py LocalState LoginData
# Configuration
CHROME_PATH_LOCAL_STATE = None
CHROME_PATH_LOGIN_DATA = None

def get_secret_key(local_state_path):
    try:
        # (1) Get secret key from Chrome local state
        with open(local_state_path, "r", encoding='utf-8') as f:
            local_state = f.read()
            local_state = json.loads(local_state)
        secret_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
        # Remove suffix DPAPI
        secret_key = secret_key[5:]
        return secret_key
    except Exception as e:
        print("%s" % str(e))
        print("[ERR] Chrome secret key cannot be found")
        return None

def decrypt_payload(cipher, payload):
    return cipher.decrypt(payload)

def generate_cipher(aes_key, iv):
    return AES.new(aes_key, AES.MODE_GCM, iv)

def decrypt_password(ciphertext, secret_key):
    try:
        # (3-a) Initialization vector for AES decryption
        initialisation_vector = ciphertext[3:15]
        # (3-b) Get encrypted password by removing suffix bytes (last 16 bits)
        # Encrypted password is 192 bits
        encrypted_password = ciphertext[15:-16]
        # (4) Build the cipher to decrypt the ciphertext
        cipher = generate_cipher(secret_key, initialisation_vector)
        decrypted_pass = decrypt_payload(cipher, encrypted_password)
        decrypted_pass = decrypted_pass.decode()
        return decrypted_pass
    except Exception as e:
        print("%s" % str(e))
        print("[ERR] Unable to decrypt, Chrome version <80 not supported. Please check.")
        return ""

def get_db_connection(chrome_path_login_db):
    try:
        shutil.copy2(chrome_path_login_db, "Loginvault.db")
        return sqlite3.connect("Loginvault.db")
    except Exception as e:
        print("%s" % str(e))
        print("[ERR] Chrome database cannot be found")
        return None

if __name__ == '__main__':
    try:
        if len(sys.argv) < 3:
            print("Usage: python script.py <Local_State_Path> <Login_Data_Path>")
            sys.exit(1)

        CHROME_PATH_LOCAL_STATE = sys.argv[1]
        CHROME_PATH_LOGIN_DATA = sys.argv[2]

        # Create Dataframe to store passwords
        with open('decrypted_password.csv', mode='w', newline='', encoding='utf-8') as decrypt_password_file:
            csv_writer = csv.writer(decrypt_password_file, delimiter=',')
            csv_writer.writerow(["index", "url", "username", "password"])

            # (1) Get secret key
            secret_key = get_secret_key(CHROME_PATH_LOCAL_STATE)

            if secret_key:
                conn = get_db_connection(CHROME_PATH_LOGIN_DATA)
                if conn:
                    cursor = conn.cursor()
                    cursor.execute("SELECT action_url, username_value, password_value FROM logins")
                    for index, login in enumerate(cursor.fetchall()):
                        url = login[0]
                        username = login[1]
                        ciphertext = login[2]
                        if url != "" and username != "" and ciphertext != "":
                            # (3) Filter the initialization vector & encrypted password from ciphertext
                            # (4) Use AES algorithm to decrypt the password
                            decrypted_password = decrypt_password(ciphertext, secret_key)
                            print("Sequence: %d" % index)
                            print("URL: %s\nUser Name: %s\nPassword: %s\n" % (url, username, decrypted_password))
                            print("*" * 50)
                            # (5) Save into CSV
                            csv_writer.writerow([index, url, username, decrypted_password])
                    # Close database connection
                    cursor.close()
                    conn.close()
                    # Delete temp login db
                    os.remove("Loginvault.db")
    except Exception as e:
        print("[ERR] %s" % str(e))
