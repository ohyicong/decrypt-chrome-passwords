# Decrypt Chrome Passwords
A simple program to decrypt chrome password saved on your machine. <br>
This code has only been tested on windows, so it may not work on other OS.<br>
If you have an idea for improvement, do let me know!<br>

## OS support
1. Windows

## Dependencies (see requirements)
1. sqlite
2. pycryptodomex
3. pywin32
   
### You can find **Login Data** file that contains The Encrypted Passwords in
```
%USERPROFILE%\AppData\Local\Google\Chrome\User Data\Default
```

### You can find **Local State** file that contain The Encryption Keys in
```
%USERPROFILE%\AppData\Local\Google\Chrome\User Data
```

## Usage
```python
python decrypt_chrome_password.py [login data] [login state]
```
## Output
Saved as decrypted_password.csv



