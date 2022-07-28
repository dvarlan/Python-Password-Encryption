import base64

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import getpass

# Set the salt for the encryption
salzstreuer = b'\xd5\xbd\xd7E\xc0R\xba3\xb0|\xcb\xf1\xd9\x9a\x07=\x81;1\xc1\xb3M\xdeN[k\xef|\x88A\xf5\xc5'


# The "encrypt" and "decrypt" functions are inspired by this tutorial:
# https://www.geeksforgeeks.org/encrypt-and-decrypt-files-using-python/

def decrypt(user_key):
    """
    Uses the user generated "user_key" to decrypt the "vault.txt" file and prints the file content

    Parameter(s):
        user_key (Bytes): The key generated from the user input / password
    """
    fernet = Fernet(user_key)

    with open("vault.txt", "rb") as enc_file:
        encrypted = enc_file.read()

    decrypted = fernet.decrypt(encrypted)

    with open("vault.txt", "wb") as dec_file:
        dec_file.write(decrypted)

    print("Decrypted file content: ")
    print_file("vault.txt")


def encrypt(user_key):
    """
    Uses the user generated "user_key" to encrypt the "vault.txt" file and prints the file content

    Parameter(s):
        user_key (Bytes): The key generated from the user input / password
    """
    fernet = Fernet(user_key)

    with open("vault.txt", "rb") as file:
        original = file.read()

    encrypted = fernet.encrypt(original)

    with open("vault.txt", "wb") as encrypted_file:
        encrypted_file.write(encrypted)

    print("Encrypted file content: ")
    print_file("vault.txt")


def create_key():
    """
    Asks the user for an encryption password.
    Creates the key (from the password) and the "userkey.key" file in which the key is stored.

    Return values:
        key (Bytes): The key generated from the user input / password
    """
    password = getpass.getpass(prompt="Enter your Password: ")
    print("You entered: ", password)
    password = password.encode()

    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),
                     length=32,
                     salt=salzstreuer,
                     iterations=480000,
                     backend=default_backend())

    key = base64.urlsafe_b64encode(kdf.derive(password))
    with open("userkey.key", "w") as user_key_hash:
        user_key_hash.write(str(key))

    return key


def check_key(user_key):
    """
    Asks the user to repeat his password and generates a key from that new password.
    Checks if the key generated from the new password matches the one from the first password (user_key)
    If the keys are the same calls "decrypt()"

    Parameter(s):
        user_key (Bytes): The key generated from the first user input / password
    """
    password = getpass.getpass(prompt="Enter your Password to unlock the vault: ")
    password = password.encode()

    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),
                     length=32,
                     salt=salzstreuer,
                     iterations=480000,
                     backend=default_backend())
    key = base64.urlsafe_b64encode(kdf.derive(password))

    if key == user_key:
        print("Correct password")
        decrypt(user_key)
    else:
        print("Wrong password")


def print_file(file):
    """
    Prints the content of a .txt file line for line

    Parameter(s):
        file (String): The path to the file you want to print
    """
    input_file = open(file, "r")
    read = input_file.readlines()

    print("----------")

    for line in read:
        print(line)

    print("----------")


def main():
    """
    1. Shows you the original unencrypted content of "vault.txt"
    2. Calls "create_key" to create an encryption key from the password the user entered ("userkey.key" file is created)
    3. Calls "encrypt" with the key from "create_key" to encrypt the "vault.txt" file (prints encrypted file content)
    4. Calls "check_key" with the key from "create_key"
       -> Decrypts & prints the file if the user enters the correct password
    """
    print("Original file content: ")
    print_file("vault.txt")
    user_key = create_key()
    encrypt(user_key)
    check_key(user_key)


if __name__ == '__main__':
    main()
