import argparse
import base64
import hashlib
import random
import string
import pyperclip
import json
from cryptography.fernet import Fernet

# Create ArgumentParser object
parser = argparse.ArgumentParser(description='Python command line password manager')

# Add arguments

parser.add_argument('-n', '--new', action='store_true', help='Create a new random password')
parser.add_argument('-s', '--store', action='store_true', help='Store password in the encrypted database') 
parser.add_argument('-f', '--find', action='store_true', help='Find password from the encrypted database') 

# Parse the command-line arguments
args = parser.parse_args()

master = input('Enter master password: ')
special_chars = ['!', '$', '&', '(', ')', '*', '+', '-', '/', '<', '=', '>', '?', '@', '[', ']', '^', '_', '`', '|', '~']

def generateRandomPassword(pswd_length):
    return ''.join(random.choices(string.ascii_letters+"".join(special_chars) + string.digits, k=pswd_length))

def encrypt_data(data, key):
    #Encrypt data using the provided key.
    f = Fernet(key)
    return f.encrypt(data.encode()).decode()

def decrypt_data(data, key):
    #Decrypt data using the provided key.
    f = Fernet(key)
    return f.decrypt(data.encode()).decode()

def generate_key(master):
    # Generate a Fernet key using the provided master key.
    # symmetric cipher
    # Convert the master key to bytes
    master_bytes = master.encode()
    
    # Use SHA-256 hash of the master key as the key for Fernet
    hashed_key = hashlib.sha256(master_bytes).digest()
    
    # Fernet keys are required to be 32 url-safe base64-encoded bytes
    return base64.urlsafe_b64encode(hashed_key)


def store_password(username, password,application,master):
            # Example data to write to the JSON file
        # Encrypt the data
    
    key = generate_key(master)

    encrypted_username = encrypt_data(username, key)
    encrypted_password = encrypt_data(password, key)
    encrypted_application = encrypt_data(application, key)

    # Example data to write to the JSON file
    data_to_write = {
        "application": encrypted_application,
        "username": encrypted_username,
        "password": encrypted_password
    }

    # File path
    file_path = "/Users/aatmaj/IS_IA1/passwords.json"

    
    
    # Writing data to the JSON file
    with open(file_path, "a") as json_file:
        json_file.write(json.dumps(data_to_write) + '\n')



def find_data(application,master):
    file_path = "./passwords.json"
    with open(file_path, "r") as string_file:
        data = string_file.readlines()

    key = generate_key(master)

    for line in data:
        entry = json.loads(line)
        if application == decrypt_data(entry["application"],key) :
            # Decrypt the username and password using the master key
            decrypted_username = decrypt_data(entry["username"], key)
            decrypted_password = decrypt_data(entry["password"], key)
            return decrypted_username, decrypted_password

    return None, None

if(args.new):
    
    application = input("Enter the application where you want to store the password: ")
    username = input("Enter your username: ")
    #generate a random password and send to user
    retry_flag = 'N'
    while retry_flag in ('n', 'N'):
        try:
            password_length = int(input("Enter the length of the password: "))
        except Exception as e:
            print("Invalid input")
            continue
        new_password = generateRandomPassword(password_length)
        print(f"New password generated & copied to clipboard -> {new_password}.")
        pyperclip.copy(new_password)
        retry_flag=input(" Should we store it? Press 'n' for retry. (Y/n) ")
    
    store_password(username,new_password,application,master)
    
    
elif(args.store):  
    application = input("Enter the application for which you want to store the password: ")
    username = input("Enter your username: ")

    password = input("Enter the password: ")
    retry_flag = 'N'
    while retry_flag in ('n', 'N'):
        retry_flag=input(f"Confirm password -> {password} \n Press 'n' for retry. (Y/n)")
    #store the password
    store_password(username,password,application,master)
    print("Password stored into database")

elif(args.find):
    application = input("Enter the application for which you want to find the password: ")

    username,password = find_data(application,master)
    if username is None or password is None:
        print(f"Application not found.")
        
    else:
        print(f"Username: {username} \n Password: {password} \nPassword copied to clipboard")
        pyperclip.copy(password)


