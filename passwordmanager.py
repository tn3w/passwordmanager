import os
import re
LOGO = """ _____ _ _ _ ____     _____                         
|  _  | | | |    \   |     |___ ___ ___ ___ ___ ___ 
|   __| | | |  |  |  | | | | .'|   | .'| . | -_|  _|
|__|  |_____|____/   |_|_|_|__,|_|_|__,|_  |___|_|  
                                       |___|\n\n"""

while True:
    os.system('cls' if os.name == 'nt' else 'clear')
    print(LOGO)
    password_file = input("Path to the password file or Enter to create a new one: ")
    if password_file == "":
        while True:
            os.system('cls' if os.name == 'nt' else 'clear')
            print(LOGO)
            print("Path to the password file or Enter to create a new one: \n")
            password_file_name = input("What should the password file be called: ")
            if re.search(r'[^a-zA-Z]', password_file_name):
                print("[Error] File name can contain only letters.")
            else:
                if password_file_name == "":
                    password_file_name = "passwords"
                break
        i = 0
        password_file = os.path.join(os.getcwd(), password_file_name + ("" if i == 0 else str(i)) + ".pwd")
        while os.path.isfile(password_file):
            i += 1
            password_file = os.path.join(os.getcwd(), password_file_name + ("" if i == 0 else str(i)) + ".pwd")
        break
    elif os.path.isfile(password_file):
        break
    else:
        print(f"[Error] Given file '{password_file}' not found.")
