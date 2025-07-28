import os
import hashlib
import yaml

# A02: Hardcoded credentials
USERNAME = "admin"
PASSWORD_HASH = hashlib.md5("password123".encode()).hexdigest()  # Weak hash

def login():
    user = input("Enter username: ")
    pwd = input("Enter password: ")
    if user == USERNAME and hashlib.md5(pwd.encode()).hexdigest() == PASSWORD_HASH:
        print("Login successful")
        return True
    else:
        print("Login failed")
        return False

# A03: Command Injection vulnerability
def search_file():
    filename = input("Enter filename to search: ")
    os.system("ls " + filename)  # vulnerable: no sanitization

# A08: Insecure deserialization using PyYAML
def load_config():
    yaml_data = input("Paste YAML config: ")
    config = yaml.load(yaml_data, Loader=yaml.Loader)  # CVE-2019-11324
    print("Loaded config:", config)

def main():
    if login():
        print("1. Search File\n2. Load Config")
        choice = input("Enter choice: ")
        if choice == "1":
            search_file()
        elif choice == "2":
            load_config()

if __name__ == "__main__":
    main()
