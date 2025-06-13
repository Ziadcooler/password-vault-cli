import base64
import hashlib
import os
import json
from cryptography.fernet import Fernet

MASTER_FILE = "master.hash"
VAULT_FILE = "vault.dat"

# Enter master password or set a new one if not already set

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Check if password exists
if not os.path.exists(MASTER_FILE):
    print("No master password found.")
    pw1 = input("Set a new master password.")
    pw2 = input("Confirm password.")

    if pw1 != pw2:
        print("Passwords do not match. Try again.")
        exit()

    with open(MASTER_FILE, "w") as f:
        f.write(hash_password(pw1))
    print("Master password set!")
    
    pw = pw1
else:

    pw = input("Please enter your master password.")
    
    with open(MASTER_FILE, "r") as f:
        saved_hash = f.read()
    
    if hash_password(pw) == saved_hash:
        print("Access granted!")
    else:
        print("Access denied. Try again.")
        exit()

salt = b'static_salt_123456'

# Convert into a key
key = hashlib.pbkdf2_hmac('sha256', pw.encode(), salt, 100000)
key = base64.urlsafe_b64encode(key)

# Create key, unlock/lock tool
fernet = Fernet(key)

def save_entries(entries, fernet):
    # Convert list to JSON then encrypt then save 
    data = json.dumps(entries).encode()
    encrypted = fernet.encrypt(data)
    with open(VAULT_FILE, "wb") as f:
        f.write(encrypted)

def load_entries(fernet):
    if not os.path.exists(VAULT_FILE):
        return []
    with open(VAULT_FILE, "rb") as f:
        encrypted = f.read()
    try:
        decrypted = fernet.decrypt(encrypted).decode()
        return json.loads(decrypted)
    except:
        print("Failed to access vault.")
        return []

def show_menu():
    print("\n==Password Vault==")
    print("1: Show all Saved Entries")
    print("2. Write New Entries")
    print("3. Exit")
    return input("Choose an option: ")

entries = load_entries(fernet)

while True:
    choice = show_menu()

    if choice == "1":
        print("\nStored Entries")
        for entry in entries:
            print(f"{entry['site']}: {entry['username']} / {entry['password']}")
    elif choice == "2":
        site = input("Site name: ")
        username = input("Username: ")
        password = input("Password: ")
        entries.append({
            "site": site,
            "username": username,
            "password": password
        }) 
        save_entries(entries, fernet)
        print("Entry saved!")
    elif choice == "3":
        print("Goodbye!")
        break
    else:
        print("Invalid option.")