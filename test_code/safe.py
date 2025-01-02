# safe_file.py
import hashlib

def safe_function():
    # Perform a safe operation
    print("This is a safe function!")



def secure_hash():
    # Creating a secure hash with sha256 (not md5 or sha1)
    data = "This is a secure string"
    hashed_data = hashlib.sha256(data.encode()).hexdigest()
    print(f"Secure hash: {hashed_data}")

if __name__ == "__main__":
    safe_function()
    generate_random_number()
    secure_hash()
