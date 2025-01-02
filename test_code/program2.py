import os
import sys
import subprocess
import pickle
import hashlib
import random
import logging

# Hardcoded password
config = {
    "password": "12345"  # This is a hardcoded password, should not be in code
}

# Dangerous eval usage
def dangerous_eval():
    user_input = input("Enter code to execute: ")
    eval(user_input)  # Dangerous use of eval()

# Insecure deserialization with pickle
def insecure_deserialization():
    data = b"cos\nsystem\n(S'echo hello'\ntR."
    obj = pickle.loads(data)  # Insecure deserialization
    obj()

# Weak hashing algorithm (md5)
def weak_hashing():
    password = "password123"
    hashed = hashlib.md5(password.encode()).hexdigest()  # Weak hashing (MD5)
    print(f"Hashed password: {hashed}")

# Command injection using os.system
def command_injection():
    command = input("Enter a command to execute: ")
    os.system(command)  # Command injection vulnerability

# SQL injection vulnerability (no parameterized queries)
def sql_injection():
    username = input("Enter your username: ")
    password = input("Enter your password: ")
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    print(f"Running query: {query}")
    # Code that executes the query (without sanitizing inputs), making it vulnerable to SQL injection

# Dangerous imports
def dangerous_imports():
    subprocess.call(["ls", "-l"])  # Dangerous subprocess call (not sanitized)

# Insecure random number generation
def insecure_random():
    random_value = random.randint(0, 100)
    print(f"Random number: {random_value}")

# Sensitive data logging (password logged)
def sensitive_logging():
    password = "supersecretpassword"
    logging.info(f"User's password: {password}")  # Logging sensitive information

# Main function to invoke vulnerabilities
def main():
    # Choose which vulnerability to trigger
    choice = input("Choose an option (1-7):\n1. Dangerous eval\n2. Insecure deserialization\n3. Weak hashing\n4. Command injection\n5. SQL injection\n6. Dangerous imports\n7. Insecure random\n8. Sensitive logging\nEnter number: ")
    
    if choice == "1":
        dangerous_eval()
    elif choice == "2":
        insecure_deserialization()
    elif choice == "3":
        weak_hashing()
    elif choice == "4":
        command_injection()
    elif choice == "5":
        sql_injection()
    elif choice == "6":
        dangerous_imports()
    elif choice == "7":
        insecure_random()
    elif choice == "8":
        sensitive_logging()
    else:
        print("Invalid choice.")

if __name__ == "__main__":
    main()
