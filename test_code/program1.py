import os
import subprocess
import hashlib
import pickle
import random

# Hardcoded credentials
username = "admin"
password = "123456"

# Insecure use of eval
user_input = input("Enter a command to evaluate: ")
result = eval(user_input)

# Command injection
os.system("ls; rm -rf /")

# Insecure deserialization
data = pickle.loads(b"cos\nsystem\n(S'rm -rf /'\ntR.")

# Weak hashing
hashed_value = hashlib.md5(b"password").hexdigest()

# Insecure random number generation
otp = random.randint(100000, 999999)

# HTTP instead of HTTPS
url = "http://example.com/api"
response = subprocess.run(["curl", url], capture_output=True)

print("Potentially insecure operations completed.")
