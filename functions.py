import re
from cryptography.fernet import Fernet

key = Fernet.generate_key()
cipher_suite = Fernet(key)

def encrypt_data(data):
    return cipher_suite.encrypt(data.encode()).decode()

def decrypt_data(data):
    return cipher_suite.decrypt(data.encode()).decode()


def not_valid_input(input_string):
    # Check if input contains any malicious characters
    if re.search(r'[<>]', input_string):
        return True
    return False

def is_valid_email(email):
    return re.match(r"[^@]+@[^@]+\.[^@]+", email)

def is_valid_password(password):
    return len(password) >= 8 and re.search(r"\d", password) and re.search(r"[A-Z]", password)

# Monitor and log suspicious activity
def log_suspicious_activity(activity_type, details, app):
    app.logger.warning(f"Suspicious activity detected: {activity_type} - {details}")
