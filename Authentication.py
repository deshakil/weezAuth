'''
from flask import Flask, request, jsonify
from azure.data.tables import TableServiceClient, TableEntity
from datetime import datetime, timezone
import os
import bcrypt

app = Flask(__name__)

# Set up Azure Table connection
connection_string = os.getenv("AZURE_STORAGE_CONNECTION_STRING")
table_service_client = TableServiceClient.from_connection_string(conn_str=connection_string)
table_name = "Authentication"  # Table name in Azure Table Storage
table_client = table_service_client.get_table_client(table_name)

# Ensure the table exists
try:
    table_client.create_table()
except Exception as e:
    print("Table already exists or could not be created:", e)

# Helper function to hash passwords
def hash_password(password):
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode('utf-8'), salt)

# Helper function to verify passwords
def verify_password(stored_password, provided_password):
    return bcrypt.checkpw(provided_password.encode('utf-8'), stored_password)

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    email = data['email']
    password = data['password']
    name = data.get('name')
    dob = data.get('dob')
    gender = data.get('gender')
    mobile_number = data.get('mobileNumber')
    
    # Check if user already exists
    try:
        existing_user = table_client.get_entity(partition_key="users", row_key=email)
        return jsonify({"message": "User already exists"}), 409
    except Exception:  # User not found exception, can proceed with registration
        pass

    # Hash password
    hashed_password = hash_password(password)
    
    # Prepare user entity with additional fields
    user_entity = {
        "PartitionKey": "users",
        "RowKey": email,
        "password": hashed_password.decode('utf-8'),  # Store as UTF-8 string
        "created_at": datetime.now(timezone.utc).isoformat(),
        "name": name,
        "dob": dob,
        "gender": gender,
        "mobile_number": mobile_number
    }
    
    # Insert user entity into the table
    table_client.create_entity(entity=user_entity)
    
    return jsonify({"message": "User registered successfully"}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data['email']
    password = data['password']
    
    try:
        # Retrieve the user entity from the table
        user_entity = table_client.get_entity(partition_key="users", row_key=email)
        stored_password = user_entity['password'].encode('utf-8')  # Decode to bytes for bcrypt check
        
        # Verify password
        if verify_password(stored_password, password):
            return jsonify({"message": "Login successful"}), 200
        else:
            return jsonify({"message": "Invalid credentials"}), 401
    except Exception:
        return jsonify({"message": "User not found"}), 404

if __name__ == '__main__':
    app.run(debug=True)
'''

from flask import Flask, request, jsonify
from azure.data.tables import TableServiceClient
from datetime import datetime, timezone
import os
import bcrypt
import random
import smtplib
from email.message import EmailMessage

from flask import Flask
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

app = Flask(__name__)

# Azure Table Storage connection
connection_string = os.getenv("AZURE_STORAGE_CONNECTION_STRING")
table_service_client = TableServiceClient.from_connection_string(conn_str=connection_string)
table_name = "Authentication"
table_client = table_service_client.get_table_client(table_name)

# Ensure the table exists
try:
    table_client.create_table()
except Exception as e:
    print("Table already exists or could not be created:", e)

# OTP storage
otp_store = {}

# Helper functions for hashing and verifying passwords
def hash_password(password):
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode('utf-8'), salt)

def verify_password(stored_password, provided_password):
    return bcrypt.checkpw(provided_password.encode('utf-8'), stored_password)

# Helper function to send OTP email
def send_otp_email(to_email, otp):
    email_sender = os.getenv("EMAIL_SENDER")
    email_password = os.getenv("EMAIL_PASSWORD")
    message = EmailMessage()
    message.set_content(f"Your OTP is: {otp}")
    message['Subject'] = 'Your OTP Code'
    message['From'] = email_sender
    message['To'] = to_email

    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
        server.login(email_sender, email_password)
        server.send_message(message)

# Registration endpoint
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    name = data.get('name')
    gender = data.get('gender')
    dob = data.get('dob')
    mobile_number = data.get('mobileNumber')

    # Check if user already exists
    try:
        table_client.get_entity(partition_key="users", row_key=email)
        return jsonify({"message": "User already exists"}), 409
    except Exception:
        pass

    # Hash the password
    hashed_password = hash_password(password)

    # Prepare user data to store in Azure Table Storage
    user_entity = {
        "PartitionKey": "users",
        "RowKey": email,
        "password": hashed_password.decode('utf-8'),
        "name": name,
        "gender": gender,
        "dob": dob,
        "mobileNumber": mobile_number,
        "created_at": datetime.now(timezone.utc).isoformat()
    }

    # Insert user data into Azure Table Storage
    table_client.create_entity(entity=user_entity)
    return jsonify({"message": "User registered successfully"}), 201

# Login endpoint with OTP
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    # Fetch user details from Azure Table Storage
    try:
        user_entity = table_client.get_entity(partition_key="users", row_key=email)
        stored_password = user_entity["password"].encode('utf-8')

        # Verify password
        if verify_password(stored_password, password):
            # Generate and send OTP
            otp = random.randint(100000, 999999)
            otp_store[email] = otp
            send_otp_email(email, otp)
            return jsonify({"message": "OTP sent to email"}), 200
        else:
            return jsonify({"message": "Invalid credentials"}), 401
    except Exception:
        return jsonify({"message": "User not found"}), 404

# OTP verification endpoint
@app.route('/verify-otp', methods=['POST'])
def verify_otp():
    data = request.get_json()
    email = data.get('email')
    otp = data.get('otp')

    # Verify OTP
    if otp_store.get(email) == otp:
        del otp_store[email]
        return jsonify({"message": "OTP verified successfully"}), 200
    else:
        return jsonify({"message": "Invalid OTP"}), 400

if __name__ == '__main__':
    app.run(debug=True)
