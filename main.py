# importing packages and modules 
import streamlit as st
import hashlib
import json
import os
import time
from cryptography.fernet import Fernet
from base64 import urlsafe_b64encode
from hashlib import pbkdf2_hmac


DATA_FILE = "secure_data.json"
SALT = b"secure-salt_value"
LOCKOUT_DURATION = 60

if "uthenticated_user" not in st.session_state:
    st.session_state.uthenticated_user = None

if "failed_sttempts" not in st.session_state:
    st.session_state.failed_attempts = 0

if "lockout_time" not in st.session_state:
    st.session_state.lockout_time = 0  

def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            return json.load(f)
        return {}
    
def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f)

def generate_key(passkey):
     key = pbkdf2_hmac("sha256", passkey.encode(), SALT, 100000)
     return urlsafe_b64encode(key)

def hash_password(password):
    return hashlib.pbkdf2_hmac('sha256', password.encode(), SALT, 100000).hex()

# cyptography Farnet used

def encrypt_text(text, key):
    cipher = Fernet(generate_key(key))
    return cipher.encrypt(text.encode()).decode()

def decrypt_text(encrypt_text, key):
    try:
        cipher = Fernet(generate_key(key))
        return cipher.decrypt(encrypt_text.encode()).decode()
    except:
        return None
    
stored_data = load_data()


# navigation bar
st.title('🔐 Secure & Encrypt Data')
menu = ["Home", "Register", "Login", "Store Data", "Retrive Data"]
choice = st.sidebar.selectbox("Navigation", menu)

if choice == "Home":
    st.subheader("welcome to my 🔐 Secure & Encrypt Data System")
    st.markdown("This application takes data from user and encrypt the data to sucure the data")

elif choice == "Register":
    st.subheader("Register new user 👤 ")
    userName = st.text_input("Choose User Name")
    password = st.text_input("Choose Password", type="password")

    if st.button("Register"):
        if userName and password:
            if userName in stored_data:
                st.warning("⚠️ User Name already exists.")
            
            else:
                stored_data[userName] = {
                    "password": hash_password(password),
                    "data": []
                }
                save_data(stored_data)
                st.success("✅ User Registered Sucessfully !")

        else:
            st.error("Both Fields are required")

    elif choice == "Login":
        st.subheader("🗝️ User Login")

        if time.time() < st.session_state.lockout_time:
            remaining = int(st.session_state.lockout_time - time.time())
            st.error(f"Too many failed attempts . please wait {remaining} seconds.")
            st.stop()

        userName = st.text_input("Username")
        password = st.text_input("password", type="password")

        if st.button("Login"):
            if userName in stored_data and stored_data[userName]["password"] == hash_password(password):
                st.session_state.authenticated_user = userName
                st.session_state.failed_attempts = 0
                st.success(f"Welcome {userName} 😊")

            else:
                st.session_state.failed_attempts += 1
                remaining = 3 - st.session_state.failed_attempts
                st.error(f"❌ Invalid Credentials! Attempts remaining {remaining}")

                if st.session_state.failed_attempts >= 3:
                    st.session_state.lockout_time = time.time() + LOCKOUT_DURATION
                    st.error(f"Too many failed attempts. lock out time is 60 seconds")
                    st.stop()


elif choice == "Store Data":
    if not st.session_state.authenticated_user:
        st.warning("Please login first")

    else:
        st.subheader("Store Encrypted Data")
        data = st.text_area("Enter Data to Encrypt")
        passkey = st.text_input("Encryption key (passphrase)", key="password")

        if st.button("Encrypt and save"):
            if data and passkey:
                encrypted = encrypt_text(data, passkey)
                stored_data[st.session_state.authenticated_user]["data"].append(encrypted)
                save_data(stored_data)
                st.success("Data Encrypted sucessfully")

            else:
                st.error("All feiled are required")

elif choice == "Retrive Data":
    if not st.session_state.authenticated_user:
        st.warning("Please login first")
    else:
        st.subheader("🔎 Retrive Data")
        user_data = stored_data.get(st.session_state.authenticated_user, {}).get("data", [])

        if not user_data:
            st.info("No data found")
        else:
            st.write("Encrypted data Entries")
            for i, item in enumerate(user_data):
                st.code(item, language="text")

            encrypt_input = st.text_area("Enter Encryptd text")
            passkey = st.text_input("Enter Passkey to Decrypt", type="password")

            if st.button("Decrypt"):
                result = decrypt_text(encrypt_input, passkey)
                if result:
                    st.success(f"Decrypted : {result}")
                else:
                    st.error("Incorrect passkey")
