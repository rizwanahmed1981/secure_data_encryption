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