!pip install streamlit pyngrok pyjwt
%%writefile app.py

%%writefile app.py
import streamlit as st
import sqlite3
import re
import hashlib

st.set_page_config(page_title="Milestone 1", layout="centered")

DB_NAME = "users.db"

# ======================
# DATABASE FUNCTIONS
# ======================

def create_table():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            security_question TEXT NOT NULL,
            security_answer TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def add_user(username, email, password, question, answer):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute(
        "INSERT INTO users (username, email, password, security_question, security_answer) VALUES (?, ?, ?, ?, ?)",
        (username, email.lower(), hash_password(password), question, answer.lower())
    )
    conn.commit()
    conn.close()

def get_user_by_email(email):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE LOWER(email)=?", (email.lower(),))
    user = c.fetchone()
    conn.close()
    return user

def update_password(email, new_password):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("UPDATE users SET password=? WHERE LOWER(email)=?",
              (hash_password(new_password), email.lower()))
    conn.commit()
    conn.close()

create_table()

# ======================
# VALIDATION FUNCTIONS
# ======================

def validate_username(username):
    pattern = r'^[a-zA-Z0-9_]{3,}$'
    return re.match(pattern, username)

def validate_email(email):
    pattern = r'^[\w\.-]+@[\w\.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email)

def validate_password(password):
    if " " in password:
        return False
    if not password.isalnum():
        return False
    if len(password) < 8 or len(password) > 10:
        return False
    return True

def validate_security_answer(answer):
    return len(answer) >= 3 and " " not in answer

# ======================
# SESSION INIT
# ======================

if "page" not in st.session_state:
    st.session_state.page = "login"

if "login_attempts" not in st.session_state:
    st.session_state.login_attempts = 0

# ======================
# LOGIN PAGE
# ======================

if st.session_state.page == "login":

    st.title("Milestone 1 - Login")

    email = st.text_input("Email", key="login_email")
    password = st.text_input("Password", type="password", key="login_password")

    if st.button("Sign In"):

        if not email or not password:
            st.error("All fields required")

        elif not validate_email(email):
            st.error("Invalid Email")

        else:
            user = get_user_by_email(email)

            if user and user[3] == hash_password(password):
                st.session_state.username = user[1]
                st.session_state.page = "dashboard"
                st.session_state.login_attempts = 0

                st.session_state.pop("login_email", None)
                st.session_state.pop("login_password", None)

                st.rerun()
            else:
                st.session_state.login_attempts += 1
                st.error(f"Invalid Credentials ({st.session_state.login_attempts}/3)")

    col1, col2 = st.columns(2)

    with col1:
        if st.button("Create Account"):
            st.session_state.page = "signup"
            st.rerun()

    with col2:
        if st.button("Forgot Password"):
            st.session_state.page = "forgot"
            st.rerun()

# ======================
# SIGNUP PAGE
# ======================

elif st.session_state.page == "signup":

    st.title("Create Account")

    username = st.text_input("Username", key="su_user")
    email = st.text_input("Email", key="su_email")
    password = st.text_input("Password", type="password", key="su_pass")
    confirm = st.text_input("Confirm Password", type="password", key="su_confirm")

    question = st.selectbox("Security Question",
        ["What is your pet name?",
         "What is your mother’s maiden name?",
         "What is your favorite teacher?"]
    )

    answer = st.text_input("Security Answer", key="su_answer")

    if st.button("Register"):

        if not all([username, email, password, confirm, answer]):
            st.error("All fields required")

        elif not validate_username(username):
            st.error("Username must be at least 3 characters and contain only letters, numbers, underscore (no spaces)")

        elif not validate_email(email):
            st.error("Invalid Email")

        elif not validate_password(password):
            st.error("Password must be 8-10 characters, alphanumeric, no spaces")

        elif password != confirm:
            st.error("Passwords do not match")

        elif not validate_security_answer(answer):
            st.error("Invalid Security Answer")

        else:
            try:
                add_user(username, email, password, question, answer)
                st.success("Account Created Successfully")

                for key in ["su_user","su_email","su_pass","su_confirm","su_answer"]:
                    st.session_state.pop(key, None)

            except:
                st.error("Username or Email already exists")

    if st.button("Back to Login"):
        st.session_state.page = "login"
        st.rerun()

# ======================
# FORGOT PASSWORD
# ======================

elif st.session_state.page == "forgot":

    st.title("Reset Password")

    email = st.text_input("Enter Email", key="fp_email")

    if st.button("Verify"):
        user = get_user_by_email(email)
        if user:
            st.session_state.reset_email = email
            st.session_state.question = user[4]
        else:
            st.error("Email not found")

    if "question" in st.session_state:
        st.write("Security Question:", st.session_state.question)
        answer = st.text_input("Answer", key="fp_answer")

        if st.button("Submit"):
            user = get_user_by_email(st.session_state.reset_email)
            if answer.lower() == user[5]:
                st.session_state.allow_reset = True
            else:
                st.error("Incorrect Answer")

    if "allow_reset" in st.session_state:
        new_pass = st.text_input("New Password", type="password", key="fp_new")

        if st.button("Update Password"):

            if not validate_password(new_pass):
                st.error("Invalid Password Format")

            else:
                update_password(st.session_state.reset_email, new_pass)
                st.success("Password Updated")

                st.session_state.clear()
                st.session_state.page = "login"
                st.rerun()

    if st.button("Back to Login"):
        st.session_state.page = "login"
        st.rerun()

# ======================
# DASHBOARD
# ======================

elif st.session_state.page == "dashboard":

    st.title("Dashboard")
    st.success(f"Welcome {st.session_state.username}")

    if st.button("Logout"):
        st.session_state.clear()
        st.session_state.page = "login"
        st.rerun()

!pip install pyngrok
from pyngrok import ngrok
import subprocess
import time

# Stop any previous tunnels
ngrok.kill()

NGROK_AUTH_TOKEN = "Token"
ngrok.set_auth_token(NGROK_AUTH_TOKEN)

# Start streamlit
process = subprocess.Popen(["streamlit", "run", "app.py"])

time.sleep(5)

# Create ONE tunnel only
public_url = ngrok.connect(8501)

print("🚀 App Running At:")
print(public_url)
