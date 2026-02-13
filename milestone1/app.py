!pip install streamlit pyngrok pyjwt
%%writefile app.py

import streamlit as st
import sqlite3
import re

st.set_page_config(page_title="Milestone 1", layout="centered")

DB_NAME = "users.db"

# ======================
# DATABASE
# ======================

def create_table():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            security_question TEXT NOT NULL,
            security_answer TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()

def add_user(username, email, password, question, answer):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("INSERT INTO users (username, email, password, security_question, security_answer) VALUES (?, ?, ?, ?, ?)",
              (username, email, password, question, answer))
    conn.commit()
    conn.close()

def get_user(email):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE email = ?", (email,))
    user = c.fetchone()
    conn.close()
    return user

def update_password(email, new_password):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("UPDATE users SET password = ? WHERE email = ?", (new_password, email))
    conn.commit()
    conn.close()

# ======================
# VALIDATION
# ======================

def validate_email(email):
    pattern = r'^[\w\.-]+@[\w\.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email)

def validate_password(password):
    if not password.isalnum():
        return False
    if len(password) < 8 or len(password) > 10:
        return False
    return True

create_table()

# ======================
# SESSION STATE CONTROL
# ======================

if "page" not in st.session_state:
    st.session_state.page = "login"

# ======================
# LOGIN PAGE
# ======================

if st.session_state.page == "login":

    st.title("Milestone 1")
    st.subheader("Please sign in to continue")

    email = st.text_input("Email Address")
    password = st.text_input("Password", type="password")

    if st.button("Sign In"):
        user = get_user(email)
        if user and user[3] == password:
            st.session_state.username = user[1]
            st.session_state.page = "dashboard"
            st.rerun()
        else:
            st.error("Invalid Email or Password")

    st.markdown("---")

    col1, col2 = st.columns(2)

    with col1:
        if st.button("Forgot Password?"):
            st.session_state.page = "forgot"
            st.rerun()

    with col2:
        if st.button("Create an Account"):
            st.session_state.page = "signup"
            st.rerun()

# ======================
# SIGNUP PAGE
# ======================

elif st.session_state.page == "signup":

    st.title("Create Account")

    username = st.text_input("Username")
    email = st.text_input("Email ID")
    password = st.text_input("Password", type="password")
    confirm_password = st.text_input("Confirm Password", type="password")

    security_question = st.selectbox(
        "Security Question",
        ["What is your pet name?",
         "What is your mother’s maiden name?",
         "What is your favorite teacher?"]
    )

    security_answer = st.text_input("Security Answer")

    if st.button("Register"):
        if not all([username, email, password, confirm_password, security_answer]):
            st.error("All fields are mandatory!")

        elif not validate_email(email):
            st.error("Invalid Email Format!")

        elif not validate_password(password):
            st.error("Password must be alphanumeric and 8–10 characters long.")

        elif password != confirm_password:
            st.error("Passwords do not match!")

        else:
            try:
                add_user(username, email, password, security_question, security_answer)
                st.success("Account Created Successfully!")
            except:
                st.error("Email already registered!")

    if st.button("Back to Login"):
        st.session_state.page = "login"
        st.rerun()

# ======================
# FORGOT PASSWORD
# ======================

elif st.session_state.page == "forgot":

    st.title("Forgot Password")

    email = st.text_input("Enter your Email")

    if st.button("Verify Email"):
        user = get_user(email)

        if user:
            st.session_state.reset_email = email
            st.session_state.security_question = user[4]
        else:
            st.error("Email not found!")

    if "security_question" in st.session_state:
        st.write("Security Question:", st.session_state.security_question)
        answer = st.text_input("Your Answer")

        if st.button("Submit Answer"):
            user = get_user(st.session_state.reset_email)

            if answer == user[5]:
                new_password = st.text_input("New Password", type="password")

                if st.button("Update Password"):
                    if validate_password(new_password):
                        update_password(st.session_state.reset_email, new_password)
                        st.success("Password Updated Successfully!")
                        st.session_state.clear()
                        st.session_state.page = "login"
                        st.rerun()
                    else:
                        st.error("Password must be alphanumeric and 8–10 characters long.")
            else:
                st.error("Incorrect Security Answer!")

    if st.button("Back to Login"):
        st.session_state.page = "login"
        st.rerun()

# ======================
# DASHBOARD
# ======================

elif st.session_state.page == "dashboard":

    st.title("Dashboard")
    st.success(f"Welcome, {st.session_state.username}!")

    if st.button("Logout"):
        st.session_state.clear()
        st.session_state.page = "login"
        st.rerun()

from pyngrok import ngrok
import subprocess
import time

# 🔴 Replace with your NEW ngrok token
NGROK_AUTH_TOKEN = "Token"

ngrok.kill()
ngrok.set_auth_token(NGROK_AUTH_TOKEN)

process = subprocess.Popen(["streamlit", "run", "app.py"])

time.sleep(5)

public_url = ngrok.connect(8501)
print("🚀 App Running At:")
print(public_url)


