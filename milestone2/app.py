!pip install streamlit pyjwt bcrypt python-dotenv pyngrok nltk streamlit-option-menu plotly textstat PyPDF2 -q



%%writefile app.py
import streamlit as st
import sqlite3
import re
import hashlib
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import secrets
import time
import hmac
import struct
import jwt
import bcrypt
import datetime
import os
import textstat
import string
import pandas as pd
from streamlit_option_menu import option_menu
import plotly.graph_objects as go
import PyPDF2
import uuid

# ======================
# CONFIGURATION & THEME
# ======================
st.set_page_config(page_title="Infosys LLM Secure Auth", page_icon="🌌", layout="wide")

DB_NAME = "users.db"
SECRET_KEY = os.getenv("JWT_SECRET", "super-secret-key-change-this")
EMAIL_ADDRESS = "sasdfghj771@gmail.com"  
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD") 
OTP_EXPIRY_MINUTES = 10

ADMIN_EMAIL = "sasdfghj771@gmail.com"
ADMIN_PASSWORD = "Bhavi@123"

def apply_galaxy_theme():
    st.markdown("""
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@300;400;500;600;700&display=swap');
        
        /* Main Background (Deep Space Gradient) */
        .stApp { 
            background: linear-gradient(135deg, #0b0914 0%, #161224 50%, #0d0a18 100%);
            color: #E2E8F0; 
            font-family: 'Space Grotesk', sans-serif;
        }
        
        h1, h2, h3, h4 { 
            color: #E9D5FF !important; 
            font-family: 'Space Grotesk', sans-serif; 
            font-weight: 700;
            text-shadow: 0 0 15px rgba(216, 180, 254, 0.4);
        }
        p, span, div {
            font-family: 'Space Grotesk', sans-serif;
        }
        
        /* Buttons - Nebula Glow */
        .stButton > button { 
            background: linear-gradient(45deg, #8B5CF6 0%, #EC4899 100%);
            color: #FFFFFF; 
            border: none; 
            border-radius: 30px; 
            font-weight: 600; 
            transition: all 0.3s ease; 
            width: 100%; 
            padding: 0.6rem 1rem;
            box-shadow: 0 0 15px rgba(236, 72, 153, 0.3);
        }
        .stButton > button:hover { 
            background: linear-gradient(45deg, #7C3AED 0%, #DB2777 100%);
            box-shadow: 0 0 25px rgba(236, 72, 153, 0.6);
            transform: translateY(-2px);
            color: #FFFFFF;
        }
        .stButton > button:active {
            transform: translateY(0px);
        }
        
        /* Input Fields - Glassmorphism */
        .stTextInput > div > div > input { 
            background: rgba(255, 255, 255, 0.03);
            backdrop-filter: blur(10px);
            color: #FFFFFF; 
            border: 1px solid rgba(255, 255, 255, 0.1); 
            border-radius: 10px; 
        }
        .stTextInput > div > div > input:focus { 
            border-color: #06B6D4; 
            box-shadow: 0 0 10px rgba(6, 182, 212, 0.5); 
        }
        .stTextArea > div > div > textarea { 
            background: rgba(255, 255, 255, 0.03);
            backdrop-filter: blur(10px);
            color: #FFFFFF; 
            border: 1px solid rgba(255, 255, 255, 0.1); 
            border-radius: 10px; 
        }
        .stTextArea > div > div > textarea:focus { 
            border-color: #06B6D4; 
            box-shadow: 0 0 10px rgba(6, 182, 212, 0.5); 
        }
        
        /* Sidebar - Dark Void */
        section[data-testid="stSidebar"] { 
            background-color: rgba(5, 3, 10, 0.8); 
            backdrop-filter: blur(15px);
            border-right: 1px solid rgba(255, 255, 255, 0.05);
        }
        
        /* Tabs */
        .stTabs [data-baseweb="tab-list"] { 
            gap: 24px; 
            border-bottom: 1px solid rgba(255, 255, 255, 0.1);
        }
        .stTabs [data-baseweb="tab"] { 
            background-color: transparent; 
            color: #94A3B8; 
            padding: 12px 4px;
            border-bottom: 2px solid transparent;
            font-weight: 500;
        }
        .stTabs [aria-selected="true"] { 
            background-color: transparent !important; 
            color: #06B6D4 !important; 
            border-bottom: 2px solid #06B6D4;
            text-shadow: 0 0 10px rgba(6, 182, 212, 0.5);
        }
        
        /* Expander (History Items) */
        .streamlit-expanderHeader { 
            background: rgba(255, 255, 255, 0.03);
            color: #E2E8F0; 
            border-radius: 10px;
            border: 1px solid rgba(255, 255, 255, 0.1);
            font-weight: 500;
        }
        
        /* Chat Messages */
        .stChatMessage { 
            background: rgba(139, 92, 246, 0.05); 
            border: 1px solid rgba(139, 92, 246, 0.2); 
            border-radius: 15px; 
            padding: 1.5rem;
            box-shadow: inset 0 0 20px rgba(0,0,0,0.2);
            margin-bottom: 10px;
        }
        
        /* Highlight Metrics */
        [data-testid="stMetricValue"] { 
            color: #06B6D4; 
            text-shadow: 0 0 10px rgba(6, 182, 212, 0.4);
            font-weight: 700;
        }
        [data-testid="stMetricLabel"] {
            color: #94A3B8;
            font-weight: 500;
        }
        
        hr {
            border-color: rgba(255, 255, 255, 0.1);
            margin: 2rem 0;
        }
    </style>
    """, unsafe_allow_html=True)

apply_galaxy_theme()

# ======================
# DATABASE SCHEMA & FUNCTIONS
# ======================
def create_table():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, email TEXT UNIQUE NOT NULL, password TEXT NOT NULL, security_question TEXT NOT NULL, security_answer TEXT NOT NULL)""")
    c.execute("""CREATE TABLE IF NOT EXISTS chat_threads (thread_id TEXT PRIMARY KEY, username TEXT NOT NULL, title TEXT NOT NULL, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)""")
    c.execute("""CREATE TABLE IF NOT EXISTS chat_messages (id INTEGER PRIMARY KEY AUTOINCREMENT, thread_id TEXT NOT NULL, username TEXT NOT NULL, role TEXT NOT NULL, content TEXT NOT NULL, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)""")
    c.execute("""CREATE TABLE IF NOT EXISTS readability_records (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL, title TEXT NOT NULL, full_text TEXT NOT NULL, grade_level REAL NOT NULL, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)""")
    conn.commit()
    conn.close()

# --- USER AUTH FUNCTIONS ---
def hash_password(password): return hashlib.sha256(password.encode()).hexdigest()

def add_user(username, email, password, question, answer):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    try:
        c.execute("INSERT INTO users (username, email, password, security_question, security_answer) VALUES (?, ?, ?, ?, ?)", (username, email.lower(), hash_password(password), question, answer.lower()))
        conn.commit(); return True
    except sqlite3.IntegrityError: return False
    finally: conn.close()

def get_user_by_email(email):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE LOWER(email)=?", (email.lower(),))
    user = c.fetchone(); conn.close()
    return user

def update_password(email, new_password):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("UPDATE users SET password=? WHERE LOWER(email)=?", (hash_password(new_password), email.lower()))
    conn.commit(); conn.close()

def get_all_users():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("SELECT id, username, email FROM users")
    users = c.fetchall(); conn.close()
    return users

def delete_user_by_id(user_id):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("DELETE FROM users WHERE id=?", (user_id,))
    conn.commit(); conn.close()

# --- CHAT HISTORY FUNCTIONS ---
def create_chat_thread(username, title):
    thread_id = str(uuid.uuid4())
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("INSERT INTO chat_threads (thread_id, username, title) VALUES (?, ?, ?)", (thread_id, username, title))
    conn.commit(); conn.close()
    return thread_id

def get_chat_threads(username):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("SELECT thread_id, title, timestamp FROM chat_threads WHERE username=? ORDER BY timestamp DESC", (username,))
    data = c.fetchall(); conn.close()
    return data

def delete_chat_thread(thread_id):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("DELETE FROM chat_messages WHERE thread_id=?", (thread_id,))
    c.execute("DELETE FROM chat_threads WHERE thread_id=?", (thread_id,))
    conn.commit(); conn.close()

def update_thread_title(thread_id, title):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("UPDATE chat_threads SET title=? WHERE thread_id=?", (title, thread_id))
    conn.commit(); conn.close()

def add_chat_message(thread_id, username, role, content):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("INSERT INTO chat_messages (thread_id, username, role, content) VALUES (?, ?, ?, ?)", (thread_id, username, role, content))
    conn.commit(); conn.close()

def get_chat_messages(thread_id):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("SELECT role, content, timestamp FROM chat_messages WHERE thread_id=? ORDER BY timestamp ASC", (thread_id,))
    data = c.fetchall(); conn.close()
    return data

def clear_all_chat(username):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("DELETE FROM chat_messages WHERE thread_id IN (SELECT thread_id FROM chat_threads WHERE username=?)", (username,))
    c.execute("DELETE FROM chat_threads WHERE username=?", (username,))
    conn.commit(); conn.close()

# --- READABILITY HISTORY FUNCTIONS ---
def add_readability_record(username, title, full_text, grade_level):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("INSERT INTO readability_records (username, title, full_text, grade_level) VALUES (?, ?, ?, ?)", (username, title, full_text, grade_level))
    conn.commit(); conn.close()

def get_readability_records(username):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("SELECT id, title, full_text, grade_level, timestamp FROM readability_records WHERE username=? ORDER BY timestamp DESC", (username,))
    data = c.fetchall(); conn.close()
    return data

def delete_readability_record(record_id):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("DELETE FROM readability_records WHERE id=?", (record_id,))
    conn.commit(); conn.close()

def clear_all_readability(username):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("DELETE FROM readability_records WHERE username=?", (username,))
    conn.commit(); conn.close()

create_table()

# ======================
# VALIDATION FUNCTIONS
# ======================
def validate_username(username): return re.match(r'^[a-zA-Z0-9_]{3,}$', username)
def validate_email(email): return re.match(r'^[\w\.-]+@[\w\.-]+\.[a-zA-Z]{2,}$', email)
def validate_password(password):
    if " " in password: return False
    if len(password) < 8 or len(password) > 20: return False
    if not any(char in string.punctuation for char in password): return False
    return True
def validate_security_answer(answer): return len(answer) >= 3 and " " not in answer

# ======================
# OTP & EMAIL LOGIC
# ======================
def generate_otp():
    secret = secrets.token_bytes(20)
    counter = int(time.time())
    msg = struct.pack(">Q", counter)
    hmac_hash = hmac.new(secret, msg, hashlib.sha1).digest()
    offset = hmac_hash[19] & 0xf
    code = ((hmac_hash[offset] & 0x7f) << 24 | (hmac_hash[offset + 1] & 0xff) << 16 | (hmac_hash[offset + 2] & 0xff) << 8 | (hmac_hash[offset + 3] & 0xff))
    return f"{code % 1000000:06d}"

def create_otp_token(otp, email):
    otp_hash = bcrypt.hashpw(otp.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    payload = {'otp_hash': otp_hash, 'sub': email, 'type': 'password_reset', 'iat': datetime.datetime.utcnow(), 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=OTP_EXPIRY_MINUTES)}
    return jwt.encode(payload, SECRET_KEY, algorithm='HS256')

def verify_otp_token(token, input_otp, email):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        if payload.get('sub') != email: return False, "Token mismatch"
        if bcrypt.checkpw(input_otp.encode('utf-8'), payload['otp_hash'].encode('utf-8')): return True, "Valid OTP"
        return False, "Invalid OTP"
    except Exception as e: return False, str(e)

def send_email(to_email, otp):
    if not EMAIL_PASSWORD: return False, "Server misconfiguration: EMAIL_PASSWORD missing"
    msg = MIMEMultipart("alternative")
    msg['From'] = f"Infosys LLM <{EMAIL_ADDRESS}>"
    msg['To'] = to_email
    msg['Subject'] = "🌌 Cosmos LLM - Password Reset Verification"
    
    html_body = f"""
    <!DOCTYPE html><html><head><style>
    .container {{ font-family: 'Space Grotesk', sans-serif; background-color: #0b0914; padding: 40px; text-align: center; color: #E2E8F0; }}
    .card {{ background-color: #161224; border-radius: 15px; box-shadow: 0 0 30px rgba(139, 92, 246, 0.2); padding: 40px; max-width: 500px; margin: 0 auto; border: 1px solid rgba(255,255,255,0.05); }}
    .header {{ color: #E9D5FF; font-size: 24px; font-weight: 700; margin-bottom: 20px; text-shadow: 0 0 10px rgba(216, 180, 254, 0.5); }}
    .otp-box {{ background: linear-gradient(45deg, rgba(139, 92, 246, 0.1), rgba(236, 72, 153, 0.1)); color: #06B6D4; font-size: 38px; font-weight: 700; letter-spacing: 8px; padding: 20px; border-radius: 10px; margin: 30px 0; display: inline-block; border: 1px solid rgba(6, 182, 212, 0.3); text-shadow: 0 0 15px rgba(6, 182, 212, 0.5); }}
    .text {{ color: #94A3B8; font-size: 15px; line-height: 1.6; margin-bottom: 20px; }}
    .footer {{ color: #475569; font-size: 13px; margin-top: 30px; border-top: 1px solid rgba(255,255,255,0.05); padding-top: 20px; }}
    </style></head><body><div class="container"><div class="card">
    <div class="header">🚀 Cosmos System Security</div>
    <div class="text">A password reset was requested for the identity: <strong>{to_email}</strong>. Use the secure transmission code below:</div>
    <div class="otp-box">{otp}</div>
    <div class="text">This authorization code expires in <strong>{OTP_EXPIRY_MINUTES} minutes</strong>. Keep it secure.</div>
    <div class="footer">&copy; 2026 Infosys LLM Galactic Network</div>
    </div></div></body></html>
    """
    
    msg.attach(MIMEText(f"Use this OTP to reset your password for {to_email}.\n{otp}\nValid for {OTP_EXPIRY_MINUTES} minutes.", 'plain'))
    msg.attach(MIMEText(html_body, 'html'))
    try:
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
        server.sendmail(EMAIL_ADDRESS, to_email, msg.as_string())
        server.quit()
        return True, "Email sent"
    except Exception as e: return False, str(e)

# ======================
# DATA EXPORT UTILITY
# ======================
@st.cache_data
def convert_df_to_csv(df):
    return df.to_csv(index=False).encode('utf-8')

# ======================
# READABILITY ANALYZER 
# ======================
class ReadabilityAnalyzer:
    def __init__(self, text):
        self.text = text
        self.num_sentences = textstat.sentence_count(text)
        self.num_words = textstat.lexicon_count(text, removepunct=True)
        self.num_syllables = textstat.syllable_count(text)
        self.complex_words = textstat.difficult_words(text)
        self.char_count = textstat.char_count(text)

    def get_all_metrics(self):
        return {
            "Flesch Reading Ease": textstat.flesch_reading_ease(self.text),
            "Flesch-Kincaid Grade": textstat.flesch_kincaid_grade(self.text),
            "SMOG Index": textstat.smog_index(self.text),
            "Gunning Fog": textstat.gunning_fog(self.text),
            "Coleman-Liau": textstat.coleman_liau_index(self.text)
        }

def create_gauge(value, title, min_val=0, max_val=100, color="#06B6D4"):
    fig = go.Figure(go.Indicator(
        mode = "gauge+number", value = value, title = {'text': title, 'font': {'color': "#94A3B8", 'size': 14, 'family': 'Space Grotesk'}},
        number = {'font': {'color': "#FFFFFF", 'size': 24, 'family': 'Space Grotesk', 'weight': 'bold'}},
        gauge = {'axis': {'range': [min_val, max_val], 'tickwidth': 1, 'tickcolor': "rgba(255,255,255,0.1)"}, 'bar': {'color': color},
                 'bgcolor': "rgba(255,255,255,0.02)", 'borderwidth': 1, 'bordercolor': "rgba(255,255,255,0.05)", 'steps': [{'range': [min_val, max_val], 'color': "rgba(0,0,0,0.5)"}]}
    ))
    fig.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font={'family': "Space Grotesk"}, height=220, margin=dict(l=10, r=10, t=40, b=10))
    return fig

# ======================
# SESSION INIT & ROUTING
# ======================
if "page" not in st.session_state: st.session_state.page = "login"
if "login_attempts" not in st.session_state: st.session_state.login_attempts = 0
if "is_admin" not in st.session_state: st.session_state.is_admin = False

# --- LOGGED OUT PAGES ---
if st.session_state.page in ["login", "signup", "forgot"]:
    
    if st.session_state.page == "login":
        st.title("🌌 Nexus Gateway Login")
        st.markdown("Authenticate to access the cosmic network.")
        st.markdown("<br>", unsafe_allow_html=True)
        
        email = st.text_input("Identity (Email)", key="login_email")
        password = st.text_input("Passcode", type="password", key="login_password")

        st.markdown("<br>", unsafe_allow_html=True)
        if st.button("Initialize Sequence"):
            if not email or not password: st.error("All parameters required")
            elif not validate_email(email): st.error("Invalid Identity Format")
            else:
                if email.lower() == ADMIN_EMAIL.lower() and password == ADMIN_PASSWORD:
                    st.session_state.username = "Commander"
                    st.session_state.is_admin = True
                    st.session_state.page = "dashboard"
                    st.session_state.login_attempts = 0
                    st.rerun()
                else:
                    user = get_user_by_email(email)
                    if user and user[3] == hash_password(password):
                        st.session_state.username = user[1]
                        st.session_state.is_admin = False
                        st.session_state.page = "dashboard"
                        st.session_state.login_attempts = 0
                        st.rerun()
                    else:
                        st.session_state.login_attempts += 1
                        st.error(f"Authentication Failed ({st.session_state.login_attempts}/3)")

        st.markdown("<br>", unsafe_allow_html=True)
        c1, c2 = st.columns(2)
        if c1.button("Register Identity"): st.session_state.page = "signup"; st.rerun()
        if c2.button("Recover Passcode"): st.session_state.page = "forgot"; st.rerun()

    elif st.session_state.page == "signup":
        st.title("🌠 Enlist New Identity")
        st.markdown("Join the Infosys LLM galactic network.")
        
        username = st.text_input("Callsign (Username)", key="su_user")
        email = st.text_input("Identity (Email)", key="su_email")
        password = st.text_input("Passcode", type="password", key="su_pass", help="8-20 chars, no spaces, must include special chars.")
        confirm = st.text_input("Confirm Passcode", type="password", key="su_confirm")
        question = st.selectbox("Security Vector", ["What is your pet name?", "What is your mother’s maiden name?", "What is your favorite teacher?"])
        answer = st.text_input("Security Response", key="su_answer")

        st.markdown("<br>", unsafe_allow_html=True)
        if st.button("Initialize Registration"):
            if not all([username, email, password, confirm, question, answer]): st.error("All parameters are required")
            elif not validate_username(username): st.error("Invalid Callsign")
            elif not validate_email(email): st.error("Invalid Identity Format")
            elif not validate_password(password): st.error("Invalid Passcode: Must be 8-20 characters, no spaces, include special character.")
            elif password != confirm: st.error("Passcodes do not match")
            elif not validate_security_answer(answer): st.error("Invalid Security Response")
            elif email.lower() == ADMIN_EMAIL.lower(): st.error("This identity is reserved for Command.")
            elif add_user(username, email, password, question, answer):
                st.success("Identity registered successfully!"); time.sleep(1); st.session_state.page = "login"; st.rerun()
            else: st.error("Callsign or Identity already exists in the network")

        st.markdown("---")
        if st.button("Abort & Return"): st.session_state.page = "login"; st.rerun()

    elif st.session_state.page == "forgot":
        st.title("🔭 Signal Recovery")
        if "reset_email" not in st.session_state: st.session_state.reset_email = None
        if "reset_method" not in st.session_state: st.session_state.reset_method = None
        if "allow_reset" not in st.session_state: st.session_state.allow_reset = False
        if "otp_sent" not in st.session_state: st.session_state.otp_sent = False

        if not st.session_state.reset_email:
            st.markdown("Enter your registered identity to begin recovery protocol.")
            email = st.text_input("Identity (Email)", key="fp_email")
            if st.button("Transmit Ping"):
                if not email: st.error("Please enter an identity.")
                elif email.lower() == ADMIN_EMAIL.lower(): st.error("Command passcode cannot be reset through this terminal.")
                else:
                    user = get_user_by_email(email)
                    if user:
                        st.session_state.reset_email = user[2]; st.session_state.old_password_hash = user[3]; st.session_state.reset_question = user[4]; st.session_state.reset_answer = user[5]
                        st.success("Signal located!"); st.rerun()
                    else: st.error("Signal lost. Identity not found.")
            if st.button("Abort"): st.session_state.clear(); st.session_state.page = "login"; st.rerun()

        elif not st.session_state.allow_reset:
            st.info(f"Recovery target locked: **{st.session_state.reset_email}**")
            if not st.session_state.reset_method:
                c1, c2 = st.columns(2)
                with c1:
                    if st.button("Quantum OTP Protocol"):
                        st.session_state.reset_method = "otp"
                        otp = generate_otp()
                        token = create_otp_token(otp, st.session_state.reset_email)
                        success, msg = send_email(st.session_state.reset_email, otp)
                        if success: st.session_state.otp_token = token; st.session_state.otp_sent = True; st.success("Secure transmission dispatched."); st.rerun()
                        else: st.error(f"Transmission Failed: {msg}"); st.session_state.reset_method = None; st.rerun()
                with c2:
                    if st.button("Security Vector Protocol"): st.session_state.reset_method = "security"; st.rerun()

            if st.session_state.reset_method == "otp":
                if st.session_state.otp_sent:
                    entered_otp = st.text_input("Enter 6-digit Code", key="fp_otp")
                    if st.button("Verify Signature"):
                        valid, msg = verify_otp_token(st.session_state.otp_token, entered_otp, st.session_state.reset_email)
                        if valid: st.session_state.allow_reset = True; st.success("Signature Verified."); st.rerun()
                        else: st.error(msg)
                st.markdown("---")
                if st.button("Switch Protocol"): st.session_state.reset_method = None; st.rerun()

            elif st.session_state.reset_method == "security":
                st.markdown(f"**Security Vector:** {st.session_state.reset_question}")
                entered_answer = st.text_input("Your Response", key="fp_sec_ans")
                if st.button("Verify Response"):
                    if entered_answer.strip().lower() == st.session_state.reset_answer: st.session_state.allow_reset = True; st.success("Signature Verified."); st.rerun()
                    else: st.error("Verification Failed.")
                st.markdown("---")
                if st.button("Switch Protocol"): st.session_state.reset_method = None; st.rerun()

            if st.button("Abort & Return"): st.session_state.clear(); st.session_state.page = "login"; st.rerun()

        elif st.session_state.allow_reset:
            st.success("Authorization granted. Configure a new passcode.")
            new_pass = st.text_input("New Passcode", type="password", key="fp_new")
            if st.button("Update System"):
                if not validate_password(new_pass): st.error("Protocol Violation: Must be 8-20 characters, no spaces, include special character.")
                elif hash_password(new_pass) == st.session_state.old_password_hash: st.error("Protocol Violation: Cannot reuse the previous passcode.")
                else:
                    update_password(st.session_state.reset_email, new_pass)
                    st.success("System updated successfully."); time.sleep(1.5); st.session_state.clear(); st.session_state.page = "login"; st.rerun()

# --- LOGGED IN ROUTING WITH SIDEBAR ---
else:
    with st.sidebar:
        st.markdown(f"### Cosmos Link\n👤 **{st.session_state.username}**")
        st.markdown("---")

        opts = ["Nebula Chat", "Data Analytics", "Void Storage"]
        icons = ["chat-right-quote", "bar-chart-line", "cloud-arrow-down"]
        if st.session_state.get("is_admin"):
            opts.append("Command Center")
            icons.append("shield-shaded")

        selected = option_menu(None, opts, icons=icons, default_index=0,
            styles={
                "container": {"background-color": "transparent", "padding": "5px"},
                "icon": {"color": "#EC4899"},
                "nav-link": {"color": "#94A3B8", "font-family": "Space Grotesk", "border-radius": "10px", "margin": "4px 0", "font-size": "15px", "font-weight": "500"},
                "nav-link-selected": {"background": "linear-gradient(90deg, rgba(139, 92, 246, 0.2), transparent)", "color": "#06B6D4", "border-left": "4px solid #06B6D4"},
            })

        # Dynamic Sidebar History
        if selected == "Nebula Chat":
            st.markdown("<br><p style='color:#8B5CF6; font-size:12px; text-transform:uppercase; font-weight:700; letter-spacing: 1px;'>Active Threads</p>", unsafe_allow_html=True)
            if st.button("➕ Open Comms", use_container_width=True):
                st.session_state.current_thread_id = create_chat_thread(st.session_state.username, "New Comms")
                st.rerun()
                
            threads = get_chat_threads(st.session_state.username)
            for t in threads:
                t_id, t_title, t_ts = t
                c1, c2 = st.columns([5, 1])
                with c1:
                    btn_type = "primary" if st.session_state.get("current_thread_id") == t_id else "secondary"
                    if st.button(t_title, key=f"btn_{t_id}", use_container_width=True, type=btn_type):
                        st.session_state.current_thread_id = t_id
                        st.rerun()
                with c2:
                    if st.button("🗑️", key=f"del_{t_id}", help="Sever Thread"):
                        delete_chat_thread(t_id)
                        if st.session_state.get("current_thread_id") == t_id:
                            st.session_state.current_thread_id = None
                        st.rerun()

        elif selected == "Data Analytics":
            st.markdown("<br><p style='color:#8B5CF6; font-size:12px; text-transform:uppercase; font-weight:700; letter-spacing: 1px;'>Archived Scans</p>", unsafe_allow_html=True)
            records = get_readability_records(st.session_state.username)
            if not records:
                st.caption("No scans found.")
            for r in records[:5]: # Show top 5 in sidebar
                r_id, r_title, r_text, r_grade, r_ts = r
                c1, c2 = st.columns([5, 1])
                with c1:
                    if st.button(f"{r_title}", key=f"btn_r_{r_id}", use_container_width=True, help=f"Level: {r_grade:.1f}"):
                        st.session_state.read_text = r_text
                        st.rerun()
                with c2:
                    if st.button("🗑️", key=f"del_r_{r_id}"):
                        delete_readability_record(r_id)
                        st.rerun()

        st.markdown("---")
        if st.button("🚀 Disconnect"): st.session_state.clear(); st.session_state.page = "login"; st.rerun()

    # --- CHAT PAGE ---
    if selected == "Nebula Chat":
        st.title("🤖 AI Construct")
        
        # Ensure a thread is active
        if "current_thread_id" not in st.session_state or not st.session_state.current_thread_id:
            threads = get_chat_threads(st.session_state.username)
            if threads:
                st.session_state.current_thread_id = threads[0][0]
            else:
                st.session_state.current_thread_id = create_chat_thread(st.session_state.username, "New Comms")
        
        # Display Messages
        messages = get_chat_messages(st.session_state.current_thread_id)
        if len(messages) == 0:
            st.info("System online. Awaiting input...")
        
        for msg in messages:
            role, content, ts = msg
            with st.chat_message(role): st.markdown(content)
            
        # Chat Input
        if prompt := st.chat_input("Transmit message..."):
            # Update Title on first message
            if len(messages) == 0:
                new_title = prompt[:20] + "..." if len(prompt) > 20 else prompt
                update_thread_title(st.session_state.current_thread_id, new_title)

            add_chat_message(st.session_state.current_thread_id, st.session_state.username, "user", prompt)
            with st.chat_message("user"): st.markdown(prompt)
            
            with st.chat_message("assistant"):
                response = f"Simulated Construct: Processing data for '{prompt}' through neural network."
                st.markdown(response)
                add_chat_message(st.session_state.current_thread_id, st.session_state.username, "assistant", response)
            st.rerun()

    # --- READABILITY PAGE ---
    elif selected == "Data Analytics":
        st.title("📡 Cognitive Text Scanner")
        tab1, tab2 = st.tabs(["Manual Override", "Datacube Upload (PDF/TXT)"])
        
        default_text = st.session_state.get("read_text", "")
        text_input = ""

        with tab1:
            raw_text = st.text_area("Input data sequence (minimum 50 chars):", value=default_text, height=250)
            if raw_text: text_input = raw_text

        with tab2:
            uploaded_file = st.file_uploader("Select Datacube", type=["txt", "pdf"])
            if uploaded_file:
                try:
                    if uploaded_file.type == "application/pdf":
                        reader = PyPDF2.PdfReader(uploaded_file)
                        text_input = "".join([page.extract_text() + "\n" for page in reader.pages])
                        st.success(f"Decoded {len(reader.pages)} pages successfully.")
                    else:
                        text_input = uploaded_file.read().decode("utf-8")
                        st.success(f"Decoded raw text successfully.")
                except Exception as e:
                    st.error(f"Decryption Error: {e}")

        if st.button("Initialize Scan", type="primary"):
            if len(text_input) < 50:
                st.error("Insufficient data mass. Minimum 50 characters required.")
            else:
                with st.spinner("Processing through neural pathways..."):
                    analyzer = ReadabilityAnalyzer(text_input)
                    score = analyzer.get_all_metrics()
                    avg_grade = (score['Flesch-Kincaid Grade'] + score['Gunning Fog'] + score['SMOG Index'] + score['Coleman-Liau']) / 4
                    
                    title = text_input[:25] + "..." if len(text_input) > 25 else text_input
                    add_readability_record(st.session_state.username, title, text_input, avg_grade)

                st.markdown("---")
                st.subheader("Scan Results")
                
                # Colors adapted for Galaxy Theme
                if avg_grade <= 6: level, bg_col, text_col = "Novice", "rgba(16, 185, 129, 0.1)", "#10B981"
                elif avg_grade <= 10: level, bg_col, text_col = "Standard", "rgba(6, 182, 212, 0.1)", "#06B6D4"
                elif avg_grade <= 14: level, bg_col, text_col = "Elevated", "rgba(139, 92, 246, 0.1)", "#8B5CF6"
                else: level, bg_col, text_col = "Complex", "rgba(236, 72, 153, 0.1)", "#EC4899"

                st.markdown(f"""
                <div style="background: {bg_col}; padding: 24px; border-radius: 12px; border: 1px solid {text_col}; margin-bottom: 20px; box-shadow: 0 0 15px {bg_col};">
                    <h3 style="margin:0; color: {text_col} !important; text-shadow: 0 0 10px {text_col};">Cognitive Tier: {level}</h3>
                    <p style="margin:5px 0 0 0; color: #E2E8F0; font-size: 15px;">Complexity Index: <strong>{int(avg_grade)}</strong></p>
                </div>
                """, unsafe_allow_html=True)

                st.markdown("#### Telemetry Data")
                c1, c2, c3 = st.columns(3)
                with c1: st.plotly_chart(create_gauge(score["Flesch Reading Ease"], "Flesch Ease", 0, 100, "#06B6D4"), use_container_width=True)
                with c2: st.plotly_chart(create_gauge(score["Flesch-Kincaid Grade"], "Flesch Grade", 0, 20, "#8B5CF6"), use_container_width=True)
                with c3: st.plotly_chart(create_gauge(score["SMOG Index"], "SMOG Index", 0, 20, "#EC4899"), use_container_width=True)

                c4, c5 = st.columns(2)
                with c4: st.plotly_chart(create_gauge(score["Gunning Fog"], "Gunning Fog", 0, 20, "#F59E0B"), use_container_width=True)
                with c5: st.plotly_chart(create_gauge(score["Coleman-Liau"], "Coleman-Liau", 0, 20, "#10B981"), use_container_width=True)

    # --- DATA EXPORT & BULK DELETE PAGE ---
    elif selected == "Void Storage":
        st.title("🗄️ Void Storage Matrix")
        st.markdown("Extract or collapse your historical data constructs.")
        st.markdown("<br>", unsafe_allow_html=True)
        
        t1, t2 = st.tabs(["Comms Logs", "Scanner Logs"])
        
        with t1:
            st.markdown("#### Comms Extraction")
            threads = get_chat_threads(st.session_state.username)
            conn = sqlite3.connect(DB_NAME)
            df_chat = pd.read_sql_query("SELECT thread_id, role, content, timestamp FROM chat_messages WHERE username=?", conn, params=(st.session_state.username,))
            conn.close()

            if not df_chat.empty:
                col1, col2 = st.columns(2)
                with col1:
                    csv_chat = convert_df_to_csv(df_chat)
                    st.download_button(label="📥 Extract Logs (CSV)", data=csv_chat, file_name='comms_logs.csv', mime='text/csv')
                with col2:
                    if st.button("🗑️ Collapse Matrix (Delete All)", type="primary"):
                        clear_all_chat(st.session_state.username)
                        st.session_state.current_thread_id = None
                        st.success("Matrix collapsed."); time.sleep(1); st.rerun()
            else:
                st.info("No active logs detected.")

        with t2:
            st.markdown("#### Scanner Data Extraction")
            records = get_readability_records(st.session_state.username)
            
            if records:
                df_read = pd.DataFrame(records, columns=["ID", "Title", "Full Text", "Grade Level", "Timestamp"])
                col1, col2 = st.columns(2)
                with col1:
                    csv_read = convert_df_to_csv(df_read.drop(columns=["ID"]))
                    st.download_button(label="📥 Extract Data (CSV)", data=csv_read, file_name='scanner_logs.csv', mime='text/csv')
                with col2:
                    if st.button("🗑️ Collapse Data (Delete All)", type="primary"):
                        clear_all_readability(st.session_state.username)
                        st.session_state.read_text = ""
                        st.success("Data collapsed."); time.sleep(1); st.rerun()
            else:
                st.info("No scanner records detected.")

    # --- ADMIN DASHBOARD ---
    elif selected == "Command Center":
        if not st.session_state.get("is_admin"):
            st.error("Security Violation: Access Denied"); st.session_state.clear(); st.session_state.page = "login"; st.rerun()

        st.title("🛡️ Command Center")
        st.markdown("System architecture and identity management protocol.")
        
        users = get_all_users()
        
        if users:
            st.markdown("#### Personnel Roster")
            df = pd.DataFrame(users, columns=["ID Sequence", "Callsign", "Identity"])
            st.dataframe(df, use_container_width=True, hide_index=True)
            st.caption(f"Active Identities: {len(users)}")
            
            st.markdown("---")
            st.markdown("#### Terminate Identity")
            user_options = {f"ID: {u[0]} | {u[1]} ({u[2]})": u[0] for u in users}
            
            c1, c2 = st.columns([3, 1])
            with c1: selected_user_str = st.selectbox("Target Identity:", list(user_options.keys()))
            with c2:
                st.markdown("<br>", unsafe_allow_html=True) 
                if st.button("Execute Termination", type="primary"):
                    target_id = user_options[selected_user_str]
                    target_username = [u[1] for u in users if u[0] == target_id][0]
                    delete_user_by_id(target_id)
                    clear_all_chat(target_username)
                    clear_all_readability(target_username)
                    st.success(f"Identity Terminated: {selected_user_str}"); time.sleep(1.5); st.rerun() 
        else:
            st.warning("No identities currently active in the sector.")




import os
import subprocess
import time
from google.colab import userdata
from pyngrok import ngrok

# Force kill any lingering system ngrok processes to prevent ERR_NGROK_334
os.system("pkill ngrok")

email_pass = None
ngrok_token = None

try:
    try: email_pass = userdata.get('EMAIL_PASSWORD')
    except Exception as e: print(f"⚠️ Warning: EMAIL_PASSWORD secret not found: {e}")
    try: ngrok_token = userdata.get('NGROK_AUTHTOKEN')
    except Exception as e: print(f"⚠️ Warning: NGROK_AUTHTOKEN secret not found: {e}")

    if email_pass: os.environ['EMAIL_PASSWORD'] = email_pass
    os.environ['JWT_SECRET'] = "super-secret-change-me"

except Exception as e: print(f"❌ Error setting up environment: {e}")

if ngrok_token:
    ngrok.set_auth_token(ngrok_token)
    ngrok.kill()
    time.sleep(1)

    process = subprocess.Popen(['streamlit', 'run', 'app.py'], env=os.environ.copy())
    time.sleep(3)

    try:
        public_url = ngrok.connect(8501).public_url
        print(f"\n🚀 Your App is running at: {public_url}")
        print("\n👇 Click the link above to open the app!")
    except Exception as e: print(f"❌ Error starting Ngrok tunnel: {e}")

    print("\n✅ App is running! Check the URL above.")
    try: input("\n🛑 Press ENTER in this box to STOP the server...\n")
    except (KeyboardInterrupt, EOFError): pass
    finally:
        process.terminate()
        ngrok.kill()
        print("✅ Server and Tunnel stopped.")
else:
    print("❌ No Ngrok Token found. Please add 'NGROK_AUTHTOKEN' to Colab Secrets.")
