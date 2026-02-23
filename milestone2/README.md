Milestone 2 – Secure LLM Dashboard & Analytics System
📌 Project Title

Secure LLM-Based Dashboard with Authentication, Chat Management, Readability Analytics, and Admin Control using Streamlit, SQLite, JWT, and Ngrok

📖 Description

In Milestone 2, we extended the User Authentication System developed in Milestone 1 into a full-featured secure dashboard application. This milestone introduces multi-user chat management, text readability analytics, data export, and an admin command center, all protected by secure authentication mechanisms.

The application is built using Streamlit for the user interface, SQLite for persistent data storage, JWT and OTP-based verification for enhanced security, and Ngrok for public access during development and demonstration.

This milestone serves as the backbone for future LLM-powered AI interactions and analytics modules.

🚀 Features Implemented
1. Secure User Authentication (Enhanced)

User Signup with:

Username validation

Email format validation

Password validation (8–20 characters, special characters required)

Security Question & Answer

Secure password hashing

Login with Email and Password

Session-based authentication

Logout and session reset

2. Forgot Password & Recovery System

Password recovery via:

OTP-based email verification

Security question verification

OTP secured using JWT and bcrypt

OTP expiration mechanism

Password update with validation

Old password reuse prevention

3. Nebula Chat System

Multi-threaded chat system per user

Create, rename, and delete chat threads

Persistent chat history stored in SQLite

Role-based message storage (user / assistant)

Export chat logs as CSV

Clear entire chat history

4. Cognitive Text Scanner (Readability Analyzer)

Manual text input (minimum 50 characters)

File upload support:

TXT files

PDF files

Readability metrics calculated:

Flesch Reading Ease

Flesch–Kincaid Grade

SMOG Index

Gunning Fog Index

Coleman–Liau Index

Visual analytics using interactive gauges

Readability scan history storage

Export readability data as CSV

Delete individual or all records

5. Void Storage (Data Management)

Centralized data export system

Download:

Chat history

Readability analytics

Bulk delete user data

Secure user-wise data isolation

6. Admin Command Center

Admin-only access

View all registered users

Delete users from the system

Automatically removes:

User accounts

Chat history

Readability data

Real-time system management

7. UI & Experience Enhancements

Galaxy-themed UI with custom CSS

Glassmorphism effects

Responsive layout

Sidebar-based navigation

Visual feedback and animations

8. Ngrok Integration

Streamlit app hosted locally

Ngrok used to generate a public URL

Enables live demonstrations and remote access

🛠 Technologies Used

Python

Streamlit

SQLite3

JWT (JSON Web Tokens)

bcrypt

SMTP (Email OTP delivery)

Pyngrok

Plotly

Textstat

PyPDF2

Google Colab

▶️ Steps to Run the Application
Step 1: Install Required Libraries
pip install streamlit pyjwt bcrypt python-dotenv pyngrok nltk streamlit-option-menu plotly textstat PyPDF2
Step 2: Set Environment Variables
EMAIL_PASSWORD=your_email_app_password
JWT_SECRET=your_secret_key
NGROK_AUTHTOKEN=your_ngrok_token
Step 3: Run the Streamlit Application
streamlit run app.py
Step 4: Connect Ngrok (Optional – For Public Access)
from pyngrok import ngrok
ngrok.set_auth_token("YOUR_NGROK_AUTH_TOKEN")
📸 Screenshots

Login Page

Signup Page

Forgot Password (OTP & Security Question)

Nebula Chat Interface

Cognitive Text Scanner Dashboard

Admin Command Center

(Screenshots to be added in the repository)

🌐 Demonstration Link

Ngrok Public URL:
(Add your generated Ngrok URL here)

📂 Project Structure
milestone2/
│
├── app.py
├── InfosysSpringBoard_Internship_Milestone2.ipynb
├── README.md
├── screenshots/
│   ├── login.png
│   ├── signup.png
│   ├── chat.png
│   ├── analytics.png
│   └── admin.png
|   ├── 
✅ Milestone 2 Outcome

Successfully developed a secure, scalable, and feature-rich dashboard system with:

Strong authentication & recovery mechanisms

Persistent chat management

Advanced readability analytics

Secure data export & deletion

Admin-level system control

Public access via Ngrok

This milestone establishes a robust foundation for future LLM-based AI integration.

👨‍💻 Author

Student Name: Bhavithravanan C A
Program: Infosys Springboard Internship
Milestone: Milestone 2 – Secure LLM Dashboard & Analytics System
