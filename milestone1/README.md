
# Milestone 1 – User Authentication System

## 📌 Project Title
Secure User Authentication System using Streamlit, SQLite, JWT Concept, and Ngrok

---

## 📖 Description

In Milestone 1, we developed a secure and functional User Authentication System that serves as the foundation for the PolicyNav project. This system ensures that only authenticated users can access the application.

The authentication system was built using Streamlit for the frontend interface, SQLite for database storage, and secure password handling techniques. The application also uses Ngrok to generate a public URL so the locally hosted application can be accessed over the internet.

This module will later be integrated with AI-based public policy analysis, search, and summarization features.

---

## 🚀 Features Implemented

### 1. User Signup Page
- Username input
- Email ID validation (proper email format)
- Password validation:
  - Must be alphanumeric
  - Minimum 8 characters
  - Maximum 10 characters
- Confirm Password matching validation
- Security Question selection
- Security Answer input
- Secure storage of user data in SQLite database

---

### 2. User Login Page
- Login using Email ID and Password
- Verification of credentials from database
- Secure authentication
- Redirect to Dashboard after successful login

---

### 3. Dashboard Page
- Welcome message displaying the username
- Logout button
- Session management

---

### 4. Forgot Password Functionality
- User enters registered Email ID
- System displays Security Question
- User enters Security Answer
- If correct, user can reset password
- Password securely updated in database

---

### 5. Database Integration
- SQLite database used for secure credential storage
- Stores:
  - Username
  - Email
  - Password (hashed)
  - Security Question
  - Security Answer

---

### 6. Ngrok Integration
- Streamlit app hosted locally
- Ngrok used to generate public URL
- Allows external access to the application

---

## 🛠 Technologies Used

- Python
- Streamlit
- SQLite3
- Pyngrok
- Google Colab

---

## ▶️ Steps to Run the Application

### Step 1: Install Required Libraries

```bash
pip install streamlit pyngrok
````

---

### Step 2: Run the Streamlit Application

```bash
streamlit run app.py
```

---

### Step 3: Connect Ngrok (Optional for Public Access)

```python
from pyngrok import ngrok
ngrok.set_auth_token("YOUR_NGROK_AUTH_TOKEN")
```

---

## 📸 Screenshots

### Signup Page

![Signup](signup.png)

### Login Page

![Login](login.png)


### Forgot Password Page

![Forgot Password](forgot_password.png)

---

## 🌐 Demonstration Link

Ngrok Public URL:
https://diandrous-stertorously-jo.ngrok-free.dev/



---

## 📂 Project Structure

```
milestone1/
│
├── app.py
├── InfosysSpringBoard_Internship_milestone1.ipynb
├── README.md
├── signup page.png
├── login page.png
└── forgot password page.png
```

---

## ✅ Milestone 1 Outcome

Successfully developed a complete user authentication system with:

* Secure signup
* Secure login
* Password recovery system
* Dashboard access
* Database integration
* Public access using Ngrok

This system serves as the secure access layer for the upcoming PolicyNav AI-based public policy platform.

---

## 👨‍💻 Author

Student Name: Bhavithravanan C A
Program: Infosys Springboard
Milestone: Milestone 1 – User Authentication System

```
