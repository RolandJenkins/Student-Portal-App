# Student Portal Project (Group 3) 

 
A secure Student Portal web application demonstrating various security implementations including AES-256 encryption, Hashing, RBAC, and Audit Logging. 


## 🚀 Features 

- **Secure Login**: Brute-force protection (Rate Limiting) and CAPTCHA. 

- **Data Privacy**: End-to-end encryption for Personally Identifiable Information (PII) like addresses and phone numbers. 

- **Security**: 

- **HTTPS/SSL**: Secure communication via TLS. 

- **Password Hashing**: `bcrypt` for secure storage. 

- **Encryption**: AES-256-CBC for sensitive fields. 

- **Fail Secure**: Automatic shutdown if security keys are missing. 

- **RBAC**: Faculty vs. Student role enforcement. 
 

## 🛠️ Prerequisites  

- **Node.js**: v14+ (Recommended v20+) 

- **npm**: Comes with Node.js 

- **SQLite3**: Embedded database (no external install required) 

 
## 📦 Installation 

1. **Clone the repository**: 

```bash 

git clone https://github.com/Krafty28/CS370_StudentPortal_Group3.git 

cd CS370_StudentPortal_Group3 

```  

2. **Install dependencies**: 

```bash 

npm install 

``` 


## ⚙️ Configuration 
 
Create a `.env` file in the root directory (if not already present). This file is **gitignored** for security. 

 
```env 

PORT=3000 

RECAPTCHA_SECRET=your_google_recaptcha_secret 

ENCRYPTION_KEY=your_32_byte_hex_string_here 

STATIC_IV=your_16_byte_hex_string_here 

``` 

 

> **Note**: The `.env` file handles the **Protection of Keys**. Never commit it to GitHub. 

 
## 🏃‍♂️ Usage 

1. **Start the Server**: 

```bash 

npm start 

``` 


2. **Access the App**: 

Open your browser and navigate to: 

**[https://localhost:3443](https://localhost:3443)** 


*(Note: You may need to accept the self-signed certificate warning if running locally for the first time)* 

 
## 🛡️ Security Implementations 

| Feature | Implementation With | 

| :--- | :--- | 

| **HTTPS** | `https` module + `mkcert` certificates | 

| **Passwords** | `bcrypt` (Salted Hash) | 

| **Usernames** | AES-256-CBC (Deterministic IV) | 

| **Privacy (PII)** | AES-256-CBC (Randomized IV) | 

| **Spam Protection** | `express-rate-limit` | 

| **Bot Protection** | Google reCAPTCHA v2 | 

| **Database** | SQLite3 with Parameterized Queries (Anti-SQLi) | 