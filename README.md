
# LicenseLogManageLoginSystem-with-PHP-and-Google-Sheets

This project demonstrates a robust system for managing software licenses (tokens), device logs, and user authentication using Google Sheets as a backend, Google Apps Script as a serverless API, and clients in PHP, Python, and C++.

## Table of Contents

- [Features](#features)
- [Project Structure](#project-structure)
- [Prerequisites](#prerequisites)
- [Setup Guide](#setup-guide)
    - [1. Google Sheets Setup](#1-google-sheets-setup)
    - [2. Google Apps Script Deployment](#2-google-apps-script-deployment)
    - [3. PHP Frontend Setup](#3-php-frontend-setup)
    - [4. Python Client Setup](#4-python-client-setup)
    - [5. C++ Client Setup](#5-c-client-setup)
- [Security Considerations](#security-considerations)
- [API Endpoints (Google Apps Script)](#api-endpoints-google-apps-script)
- [Future Enhancements](#future-enhancements)
- [License](#license)

## Features

- **Token Management:**
    - Generate unique, time-limited access tokens for devices/users.
    - Verify token validity (active, expired, revoked).
    - Revoke tokens.
- **Device Log Management:**
    - Store device-specific logs (device ID, brand, SDK, message, timestamp, user agent).
    - Automatic log sheet rotation (up to 6 sheets, 10,000 records each, then overwrites oldest).
    - Search/filter logs by various criteria.
- **User Authentication:**
    - Secure user login with salted SHA-256 password hashing.
    - Role-based access (e.g., admin users for token generation).
- **Multi-Client Support:**
    - PHP web frontend for administrative tasks and testing.
    - Python client for programmatic interaction.
    - C++ client (demonstrating Android/native application integration).
- **Security Focus:**
    - Explicit Google Sheet access (by ID/name).
    - Input validation on Google Apps Script.
    - Custom User-Agent filtering for client requests.
    - Placeholder for symmetric communication encryption (concept for future implementation).

## Project Structure

```
LicenceLogManageLoginSystem-with-PHP-and-Google-Sheets/
├── app_log_token/
│   ├── Code.gs           # Google Apps Script (GAS) backend logic
│   ├── index.php         # PHP web frontend to interact with GAS
│   └── README.md         # Documentation for the app_log_token module
├── python_client/
│   ├── client.py         # Python client for token/log operations
│   ├── encryption.py     # Python encryption utilities (placeholder for AES etc.)
│   └── README.md         # Python client documentation
├── cpp_client/
│   ├── client.cpp        # C++ client for token/log operations
│   ├── encryption.h      # C++ encryption utilities (header)
│   ├── encryption.cpp    # C++ encryption utilities (implementation)
│   └── README.md         # C++ client documentation
└── README.md             # Main project README (this file)
```

## Prerequisites

### General
- A Google Account (for Google Sheets and Google Apps Script).
- Basic understanding of Google Sheets, JavaScript (for Apps Script), PHP, Python, and C++.

### For Local Development/Testing
- **PHP Frontend:**
    - A web server with PHP (e.g., Apache, Nginx + PHP-FPM, or local XAMPP/WAMP).
    - `php-curl` extension enabled.
- **Python Client:**
    - Python 3.6+ installed.
    - `requests` library (`pip install requests`).
- **C++ Client:**
    - C++ compiler (e.g., g++).
    - `libcurl` development libraries.
    - `jsoncpp` development libraries.

## Setup Guide

Follow these steps carefully to set up the entire system.

---

### 1. Google Sheets Setup

Create a new Google Spreadsheet and name it `LicenseLogAuthSystem`.
Within this spreadsheet, create the following sheets with the exact column headers as specified:

-   **`token` Sheet:**
    -   `NAME | TOKEN | REGISTER_DATE | EXPIRY_DATE | USERS | STATUS`
-   **`log_0` Sheet:**
    -   `DEVICE_ID | BRAND | SDK_VERSION | LOG_MESSAGE | NAME | TIMESTAMP | USER_AGENT`
-   **`log_1` to `log_5` Sheets:**
    -   Create 5 more sheets named `log_1`, `log_2`, `log_3`, `log_4`, `log_5`. Ensure they have the exact same headers as `log_0`.
-   **`auth` Sheet:**
    -   `USERNAME | PASSWORD_HASH | SALT | EMAIL | LAST_LOGIN | ROLE`

**Important:** Note down the **Spreadsheet ID** from your browser's URL. It's the long string between `/d/` and `/edit`.
`https://docs.google.com/spreadsheets/d/YOUR_SPREADSHEET_ID_HERE/edit#gid=0`

---

### 2. Google Apps Script Deployment (`app_log_token/Code.gs`)

1.  Open your `LicenseLogAuthSystem` Google Sheet.
2.  Go to `Extensions` > `Apps Script`. This will open a new tab with the Apps Script editor.
3.  Delete any existing code in `Code.gs` and copy the entire content from `app_log_token/Code.gs` into it.
4.  **CRITICAL:** In `Code.gs`, find the line `const SPREADSHEET_ID = 'YOUR_GOOGLE_SHEET_ID_HERE';` and **replace `'YOUR_GOOGLE_SHEET_ID_HERE'` with the actual Spreadsheet ID you noted down in Step 1.**
5.  Save the script (Ctrl + S or File > Save project).
6.  **Initial Admin User Setup:**
    -   Locate the `registerUser` function in `Code.gs`.
    -   You can temporarily uncomment and run `registerUser("admin", "your_strong_admin_password", "admin@example.com", "admin");` from the Apps Script editor's function dropdown to create your first admin user. **Remember to use a strong password.**
    -   **SECURITY NOTE:** After the first admin user is created, it's highly recommended to either remove this call or comment it out, or protect it with an additional security mechanism (e.g., a pre-shared secret in a `doPost` call, as hinted in the code).
7.  **Deploy as Web App:**
    -   Click the `Deploy` button (top right) > `New deployment`.
    -   Select `Web app` as the type.
    -   **Execution as:** Choose `Me` (your Google Account). This ensures the script runs with your permissions to access the spreadsheet.
    -   **Who has access:** Select `Anyone`. This makes your Apps Script accessible from external clients (PHP, Python, C++). **Be aware:** While the endpoint is public, your script's internal logic (`isValidUserAgent`, authentication checks) is designed to control access to your data.
    -   Click `Deploy`.
    -   You will be prompted to **Authorize** the script to access your Google services (especially Google Sheets). Review the permissions and click `Allow`.
    -   A dialog will appear with your **Web App URL**. **Copy this URL carefully.** This is your API endpoint for all clients.

---

### 3. PHP Frontend Setup (`app_log_token/index.php`)

1.  Save the content of `app_log_token/index.php` to a file named `index.php` in your web server's document root (or a subfolder).
2.  **CRITICAL:** In `index.php`, find the line `define('GAS_ENDPOINT', 'YOUR_APPS_SCRIPT_WEB_APP_URL_HERE');` and **replace `'YOUR_APPS_SCRIPT_WEB_APP_URL_HERE'` with the Web App URL you obtained in Step 2.**
3.  Ensure your web server (Apache/Nginx) is running and PHP is correctly configured. Make sure the `php-curl` extension is enabled.
4.  Access the `index.php` file through your web browser (e.g., `http://localhost/path/to/index.php`).
5.  Use the forms to test authentication, token generation/verification, and log submission/search.

---

### 4. Python Client Setup (`python_client/`)

1.  Navigate to the `python_client/` directory.
2.  Save the content of `python_client/client.py` as `client.py`.
3.  Save the content of `python_client/encryption.py` as `encryption.py`.
4.  **CRITICAL:** In `client.py`, find the line `GAS_ENDPOINT = 'YOUR_APPS_SCRIPT_WEB_APP_URL_HERE'` and **replace `'YOUR_APPS_SCRIPT_WEB_APP_URL_HERE'` with your Apps Script Web App URL.**
5.  Install the `requests` library:
    ```bash
    pip install requests
    ```
6.  Run the client from your terminal:
    ```bash
    python python_client/client.py
    ```
    Follow the prompts for username/password.

---

### 5. C++ Client Setup (`cpp_client/`)

1.  Navigate to the `cpp_client/` directory.
2.  Save the content of `cpp_client/client.cpp` as `client.cpp`.
3.  Save the content of `cpp_client/encryption.h` as `encryption.h`.
4.  Save the content of `cpp_client/encryption.cpp` as `encryption.cpp`.
5.  **CRITICAL:** In `client.cpp`, find the line `const std::string GAS_ENDPOINT = "YOUR_APPS_SCRIPT_WEB_APP_URL_HERE";` and **replace `"YOUR_APPS_SCRIPT_WEB_APP_URL_HERE"` with your Apps Script Web App URL.**
6.  **Install `libcurl` and `jsoncpp` development libraries.**
    -   **Debian/Ubuntu:**
        ```bash
        sudo apt-get update
        sudo apt-get install libcurl4-openssl-dev libjsoncpp-dev
        ```
    -   **macOS (with Homebrew):**
        ```bash
        brew install curl jsoncpp
        ```
    -   **Windows:** This is more complex. You'll generally need to download pre-compiled binaries for your compiler (e.g., MSVC) from `curl` and `jsoncpp` official sites, or build them from source. Configure your IDE (Visual Studio, Code::Blocks, etc.) to link against them.
7.  **Compile the C++ client:**
    ```bash
    g++ -std=c++17 client.cpp encryption.cpp -o cpp_client_app -lcurl -ljsoncpp
    ```
    (Adjust compiler flags and library names if using a different setup or Windows).
8.  **Run the client:**
    ```bash
    ./cpp_client_app
    ```
    Follow the prompts for username/password.

---

## Security Considerations

-   **HTTPS for Apps Script:** Google Apps Script web apps are served over HTTPS, securing the transport layer.
-   **User Agent Validation:** The `isValidUserAgent` function in `Code.gs` is a crucial place to enforce that only your trusted clients can interact with the API. **Harden this logic for production!**
-   **Password Hashing & Salting:** Passwords in the `auth` sheet are stored as salted SHA-256 hashes. **Never store plain passwords.**
-   **API Key/Secret (for critical actions):** For highly sensitive actions (like `generateToken` or `revokeToken`), consider adding an additional layer of security beyond just username/password. This could be a pre-shared API key sent in the request header or body, or even a token-based authorization flow where a short-lived access token is issued after successful admin login.
-   **Data Validation:** Apps Script performs basic validation on incoming data. Enhance this with stricter checks based on your application's needs.
-   **Error Messages:** Avoid returning overly detailed error messages from the Apps Script to prevent information leakage.
-   **Shared Spreadsheet Permissions:** **Crucially, ensure your main Google Spreadsheet (`LicenseLogAuthSystem`) is NOT publicly shared.** The Apps Script runs with your permissions, not the client's. If someone has the Apps Script URL, they can only do what your script allows, not directly browse your spreadsheet.
-   **Communication Encryption (Placeholder):** The `encryption.py`, `encryption.h`, `encryption.cpp` files are placeholders. For true end-to-end payload encryption beyond HTTPS, you would need to implement a robust symmetric encryption algorithm (e.g., AES) with a securely managed shared secret key between your Apps Script and clients. This is complex and might be overkill for many applications given HTTPS.

## API Endpoints (Google Apps Script)

All requests are made to your deployed Google Apps Script Web App URL.

### GET Requests:

-   **`action=verifyToken`**
    -   `token`: The token string to verify.
    -   Returns: `{ status: 'success', isValid: boolean, message: string, name: string }` or `{ status: 'error', message: string }`
-   **`action=searchLogs`**
    -   `query`: The search string.
    -   `column`: The column name to search within (e.g., `DEVICE_ID`, `LOG_MESSAGE`).
    -   `limit` (optional): Max number of results.
    -   Returns: `{ status: 'success', data: Array<object> }` or `{ status: 'error', message: string }`
-   **`action=generateToken`** (Requires admin authentication parameters)
    -   `adminUsername`: Admin username.
    -   `adminPassword`: Admin password.
    -   `name`: Name for the new token (e.g., device name).
    -   `expiryDays`: Number of days until token expires.
    -   Returns: `{ status: 'success', token: string }` or `{ status: 'error', message: string }`
-   **`action=revokeToken`** (Requires admin authentication parameters)
    -   `adminUsername`: Admin username.
    -   `adminPassword`: Admin password.
    -   `token`: The token string to revoke.
    -   Returns: `{ status: 'success', revoked: boolean }` or `{ status: 'error', message: string }`
-   **`action=authenticate`** (Can also be POST)
    -   `username`: User's username.
    -   `password`: User's plain text password.
    -   Returns: `{ authenticated: boolean, message: string, role: string, username: string }`

### POST Requests:

-   **`action=putLog`** (JSON payload)
    -   `token`: The valid token for authorization.
    -   `deviceId`: Unique identifier for the device.
    -   `brand`: Device brand (optional).
    -   `sdkVersion`: SDK version (optional).
    -   `logMessage`: The log message content.
    -   Returns: `{ status: 'success', message: string }` or `{ status: 'error', message: string }`
-   **`action=authenticate`** (JSON payload - Recommended for auth)
    -   `username`: User's username.
    -   `password`: User's plain text password.
    -   Returns: `{ authenticated: boolean, message: string, role: string, username: string }`

## Future Enhancements

-   **Robust Communication Encryption:** Implement actual AES/other symmetric encryption for data payloads using a shared secret key (requires careful key management).
-   **Advanced Authentication:** Implement OAuth2.0 for user authentication instead of direct username/password in requests (more complex, but standard for production).
-   **Rate Limiting:** Add logic in Apps Script to prevent abuse and brute-force attacks.
-   **Audit Logging:** Log all API requests and responses for auditing purposes.
-   **Frontend Improvements:** More sophisticated UI for the PHP frontend.
-   **Admin Panel:** A dedicated admin panel for managing tokens and users within Google Sheets directly, or via the PHP frontend.
-   **Cloud Logging:** Integrate Apps Script with Google Cloud Logging for better log management and analysis.
-   **Error Reporting:** Use a robust error reporting system.

## License

This project is open-source and available under the [MIT License](LICENSE.md).
