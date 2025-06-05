
This directory contains a Python client script designed to interact with the Google Apps Script (GAS) Web App API.

## Contents

-   `client.py`: The main Python script that implements functions to call the GAS API endpoints.
-   `encryption.py`: A placeholder for symmetric encryption utilities. Currently, it performs base64 encoding/decoding, but can be extended for actual encryption (e.g., AES) if payload encryption is desired.

## Setup Instructions

1.  **Prerequisites:**
    -   Python 3.6+ installed.
    -   The `requests` library: `pip install requests`
2.  **Configuration:**
    -   Open `client.py`.
    -   **IMPORTANT:** Replace `YOUR_APPS_SCRIPT_WEB_APP_URL_HERE` with your deployed Google Apps Script Web App URL.
    -   Adjust `PYTHON_USER_AGENT` if you have specific filtering rules in your `Code.gs`.
3.  **Run:**
    ```bash
    python client.py
    ```
    The script will prompt you for admin credentials to demonstrate token generation and logging.

## Functionality

-   Authenticate users/admins.
-   Verify access tokens.
-   Generate new tokens (requires admin authentication).
-   Submit device logs.
-   Search for log entries.

## Encryption Notes

The `encryption.py` file provides basic base64 encoding/decoding. For truly secure payload encryption (beyond HTTPS), you would integrate a robust cryptographic library (like PyCryptodome for AES) and implement proper key management.
