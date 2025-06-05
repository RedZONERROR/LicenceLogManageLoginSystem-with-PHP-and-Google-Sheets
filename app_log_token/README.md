
This directory contains the core Google Apps Script (GAS) backend and a simple PHP frontend to interact with it.

## Contents

-   `Code.gs`: The Google Apps Script code that acts as the serverless API endpoint.
-   `index.php`: A PHP web page that provides a simple user interface to call the GAS API for various actions.

## Setup Instructions

1.  **Google Sheets:** Ensure your Google Sheet (`LicenseLogAuthSystem`) is set up as described in the main project `README.md`.
2.  **Google Apps Script (`Code.gs`):**
    -   Open `Extensions > Apps Script` from your Google Sheet.
    -   Copy the content of this `Code.gs` into the Apps Script editor.
    -   **IMPORTANT:** Replace `YOUR_GOOGLE_SHEET_ID_HERE` with your actual Spreadsheet ID.
    -   Deploy the script as a Web App (Execute as: `Me`, Who has access: `Anyone`). Note down the Web App URL.
3.  **PHP Frontend (`index.php`):**
    -   Place this `index.php` file on your web server (e.g., Apache, Nginx with PHP-FPM).
    -   **IMPORTANT:** In `index.php`, replace `YOUR_APPS_SCRIPT_WEB_APP_URL_HERE` with the Web App URL obtained in the previous step.
    -   Ensure your PHP environment has the `curl` extension enabled.

## Functionality

-   **Authentication:** Allows users to log in (admin users can then perform privileged actions).
-   **Token Management:** Generate and verify tokens.
-   **Log Submission:** Allows devices (via tokens) to submit log data.
-   **Log Search:** Search functionality for logs based on query and column.

## Security Notes

-   The `isValidUserAgent` function in `Code.gs` is crucial for filtering requests. **Customize it for production.**
-   All sensitive operations (token generation, revocation) are protected by admin authentication.
-   Password hashing with salting is used for user credentials.
