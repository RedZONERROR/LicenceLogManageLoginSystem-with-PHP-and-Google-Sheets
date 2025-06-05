
This directory contains a C++ client demonstrating interaction with the Google Apps Script (GAS) Web App API. It's suitable for native applications, including potential integration with Android NDK.

## Contents

-   `client.cpp`: The main C++ source file containing the client logic.
-   `encryption.h`: Header for encryption utilities.
-   `encryption.cpp`: Implementation for placeholder encryption utilities.

## Setup Instructions

1.  **Prerequisites:**
    -   C++ compiler (e.g., `g++`).
    -   **`libcurl` development libraries:**
        -   Debian/Ubuntu: `sudo apt-get install libcurl4-openssl-dev`
        -   macOS (Homebrew): `brew install curl`
        -   Windows: Manual download/build or vcpkg.
    -   **`jsoncpp` development libraries:**
        -   Debian/Ubuntu: `sudo apt-get install libjsoncpp-dev`
        -   macOS (Homebrew): `brew install jsoncpp`
        -   Windows: Manual download/build or vcpkg.
2.  **Configuration:**
    -   Open `client.cpp`.
    -   **IMPORTANT:** Replace `YOUR_APPS_SCRIPT_WEB_APP_URL_HERE` with your deployed Google Apps Script Web App URL.
    -   Adjust `CPP_USER_AGENT` if you have specific filtering rules in your `Code.gs`.
3.  **Compile:**
    ```bash
    g++ -std=c++17 client.cpp encryption.cpp -o cpp_client_app -lcurl -ljsoncpp
    ```
    (Adjust compiler flags and library names as per your system if needed).
4.  **Run:**
    ```bash
    ./cpp_client_app
    ```
    The application will prompt for admin credentials to demonstrate API calls.

## Functionality

-   Authenticate users/admins.
-   Verify access tokens.
-   Submit device logs.
-   Search for log entries.

## Encryption Notes

The `encryption.h` and `encryption.cpp` files provide basic Base64 encoding/decoding. For truly secure payload encryption (beyond HTTPS), you would integrate a robust cryptographic library (like OpenSSL or Crypto++) and implement proper symmetric encryption (e.g., AES) with careful key management.
