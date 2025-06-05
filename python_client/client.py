
import requests
import json
import base64
import os
from datetime import datetime, timedelta
from encryption import encrypt_data, decrypt_data # Assuming encryption.py is in the same directory

# --- CONFIGURATION ---
# !!! REPLACE WITH YOUR ACTUAL GOOGLE APPS SCRIPT WEB APP URL !!!
GAS_ENDPOINT = 'YOUR_APPS_SCRIPT_WEB_APP_URL_HERE'
PYTHON_USER_AGENT = 'MyPythonClient/1.0' # Match this in your GAS isValidUserAgent()

class GasClient:
    def __init__(self, endpoint=GAS_ENDPOINT, user_agent=PYTHON_USER_AGENT):
        self.endpoint = endpoint
        self.user_agent = user_agent

    def _make_request(self, action, method='GET', payload=None):
        headers = {
            'User-Agent': self.user_agent,
            'Content-Type': 'application/json',
        }
        
        params = {'action': action}
        if method == 'GET' and payload:
            params.update(payload)

        try:
            if method == 'GET':
                response = requests.get(self.endpoint, params=params, headers=headers)
            elif method == 'POST':
                # Add action and userAgent to the POST payload
                if payload is None:
                    payload = {}
                payload['action'] = action
                payload['userAgent'] = self.user_agent
                
                # If encryption is truly implemented, encrypt the payload here
                # encrypted_payload = encrypt_data(payload, encryption_key) # Conceptual
                # response = requests.post(self.endpoint, data=encrypted_payload, headers=headers)
                
                response = requests.post(self.endpoint, json=payload, headers=headers)
            else:
                raise ValueError("Unsupported HTTP method")

            response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)
            
            # If decryption is truly implemented, decrypt the response here
            # decrypted_response_content = decrypt_data(response.text, encryption_key) # Conceptual
            # return json.loads(decrypted_response_content)

            return response.json()
        except requests.exceptions.HTTPError as errh:
            print(f"HTTP Error: {errh}")
            print(f"Response content: {response.text}")
            return {'status': 'error', 'message': f"HTTP error: {errh.response.status_code} - {errh.response.text}"}
        except requests.exceptions.ConnectionError as errc:
            print(f"Error Connecting: {errc}")
            return {'status': 'error', 'message': f"Connection error: {errc}"}
        except requests.exceptions.Timeout as errt:
            print(f"Timeout Error: {errt}")
            return {'status': 'error', 'message': f"Timeout error: {errt}"}
        except requests.exceptions.RequestException as err:
            print(f"Something went wrong: {err}")
            return {'status': 'error', 'message': f"Request error: {err}"}
        except json.JSONDecodeError as e:
            print(f"Failed to decode JSON response: {response.text}, Error: {e}")
            return {'status': 'error', 'message': f"Invalid JSON response: {response.text}"}

    def authenticate(self, username, password):
        print(f"Authenticating user: {username}...")
        return self._make_request('authenticate', 'POST', {'username': username, 'password': password})

    def verify_token(self, token):
        print(f"Verifying token: {token}...")
        return self._make_request('verifyToken', 'GET', {'token': token})

    def generate_token(self, admin_username, admin_password, name, expiry_days):
        print(f"Generating token for {name}...")
        return self._make_request('generateToken', 'GET', {
            'adminUsername': admin_username,
            'adminPassword': admin_password,
            'name': name,
            'expiryDays': expiry_days
        })

    def put_log(self, token, device_id, log_message, brand=None, sdk_version=None):
        print(f"Submitting log for device {device_id}...")
        log_data = {
            'token': token,
            'deviceId': device_id,
            'logMessage': log_message,
            'brand': brand,
            'sdkVersion': sdk_version
        }
        return self._make_request('putLog', 'POST', log_data)

    def search_logs(self, query, column, limit=100):
        print(f"Searching logs for '{query}' in column '{column}'...")
        return self._make_request('searchLogs', 'GET', {'query': query, 'column': column, 'limit': limit})


# --- EXAMPLE USAGE ---
if __name__ == "__main__":
    client = GasClient()

    print("\n--- 1. Authenticating Admin User ---")
    admin_username = input("Enter admin username: ")
    admin_password = input("Enter admin password: ")
    auth_response = client.authenticate(admin_username, admin_password)
    print(auth_response)

    if auth_response.get('authenticated'):
        print("\n--- 2. Generating a new token ---")
        device_name = "TestDevicePython"
        token_response = client.generate_token(admin_username, admin_password, device_name, 365)
        print(token_response)
        new_token = token_response.get('token')
    else:
        print("Admin authentication failed. Cannot proceed with token generation or other admin tasks.")
        new_token = None

    if new_token:
        print("\n--- 3. Verifying the generated token ---")
        verify_response = client.verify_token(new_token)
        print(verify_response)

        print("\n--- 4. Putting a log entry ---")
        log_response = client.put_log(
            new_token,
            "PY_DEV_001",
            "Python client test log message.",
            brand="PythonBrand",
            sdk_version="3.9"
        )
        print(log_response)

        print("\n--- 5. Searching logs ---")
        search_response = client.search_logs("PY_DEV_001", "DEVICE_ID")
        print(search_response)

        search_response = client.search_logs("test log", "LOG_MESSAGE")
        print(search_response)

    else:
        print("No token available for further operations.")

    print("\n--- Testing invalid token verification ---")
    invalid_token_response = client.verify_token("INVALID_TOKEN_XYZ")
    print(invalid_token_response)