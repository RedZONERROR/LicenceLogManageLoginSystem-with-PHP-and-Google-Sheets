
<?php
// app_log_token/index.php

// --- CONFIGURATION ---
// !!! REPLACE WITH YOUR ACTUAL GOOGLE APPS SCRIPT WEB APP URL !!!
define('GAS_ENDPOINT', 'YOUR_APPS_SCRIPT_WEB_APP_URL_HERE');
define('CUSTOM_USER_AGENT', 'MyPHPWebClient/1.0'); // Match this in your GAS isValidUserAgent()

// --- HELPER FUNCTIONS ---
function callGasEndpoint($action, $method = 'GET', $data = []) {
    $url = GAS_ENDPOINT;
    $headers = [
        'User-Agent: ' . CUSTOM_USER_AGENT, // Custom User-Agent header
        'Content-Type: application/json',
    ];

    if ($method === 'GET') {
        $url .= '?' . http_build_query(array_merge($data, ['action' => $action]));
    }

    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);

    if ($method === 'POST') {
        curl_setopt($ch, CURLOPT_POST, true);
        $data['action'] = $action; // Add action to the POST payload
        $data['userAgent'] = CUSTOM_USER_AGENT; // Add user agent to POST payload for GAS
        curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data));
    }

    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $error = curl_error($ch);
    curl_close($ch);

    if ($error) {
        return ['status' => 'error', 'message' => 'cURL Error: ' . $error];
    }
    return json_decode($response, true);
}

// --- FORM HANDLING ---
$response = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';

    switch ($action) {
        case 'authenticate':
            $username = $_POST['username'] ?? '';
            $password = $_POST['password'] ?? '';
            if ($username && $password) {
                $response = callGasEndpoint('authenticate', 'POST', ['username' => $username, 'password' => $password]);
            } else {
                $response = ['status' => 'error', 'message' => 'Username and password required.'];
            }
            break;

        case 'verifyToken':
            $token = $_POST['token_to_verify'] ?? '';
            if ($token) {
                $response = callGasEndpoint('verifyToken', 'GET', ['token' => $token]);
            } else {
                $response = ['status' => 'error', 'message' => 'Token to verify is required.'];
            }
            break;

        case 'generateToken':
            $adminUsername = $_POST['admin_username'] ?? '';
            $adminPassword = $_POST['admin_password'] ?? '';
            $tokenName = $_POST['token_name'] ?? '';
            $expiryDays = (int)($_POST['expiry_days'] ?? 0);
            if ($adminUsername && $adminPassword && $tokenName && $expiryDays > 0) {
                $response = callGasEndpoint('generateToken', 'GET', [
                    'adminUsername' => $adminUsername,
                    'adminPassword' => $adminPassword,
                    'name' => $tokenName,
                    'expiryDays' => $expiryDays
                ]);
            } else {
                $response = ['status' => 'error', 'message' => 'Admin creds, name, and expiry days are required.'];
            }
            break;

        case 'putLog':
            $logToken = $_POST['log_token'] ?? '';
            $deviceId = $_POST['device_id'] ?? '';
            $brand = $_POST['brand'] ?? '';
            $sdkVersion = $_POST['sdk_version'] ?? '';
            $logMessage = $_POST['log_message'] ?? '';
            if ($logToken && $deviceId && $logMessage) {
                $response = callGasEndpoint('putLog', 'POST', [
                    'token' => $logToken,
                    'deviceId' => $deviceId,
                    'brand' => $brand,
                    'sdkVersion' => $sdkVersion,
                    'logMessage' => $logMessage
                ]);
            } else {
                $response = ['status' => 'error', 'message' => 'Token, Device ID, Log Message required.'];
            }
            break;

        case 'searchLogs':
            $searchQuery = $_POST['search_query'] ?? '';
            $searchColumn = $_POST['search_column'] ?? '';
            if ($searchQuery && $searchColumn) {
                $response = callGasEndpoint('searchLogs', 'GET', [
                    'query' => $searchQuery,
                    'column' => $searchColumn,
                    'limit' => 50 // Example limit
                ]);
            } else {
                $response = ['status' => 'error', 'message' => 'Search query and column required.'];
            }
            break;

        default:
            $response = ['status' => 'error', 'message' => 'Invalid action specified.'];
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>License & Log Management System</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f4f4f4; }
        .container { background-color: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 0 10px rgba(0,0,0,0.1); max-width: 800px; margin: auto; }
        h2 { color: #333; border-bottom: 2px solid #eee; padding-bottom: 10px; margin-bottom: 20px; }
        form { margin-bottom: 20px; padding: 15px; border: 1px solid #ddd; border-radius: 5px; background-color: #fafafa; }
        label { display: block; margin-bottom: 5px; font-weight: bold; }
        input[type="text"], input[type="password"], input[type="number"], textarea {
            width: calc(100% - 22px); padding: 10px; margin-bottom: 10px; border: 1px solid #ccc; border-radius: 4px;
        }
        button { background-color: #007bff; color: white; padding: 10px 15px; border: none; border-radius: 4px; cursor: pointer; font-size: 16px; }
        button:hover { background-color: #0056b3; }
        .response { background-color: #e9ecef; padding: 15px; border-radius: 5px; margin-top: 20px; overflow-x: auto; white-space: pre-wrap; word-wrap: break-word; }
        .success { color: green; }
        .error { color: red; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Google Apps Script API Gateway</h1>

        <?php if ($response): ?>
            <h2>API Response</h2>
            <div class="response <?php echo ($response['status'] === 'success') ? 'success' : 'error'; ?>">
                <pre><?php print_r($response); ?></pre>
            </div>
        <?php endif; ?>

        <h2>1. User Authentication</h2>
        <form method="POST">
            <input type="hidden" name="action" value="authenticate">
            <label for="username">Username:</label>
            <input type="text" id="username" name="username" required>
            <label for="password">Password:</label>
            <input type="password" id="password" name="password" required>
            <button type="submit">Authenticate</button>
        </form>

        <h2>2. Token Verification</h2>
        <form method="POST">
            <input type="hidden" name="action" value="verifyToken">
            <label for="token_to_verify">Token:</label>
            <input type="text" id="token_to_verify" name="token_to_verify" required>
            <button type="submit">Verify Token</button>
        </form>

        <h2>3. Generate Token (Admin Only)</h2>
        <form method="POST">
            <input type="hidden" name="action" value="generateToken">
            <label for="admin_username">Admin Username:</label>
            <input type="text" id="admin_username" name="admin_username" required>
            <label for="admin_password">Admin Password:</label>
            <input type="password" id="admin_password" name="admin_password" required>
            <label for="token_name">Device/User Name (for token):</label>
            <input type="text" id="token_name" name="token_name" required>
            <label for="expiry_days">Expiry Days:</label>
            <input type="number" id="expiry_days" name="expiry_days" value="365" required>
            <button type="submit">Generate Token</button>
        </form>

        <h2>4. Put Log</h2>
        <form method="POST">
            <input type="hidden" name="action" value="putLog">
            <label for="log_token">Token (for logging):</label>
            <input type="text" id="log_token" name="log_token" required>
            <label for="device_id">Device ID:</label>
            <input type="text" id="device_id" name="device_id" required>
            <label for="brand">Brand:</label>
            <input type="text" id="brand" name="brand">
            <label for="sdk_version">SDK Version:</label>
            <input type="text" id="sdk_version" name="sdk_version">
            <label for="log_message">Log Message:</label>
            <textarea id="log_message" name="log_message" rows="4" required></textarea>
            <button type="submit">Submit Log</button>
        </form>

        <h2>5. Search Logs</h2>
        <form method="POST">
            <input type="hidden" name="action" value="searchLogs">
            <label for="search_query">Search Query:</label>
            <input type="text" id="search_query" name="search_query" required>
            <label for="search_column">Search Column:</label>
            <select id="search_column" name="search_column" required>
                <option value="DEVICE_ID">DEVICE_ID</option>
                <option value="BRAND">BRAND</option>
                <option value="SDK_VERSION">SDK_VERSION</option>
                <option value="LOG_MESSAGE">LOG_MESSAGE</option>
                <option value="NAME">NAME</option>
            </select>
            <button type="submit">Search Logs</button>
        </form>

    </div>
</body>
</html>