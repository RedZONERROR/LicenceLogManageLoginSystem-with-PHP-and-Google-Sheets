
// app_log_token/Code.gs

// --- CONFIGURATION ---
const SPREADSHEET_ID = 'YOUR_GOOGLE_SHEET_ID_HERE'; // !!! REPLACE WITH YOUR ACTUAL SPREADSHEET ID !!!
const TOKEN_SHEET_NAME = 'token';
const AUTH_SHEET_NAME = 'auth';
const LOG_SHEET_PREFIX = 'log_';
const MAX_LOG_SHEETS = 6; // log_0 to log_5
const LOG_RECORDS_PER_SHEET = 10000; // Max records before rotating to next log sheet

// --- GLOBAL UTILITIES ---
function getSpreadsheet() {
  return SpreadsheetApp.openById(SPREADSHEET_ID);
}

function getSheet(sheetName) {
  const ss = getSpreadsheet();
  const sheet = ss.getSheetByName(sheetName);
  if (!sheet) {
    throw new Error(`Sheet '${sheetName}' not found.`);
  }
  return sheet;
}

function getLogSheet() {
  const ss = getSpreadsheet();
  let currentLogSheetIndex = 0;
  for (let i = 0; i < MAX_LOG_SHEETS; i++) {
    const sheetName = LOG_SHEET_PREFIX + i;
    const sheet = ss.getSheetByName(sheetName);
    if (!sheet) { // If a log sheet doesn't exist, use it
      return { sheet: ss.insertSheet(sheetName), index: i };
    }
    const lastRow = sheet.getLastRow();
    if (lastRow < LOG_RECORDS_PER_SHEET + 1) { // +1 for header row
      return { sheet: sheet, index: i };
    }
    currentLogSheetIndex = (i + 1) % MAX_LOG_SHEETS; // Cycle to next sheet if full
  }
  // If all sheets are full, rotate back to the first one and clear it
  const sheetToClearName = LOG_SHEET_PREFIX + currentLogSheetIndex;
  const sheetToClear = ss.getSheetByName(sheetToClearName);
  if (sheetToClear) {
    sheetToClear.clearContents(); // CLEAR CONTENTS - BE CAREFUL!
    sheetToClear.getRange(1,1,1,7).setValues([['DEVICE_ID', 'BRAND', 'SDK_VERSION', 'LOG_MESSAGE', 'NAME', 'TIMESTAMP', 'USER_AGENT']]); // Re-add headers
    console.warn(`Log sheet ${sheetToClearName} was full and cleared.`);
    return { sheet: sheetToClear, index: currentLogSheetIndex };
  } else {
    // Should not happen if MAX_LOG_SHEETS are already created
    return { sheet: ss.insertSheet(sheetToClearName), index: currentLogSheetIndex };
  }
}

/**
 * Generates a random salt for password hashing.
 * @returns {string} A base64 encoded random salt.
 */
function generateSalt() {
  const bytes = new Uint8Array(16); // 16 bytes for a good salt
  Crypto.getRandomValues(bytes);
  return Utilities.base64Encode(bytes);
}

/**
 * Hashes a password with a given salt using SHA-256.
 * @param {string} password The plain text password.
 * @param {string} salt The base64 encoded salt.
 * @returns {string} The base64 encoded SHA-256 hash.
 */
function hashPassword(password, salt) {
  const combined = password + salt;
  const digest = Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, combined);
  return Utilities.base64Encode(digest);
}

/**
 * Validates the user agent. Customize this logic as needed.
 * @param {string} userAgent The user agent string from the request.
 * @returns {boolean} True if the user agent is valid, false otherwise.
 */
function isValidUserAgent(userAgent) {
  // Implement your custom user agent validation logic here.
  // Example: only allow requests from specific client types.
  // return userAgent && (userAgent.startsWith('MyPythonClient') || userAgent.startsWith('MyCppClient'));
  // For development, you might return true, but harden this for production.
  return true; // !!! IMPORTANT: Harden this for production !!!
}


// --- TOKEN MANAGEMENT ---
/**
 * Generates a unique token.
 * @param {string} name User/device name
 * @param {number} expiryDays Expiry in days from now
 * @param {string} userName The user who registered this token (from auth sheet)
 * @returns {string} The generated token.
 */
function generateToken(name, expiryDays, userName) {
  const tokenSheet = getSheet(TOKEN_SHEET_NAME);
  const tokenLength = 32; // Example length
  let token = '';
  do {
    token = Utilities.base64Encode(Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, Math.random().toString() + Date.now().toString())).substring(0, tokenLength);
  } while (tokenSheet.createTextFinder(token).findNext()); // Ensure uniqueness

  const registerDate = new Date();
  const expiryDate = new Date();
  expiryDate.setDate(registerDate.getDate() + expiryDays);

  tokenSheet.appendRow([name, token, registerDate.toISOString(), expiryDate.toISOString(), userName, 'active']);
  return token;
}

/**
 * Verifies a token's validity.
 * @param {string} token The token to verify.
 * @returns {object} { isValid: boolean, message: string, name: string }
 */
function verifyToken(token) {
  const tokenSheet = getSheet(TOKEN_SHEET_NAME);
  const data = tokenSheet.getDataRange().getValues();
  const headers = data[0];
  const tokenCol = headers.indexOf('TOKEN');
  const expiryCol = headers.indexOf('EXPIRY_DATE');
  const statusCol = headers.indexOf('STATUS');
  const nameCol = headers.indexOf('NAME');

  if (tokenCol === -1 || expiryCol === -1 || statusCol === -1 || nameCol === -1) {
    return { isValid: false, message: 'Invalid token sheet headers.' };
  }

  for (let i = 1; i < data.length; i++) {
    const row = data[i];
    if (row[tokenCol] === token) {
      if (row[statusCol] === 'revoked') {
        return { isValid: false, message: 'Token revoked.' };
      }
      const expiryDate = new Date(row[expiryCol]);
      if (new Date() > expiryDate) {
        // Optionally update status to 'expired'
        tokenSheet.getRange(i + 1, statusCol + 1).setValue('expired');
        return { isValid: false, message: 'Token expired.' };
      }
      return { isValid: true, message: 'Token is valid.', name: row[nameCol] };
    }
  }
  return { isValid: false, message: 'Token not found.' };
}

/**
 * Revokes a token.
 * @param {string} token The token to revoke.
 * @returns {boolean} True if revoked, false if not found.
 */
function revokeToken(token) {
  const tokenSheet = getSheet(TOKEN_SHEET_NAME);
  const data = tokenSheet.getDataRange().getValues();
  const headers = data[0];
  const tokenCol = headers.indexOf('TOKEN');
  const statusCol = headers.indexOf('STATUS');

  if (tokenCol === -1 || statusCol === -1) {
    return false;
  }

  for (let i = 1; i < data.length; i++) {
    if (data[i][tokenCol] === token) {
      tokenSheet.getRange(i + 1, statusCol + 1).setValue('revoked');
      return true;
    }
  }
  return false;
}

// --- LOG MANAGEMENT ---
/**
 * Puts a log entry into the appropriate log sheet.
 * @param {object} logData Object containing log fields (deviceId, brand, sdkVersion, logMessage, name, userAgent).
 */
function putLog(logData) {
  const { sheet, index } = getLogSheet();
  const headers = sheet.getRange(1, 1, 1, sheet.getLastColumn()).getValues()[0];
  const deviceIdCol = headers.indexOf('DEVICE_ID');
  const brandCol = headers.indexOf('BRAND');
  const sdkVersionCol = headers.indexOf('SDK_VERSION');
  const logMessageCol = headers.indexOf('LOG_MESSAGE');
  const nameCol = headers.indexOf('NAME');
  const timestampCol = headers.indexOf('TIMESTAMP');
  const userAgentCol = headers.indexOf('USER_AGENT');

  if ([deviceIdCol, brandCol, sdkVersionCol, logMessageCol, nameCol, timestampCol, userAgentCol].some(col => col === -1)) {
    throw new Error('Log sheet headers are missing or incorrect.');
  }

  const row = [];
  row[deviceIdCol] = logData.deviceId || '';
  row[brandCol] = logData.brand || '';
  row[sdkVersionCol] = logData.sdkVersion || '';
  row[logMessageCol] = logData.logMessage || '';
  row[nameCol] = logData.name || ''; // Name associated with the token/device
  row[timestampCol] = new Date().toISOString();
  row[userAgentCol] = logData.userAgent || '';

  sheet.appendRow(row);
  return `Log added to ${LOG_SHEET_PREFIX}${index}`;
}

/**
 * Searches log entries across all log sheets.
 * @param {string} query The search query.
 * @param {string} columnName The column to search in (e.g., 'DEVICE_ID', 'LOG_MESSAGE').
 * @param {number} limit Max number of results to return.
 * @returns {Array<object>} An array of matching log entries.
 */
function searchLogs(query, columnName, limit = 100) {
  const ss = getSpreadsheet();
  const results = [];
  const normalizedQuery = query.toLowerCase();

  for (let i = 0; i < MAX_LOG_SHEETS; i++) {
    const sheetName = LOG_SHEET_PREFIX + i;
    const sheet = ss.getSheetByName(sheetName);
    if (!sheet || sheet.getLastRow() < 2) continue; // Skip empty sheets

    const data = sheet.getDataRange().getValues();
    const headers = data[0];
    const targetColIndex = headers.indexOf(columnName.toUpperCase());

    if (targetColIndex === -1) {
      console.warn(`Column '${columnName}' not found in sheet '${sheetName}'.`);
      continue;
    }

    for (let r = 1; r < data.length; r++) { // Start from 1 to skip headers
      if (results.length >= limit) break; // Limit results
      const cellValue = String(data[r][targetColIndex]).toLowerCase();
      if (cellValue.includes(normalizedQuery)) {
        const rowObject = {};
        headers.forEach((header, colIdx) => {
          rowObject[header] = data[r][colIdx];
        });
        results.push(rowObject);
      }
    }
    if (results.length >= limit) break;
  }
  return results;
}

// --- AUTHENTICATION ---
/**
 * Authenticates a user by username and password.
 * @param {string} username The username.
 * @param {string} password The plain text password.
 * @param {string} userAgent The user agent from the request.
 * @returns {object} { authenticated: boolean, message: string, role: string }
 */
function authenticateUser(username, password, userAgent) {
  if (!isValidUserAgent(userAgent)) {
    return { authenticated: false, message: 'Invalid User Agent.' };
  }

  const authSheet = getSheet(AUTH_SHEET_NAME);
  const data = authSheet.getDataRange().getValues();
  const headers = data[0];
  const userCol = headers.indexOf('USERNAME');
  const passHashCol = headers.indexOf('PASSWORD_HASH');
  const saltCol = headers.indexOf('SALT');
  const roleCol = headers.indexOf('ROLE');

  if (userCol === -1 || passHashCol === -1 || saltCol === -1 || roleCol === -1) {
    throw new Error('Authentication sheet headers are missing or incorrect.');
  }

  for (let i = 1; i < data.length; i++) {
    const row = data[i];
    if (row[userCol] === username) {
      const storedHash = row[passHashCol];
      const storedSalt = row[saltCol];
      const hashedPassword = hashPassword(password, storedSalt);

      if (hashedPassword === storedHash) {
        // Update last login time if needed (optional)
        authSheet.getRange(i + 1, headers.indexOf('LAST_LOGIN') + 1).setValue(new Date().toISOString());
        return { authenticated: true, message: 'Authentication successful.', role: row[roleCol], username: username };
      } else {
        return { authenticated: false, message: 'Incorrect password.' };
      }
    }
  }
  return { authenticated: false, message: 'User not found.' };
}

/**
 * Registers a new admin/user. This function should ONLY be called by an authorized admin.
 * For initial setup, you might manually add a user, or run this function once from the editor.
 * @param {string} username
 * @param {string} password (plain text, will be hashed)
 * @param {string} email
 * @param {string} role (e.g., 'admin', 'user')
 */
function registerUser(username, password, email, role = 'user') {
  const authSheet = getSheet(AUTH_SHEET_NAME);
  const salt = generateSalt();
  const hashedPassword = hashPassword(password, salt);
  authSheet.appendRow([username, hashedPassword, salt, email, new Date().toISOString(), role]);
  console.log(`User ${username} registered successfully.`);
}

// --- WEB APP ENTRY POINT ---
/**
 * Main entry point for GET requests to the web app.
 * @param {GoogleAppsScript.Events.DoGet} e The event object containing request parameters.
 */
function doGet(e) {
  const action = e.parameter.action;
  const userAgent = e.parameter.userAgent || e.headers['User-Agent']; // Try to get user-agent from parameters or headers

  if (!action) {
    return ContentService.createTextOutput(JSON.stringify({ status: 'error', message: 'No action specified.' }))
      .setMimeType(ContentService.MimeType.JSON);
  }

  // Basic user agent check for all requests
  if (!isValidUserAgent(userAgent) && action !== 'authenticate') { // Allow 'authenticate' to pass for initial check
    return ContentService.createTextOutput(JSON.stringify({ status: 'error', message: 'Unauthorized User Agent.' }))
      .setMimeType(ContentService.MimeType.JSON);
  }

  let response = { status: 'error', message: 'Unknown error.' };

  try {
    switch (action) {
      case 'verifyToken':
        const token = e.parameter.token;
        if (!token) throw new Error('Token is required.');
        response = verifyToken(token);
        break;

      case 'searchLogs':
        const query = e.parameter.query;
        const column = e.parameter.column;
        const limit = parseInt(e.parameter.limit) || 100;
        if (!query || !column) throw new Error('Query and column are required for log search.');
        response = { status: 'success', data: searchLogs(query, column, limit) };
        break;

      case 'authenticate': // Should ideally be a POST for security
        const username = e.parameter.username;
        const password = e.parameter.password;
        if (!username || !password) throw new Error('Username and password are required.');
        response = authenticateUser(username, password, userAgent); // Pass userAgent for auth validation
        break;

      case 'generateToken': // Admin action - should be protected by authentication
        const adminAuthResult = authenticateUser(e.parameter.adminUsername, e.parameter.adminPassword, userAgent);
        if (!adminAuthResult.authenticated || adminAuthResult.role !== 'admin') {
          throw new Error('Authentication failed or not authorized to generate tokens.');
        }
        const name = e.parameter.name;
        const expiryDays = parseInt(e.parameter.expiryDays);
        if (!name || isNaN(expiryDays)) throw new Error('Name and expiryDays are required.');
        response = { status: 'success', token: generateToken(name, expiryDays, adminAuthResult.username) };
        break;

      case 'revokeToken': // Admin action - should be protected by authentication
        const adminRevokeAuthResult = authenticateUser(e.parameter.adminUsername, e.parameter.adminPassword, userAgent);
        if (!adminRevokeAuthResult.authenticated || adminRevokeAuthResult.role !== 'admin') {
          throw new Error('Authentication failed or not authorized to revoke tokens.');
        }
        const tokenToRevoke = e.parameter.token;
        if (!tokenToRevoke) throw new Error('Token to revoke is required.');
        response = { status: 'success', revoked: revokeToken(tokenToRevoke) };
        break;

      default:
        response = { status: 'error', message: 'Invalid action.' };
    }
  } catch (error) {
    response = { status: 'error', message: error.message };
    console.error(`Error in doGet for action ${action}: ${error.message}`);
  }

  return ContentService.createTextOutput(JSON.stringify(response))
    .setMimeType(ContentService.MimeType.JSON);
}

/**
 * Main entry point for POST requests to the web app.
 * Used for submitting data, e.g., logging or authenticated actions.
 * @param {GoogleAppsScript.Events.DoPost} e The event object containing request parameters and post data.
 */
function doPost(e) {
  let requestData;
  try {
    requestData = JSON.parse(e.postData.contents);
  } catch (error) {
    return ContentService.createTextOutput(JSON.stringify({ status: 'error', message: 'Invalid JSON payload.' }))
      .setMimeType(ContentService.MimeType.JSON);
  }

  const action = requestData.action;
  const userAgent = requestData.userAgent || e.headers['User-Agent'];

  if (!action) {
    return ContentService.createTextOutput(JSON.stringify({ status: 'error', message: 'No action specified.' }))
      .setMimeType(ContentService.MimeType.JSON);
  }

  if (!isValidUserAgent(userAgent)) {
    return ContentService.createTextOutput(JSON.stringify({ status: 'error', message: 'Unauthorized User Agent.' }))
      .setMimeType(ContentService.MimeType.JSON);
  }

  let response = { status: 'error', message: 'Unknown error.' };

  try {
    switch (action) {
      case 'putLog':
        // For log submission, we typically verify token first.
        const token = requestData.token;
        if (!token) throw new Error('Token is required for logging.');
        const verification = verifyToken(token);
        if (!verification.isValid) {
          throw new Error(`Token verification failed: ${verification.message}`);
        }
        const logData = {
          deviceId: requestData.deviceId,
          brand: requestData.brand,
          sdkVersion: requestData.sdkVersion,
          logMessage: requestData.logMessage,
          name: verification.name, // Use the name associated with the valid token
          userAgent: userAgent
        };
        response = { status: 'success', message: putLog(logData) };
        break;

      case 'authenticate': // POST is preferred for authentication
        const username = requestData.username;
        const password = requestData.password;
        if (!username || !password) throw new Error('Username and password are required.');
        response = authenticateUser(username, password, userAgent);
        break;

      // Add other actions that require POST (e.g., creating new users, protected by admin auth)
      // case 'registerAdminUser': // Example for setting up initial admin user
      //   const authKey = requestData.authKey; // A pre-shared secret for initial admin setup
      //   if (authKey !== 'YOUR_SECRET_KEY') { // DANGER: For initial setup only, hardcode this
      //     throw new Error('Unauthorized for admin registration.');
      //   }
      //   registerUser(requestData.username, requestData.password, requestData.email, 'admin');
      //   response = { status: 'success', message: 'Admin user registered.' };
      //   break;

      default:
        response = { status: 'error', message: 'Invalid action.' };
    }
  } catch (error) {
    response = { status: 'error', message: error.message };
    console.error(`Error in doPost for action ${action}: ${error.message}`);
  }

  return ContentService.createTextOutput(JSON.stringify(response))
    .setMimeType(ContentService.MimeType.JSON);
}

// --- ENCRYPTION (Placeholder - requires client-side matching) ---
// This is a conceptual placeholder. Real-world secure communication encryption
// would involve a robust symmetric key algorithm (e.g., AES) implemented on both client and server.
// The key exchange would need careful consideration (e.g., securely pre-sharing a key,
// or using a hybrid approach with asymmetric encryption for key exchange).

// For a basic example, we might just base64 encode/decode, but this is NOT encryption.
// Real encryption is beyond a simple GAS script's direct cryptographic capabilities for full end-to-end.
// GAS's HTTPS secures the transport layer. For payload, you'd need a shared secret key and a library.

/*
function encryptPayload(plainText, key) {
  // Placeholder: Implement actual symmetric encryption (e.g., AES)
  // This would typically involve a library if GAS offered direct AES, or a custom implementation.
  // For demonstration, we'll just base64 encode. This is NOT secure encryption.
  return Utilities.base64Encode(Utilities.newBlob(plainText).getBytes());
}

function decryptPayload(cipherText, key) {
  // Placeholder: Implement actual symmetric decryption
  // For demonstration, we'll just base64 decode. This is NOT secure decryption.
  return Utilities.newBlob(Utilities.base64Decode(cipherText)).getDataAsString();
}
*/