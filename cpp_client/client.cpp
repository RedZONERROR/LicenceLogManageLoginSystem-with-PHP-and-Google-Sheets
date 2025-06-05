
#include <iostream>
#include <string>
#include <curl/curl.h> // Make sure you have libcurl installed
#include <json/json.h> // Make sure you have jsoncpp installed
#include <vector>
#include "encryption.h" // For encryption/decryption placeholders

// --- CONFIGURATION ---
// !!! REPLACE WITH YOUR ACTUAL GOOGLE APPS SCRIPT WEB APP URL !!!
const std::string GAS_ENDPOINT = "YOUR_APPS_SCRIPT_WEB_APP_URL_HERE";
const std::string CPP_USER_AGENT = "MyCppClient/1.0"; // Match this in your GAS isValidUserAgent()

// Callback function to write received data to a string
size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp) {
    ((std::string*)userp)->append((char*)contents, size * nmemb);
    return size * nmemb;
}

class GasClient {
public:
    GasClient(const std::string& endpoint = GAS_ENDPOINT, const std::string& userAgent = CPP_USER_AGENT)
        : endpoint_(endpoint), userAgent_(userAgent) {
        curl_global_init(CURL_GLOBAL_DEFAULT);
    }

    ~GasClient() {
        curl_global_cleanup();
    }

    Json::Value makeRequest(const std::string& action, const std::string& method, const Json::Value& payload = Json::Value()) {
        CURL* curl;
        CURLcode res;
        std::string readBuffer;
        Json::Value response_json;

        curl = curl_easy_init();
        if (curl) {
            std::string url = endpoint_;
            std::string post_fields;

            struct curl_slist* headers = NULL;
            headers = curl_slist_append(headers, ("User-Agent: " + userAgent_).c_str());
            headers = curl_slist_append(headers, "Content-Type: application/json");

            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
            curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

            if (method == "GET") {
                url += "?action=" + action;
                for (Json::ValueConstIterator it = payload.begin(); it != payload.end(); ++it) {
                    url += "&" + it.name() + "=" + curl_easy_escape(curl, it->asString().c_str(), 0);
                }
                curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
            } else if (method == "POST") {
                Json::Value post_payload = payload;
                post_payload["action"] = action;
                post_payload["userAgent"] = userAgent_;

                // If encryption is truly implemented:
                // std::string encrypted_data = Encryption::encrypt_data(post_payload.toStyledString(), "your_secret_key");
                // post_fields = encrypted_data;
                
                Json::StreamWriterBuilder writer;
                post_fields = Json::writeString(writer, post_payload);

                curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
                curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_fields.c_str());
            } else {
                std::cerr << "Unsupported HTTP method: " << method << std::endl;
                curl_easy_cleanup(curl);
                curl_slist_free_all(headers);
                return Json::Value();
            }

            res = curl_easy_perform(curl);
            if (res != CURLE_OK) {
                std::cerr << "curl_easy_perform() failed: " << curl_easy_strerror(res) << std::endl;
                response_json["status"] = "error";
                response_json["message"] = curl_easy_strerror(res);
            } else {
                long http_code = 0;
                curl_easy_getinfo(curl, CURLINFO_HTTP_CODE, &http_code);
                if (http_code >= 400) {
                    std::cerr << "HTTP Error: " << http_code << " - " << readBuffer << std::endl;
                    response_json["status"] = "error";
                    response_json["message"] = "HTTP Error " + std::to_string(http_code) + ": " + readBuffer;
                } else {
                    // If decryption is truly implemented:
                    // std::string decrypted_response = Encryption::decrypt_data(readBuffer, "your_secret_key");
                    // Json::CharReaderBuilder reader;
                    // std::string errs;
                    // std::istringstream s(decrypted_response);
                    // if (Json::parseFromStream(reader, s, &response_json, &errs)) { ... }
                    
                    Json::CharReaderBuilder reader;
                    std::string errs;
                    std::istringstream s(readBuffer);
                    if (!Json::parseFromStream(reader, s, &response_json, &errs)) {
                        std::cerr << "Failed to parse JSON response: " << errs << std::endl;
                        response_json["status"] = "error";
                        response_json["message"] = "Invalid JSON response: " + readBuffer;
                    }
                }
            }
            curl_easy_cleanup(curl);
            curl_slist_free_all(headers);
        } else {
            std::cerr << "Failed to initialize CURL." << std::endl;
            response_json["status"] = "error";
            response_json["message"] = "Failed to initialize CURL.";
        }
        return response_json;
    }

    Json::Value authenticate(const std::string& username, const std::string& password) {
        Json::Value payload;
        payload["username"] = username;
        payload["password"] = password;
        return makeRequest("authenticate", "POST", payload);
    }

    Json::Value verifyToken(const std::string& token) {
        Json::Value payload;
        payload["token"] = token;
        return makeRequest("verifyToken", "GET", payload);
    }

    Json::Value putLog(const std::string& token, const std::string& deviceId, const std::string& logMessage,
                       const std::string& brand = "", const std::string& sdkVersion = "") {
        Json::Value payload;
        payload["token"] = token;
        payload["deviceId"] = deviceId;
        payload["logMessage"] = logMessage;
        payload["brand"] = brand;
        payload["sdkVersion"] = sdkVersion;
        return makeRequest("putLog", "POST", payload);
    }

    Json::Value searchLogs(const std::string& query, const std::string& column, int limit = 100) {
        Json::Value payload;
        payload["query"] = query;
        payload["column"] = column;
        payload["limit"] = limit;
        return makeRequest("searchLogs", "GET", payload);
    }

private:
    std::string endpoint_;
    std::string userAgent_;
};

int main() {
    GasClient client;

    // --- 1. Authenticate User ---
    std::string username, password;
    std::cout << "\n--- 1. Authenticating Admin User ---" << std::endl;
    std::cout << "Enter admin username: ";
    std::getline(std::cin, username);
    std::cout << "Enter admin password: ";
    std::getline(std::cin, password);

    Json::Value authResponse = client.authenticate(username, password);
    std::cout << "Auth Response: " << authResponse.toStyledString() << std::endl;

    std::string verifiedToken;
    if (authResponse["authenticated"].asBool()) {
        std::cout << "\n--- 2. Generating a new token (requires admin auth) ---" << std::endl;
        Json::Value genTokenPayload;
        genTokenPayload["adminUsername"] = username;
        genTokenPayload["adminPassword"] = password; // Should be handled more securely in real app
        genTokenPayload["name"] = "TestDeviceCpp";
        genTokenPayload["expiryDays"] = 365;
        Json::Value genTokenResponse = client.makeRequest("generateToken", "GET", genTokenPayload);
        std::cout << "Generate Token Response: " << genTokenResponse.toStyledString() << std::endl;
        if (genTokenResponse["status"].asString() == "success") {
            verifiedToken = genTokenResponse["token"].asString();
        }
    } else {
        std::cout << "Admin authentication failed. Cannot generate tokens." << std::endl;
    }

    // --- 3. Verify Token ---
    if (!verifiedToken.empty()) {
        std::cout << "\n--- 3. Verifying the generated token ---" << std::endl;
        Json::Value verifyResponse = client.verifyToken(verifiedToken);
        std::cout << "Verify Token Response: " << verifyResponse.toStyledString() << std::endl;

        // --- 4. Put Log ---
        std::cout << "\n--- 4. Putting a log entry ---" << std::endl;
        Json::Value putLogResponse = client.putLog(
            verifiedToken,
            "CPP_DEV_001",
            "C++ client test log message.",
            "CppBrand",
            "AndroidSDK_29"
        );
        std::cout << "Put Log Response: " << putLogResponse.toStyledString() << std::endl;

        // --- 5. Search Logs ---
        std::cout << "\n--- 5. Searching logs ---" << std::endl;
        Json::Value searchLogResponse = client.searchLogs("CPP_DEV_001", "DEVICE_ID");
        std::cout << "Search Logs Response: " << searchLogResponse.toStyledString() << std::endl;

        searchLogResponse = client.searchLogs("test log", "LOG_MESSAGE");
        std::cout << "Search Logs (by message) Response: " << searchLogResponse.toStyledString() << std::endl;
    } else {
        std::cout << "No token available for further operations." << std::endl;
    }

    std::cout << "\n--- Testing invalid token verification ---" << std::endl;
    Json::Value invalidTokenResponse = client.verifyToken("AN_INVALID_TOKEN");
    std::cout << "Invalid Token Response: " << invalidTokenResponse.toStyledString() << std::endl;

    return 0;
}