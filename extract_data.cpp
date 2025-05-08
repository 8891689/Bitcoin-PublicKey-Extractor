// g++ extract_data.cpp -lcurl -pthread -Wall -Wextra -O3 -march=native -o extract_data
// author：https://github.com/8891689
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip> // for std::hex, std::setw, std::setfill
#include <stdexcept> // for exceptions
#include <thread>
#include <mutex>
#include <atomic> // for atomic counters
#include <condition_variable> // For more complex synchronization if needed
#include <unordered_set> // for key uniqueness
#include <regex> // C++11 regex
#include <chrono> // for timing
#include <limits> // for numeric_limits
#include <cmath> // for std::max
#include <cstdlib> // for exit, EXIT_FAILURE
#include <ctime> // for time_t in logging
#include <algorithm> // for std::min

// Need libcurl for HTTP requests
#include <curl/curl.h>

// Need nlohmann/json for JSON parsing
// Download json.hpp and place it where your compiler can find it
#include "json.h" // Path might need adjustment depending on where you put json.hpp
using json = nlohmann::json; // Use alias for easier access

// ANSI colors (Optional) - Check if your terminal supports them
// On Windows, you might need to enable ANSI escape codes programmatically (or use a library like ANSICON)
const std::string C_RED = "\x1b[31m";
const std::string C_GREEN = "\x1b[32m";
const std::string C_YELLOW = "\x1b[33m";
const std::string C_MAGENTA = "\x1b[35m";
const std::string C_CYAN = "\x1b[36m";
const std::string C_RESET = "\x1b[0m";

// Bitcoin script opcodes
const unsigned char OP_PUSHDATA1 = 0x4c;
const unsigned char OP_PUSHDATA2 = 0x4d;
const unsigned char OP_PUSHDATA4 = 0x4e;
const unsigned char OP_0       = 0x00;

// Global RPC config
struct RpcConfig {
    std::string host = "127.0.0.1";
    int port = 8332;
    std::string user;
    std::string password;
    int num_workers = 1;
    std::string url; // Constructed from host and port
};

RpcConfig g_rpc_config;
const std::string RPC_CONFIG_FILE = "rpc_config.json";
const std::string LOG_FILE = "block_processing.log";


// Global state for RPC error handling and total keys
std::mutex g_state_mutex; // Protects console output and file writing (including output file and log file)
std::atomic<int> g_rpc_consecutive_failures = 0; // Atomic is sufficient for simple increments/reads
const int RPC_FAILURE_THRESHOLD = 10;

std::atomic<long long> g_total_keys_extracted_value = 0;
std::atomic<int> g_processed_blocks_count = 0; // Blocks successfully processed or skipped due to RPC failure

// Output file handle (protected by g_state_mutex)
std::ofstream g_output_file;

// Log file handle (protected by g_state_mutex - simpler to use one mutex for both files and console)
std::ofstream g_log_file;


// Regex for pubkey validation
std::regex g_pubkey_regex;
bool g_regex_compiled = false;
std::mutex g_regex_mutex; // Protects regex compilation if called lazily


// Helper to convert thread ID to string
std::string thread_id_to_string(std::thread::id id) {
    std::stringstream ss;
    ss << id;
    return ss.str();
}

// Helper function for basic logging (thread-safe)
void log_message(const std::string& level, const std::string& message) {
    auto now = std::chrono::system_clock::now();
    auto time_t_now = std::chrono::system_clock::to_time_t(now);
    std::stringstream ss;
    // Format for log file and console
    ss << std::put_time(std::localtime(&time_t_now), "%Y-%m-%d %H:%M:%S") << " - " << level << " - " << message;
    std::string formatted_message = ss.str();

    // Use a single mutex to protect both file and console output streams
    std::lock_guard<std::mutex> lock(g_state_mutex);

    // Write to log file (if open)
    if (g_log_file.is_open()) {
        g_log_file << formatted_message << std::endl;
        // Consider flushing periodically for file logging, but std::endl usually flushes lines
    }

    // Write to console (stderr) based on level
    // Only print ERROR and CRITICAL to console log lines
    if (level == "ERROR" || level == "CRITICAL") {
        std::cerr << formatted_message << std::endl;
    }
    // INFO, WARNING, DEBUG messages will only appear in the log file
}

// Helper to compile regex (call once at startup)
void compile_pubkey_regex() {
    std::lock_guard<std::mutex> lock(g_regex_mutex);
    if (g_regex_compiled) return;

    // Compressed: 33 bytes (66 hex), starts with 02 or 03
    // Uncompressed: 65 bytes (130 hex), starts with 04
    const std::string pattern = "^(02|03)[0-9a-fA-F]{64}$|^04[0-9a-fA-F]{128}$";
    try {
        g_pubkey_regex.assign(pattern, std::regex_constants::extended | std::regex_constants::icase);
        g_regex_compiled = true;
        log_message("INFO", "Successfully compiled regex.");
        std::cerr << C_GREEN << "Successfully compiled regex." << C_RESET << std::endl; // Also print to console
    } catch (const std::regex_error& e) {
        log_message("CRITICAL", C_RED + "Failed to compile regex: " + e.what() + C_RESET);
        std::cerr << C_RED << "Failed to compile regex: " << e.what() << C_RESET << std::endl; // Also print to console
        exit(EXIT_FAILURE); // Critical failure, cannot proceed
    }
}

// Helper to check pubkey format
bool is_valid_pubkey_hex(const std::string& hex_string) {
    if (!g_regex_compiled) {
        // Should be compiled in main before threads start, but check defensively
        log_message("WARNING", "Regex not compiled when is_valid_pubkey_hex called!");
        return false;
    }
    if (hex_string.empty()) return false;
    try {
         return std::regex_match(hex_string, g_pubkey_regex);
    } catch (const std::regex_error& e) {
         // Should not happen if regex is compiled correctly, but regex_match can throw
         log_message("ERROR", "Regex matching error: " + std::string(e.what()));
         return false;
    }
}

// Helper function to convert hex string to byte vector
std::vector<unsigned char> hex_to_bytes(const std::string& hex) {
    std::vector<unsigned char> bytes;
    if (hex.length() % 2 != 0) {
        // Invalid hex string length
        return bytes; // Return empty vector
    }
    bytes.reserve(hex.length() / 2);
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        try {
            unsigned int byte_val;
            std::stringstream ss;
            ss << std::hex << byteString;
            ss >> byte_val;
            bytes.push_back(static_cast<unsigned char>(byte_val));
        } catch (const std::exception& e) {
            // Invalid hex characters
            log_message("WARNING", "Thread " + thread_id_to_string(std::this_thread::get_id()) + ": Invalid hex character in string: " + hex.substr(i, 2));
            bytes.clear(); // Indicate failure
            break;
        }
    }
    return bytes;
}

// Helper function to convert byte vector to hex string
std::string bytes_to_hex(const std::vector<unsigned char>& bytes) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (unsigned char b : bytes) {
        ss << std::setw(2) << static_cast<int>(b);
    }
    return ss.str();
}

// Parse script hex string into data pushes
std::vector<std::string> parse_script_hex(const std::string& script_hex) {
    std::vector<std::string> data_pushes;
    std::vector<unsigned char> script_bytes = hex_to_bytes(script_hex);
    if (script_bytes.empty() && !script_hex.empty()) {
         // hex_to_bytes failed due to invalid hex string
         log_message("WARNING", "Thread " + thread_id_to_string(std::this_thread::get_id()) + ": Script parse error: Invalid hex string: " + script_hex.substr(0, std::min((size_t)100, script_hex.length())) + "...");
         return data_pushes; // Return empty
    }

    size_t pos = 0;
    while (pos < script_bytes.size()) {
        unsigned char opcode = script_bytes[pos];
        pos++;
        size_t data_len = 0;
        const unsigned char* data_ptr = nullptr;
        bool is_push = false;
        size_t len_field_size = 0; // Size of the length field for this push opcode

        if (opcode == OP_0) {
            data_len = 0;
            data_ptr = nullptr; // No actual data to read
            is_push = true;
        } else if (opcode >= 0x01 && opcode <= 0x4b) { // OP_PUSHBYTES_1 to OP_PUSHBYTES_75
            data_len = opcode;
            data_ptr = script_bytes.data() + pos;
            pos += data_len;
            is_push = true;
            len_field_size = 0; // Length is the opcode itself
        } else if (opcode == OP_PUSHDATA1) {
             len_field_size = 1;
             if (pos + len_field_size > script_bytes.size()) {
                 log_message("WARNING", "Thread " + thread_id_to_string(std::this_thread::get_id()) + ": Script parse error: Missing PUSHDATA1 length byte. Script: " + script_hex.substr(0, std::min((size_t)100, script_hex.length())) + "..., pos: " + std::to_string((pos - 1) * 2) + ".");
                 break; // Stop parsing
             }
             data_len = script_bytes[pos];
             pos += len_field_size;
             data_ptr = script_bytes.data() + pos;
             pos += data_len;
             is_push = true;
        } else if (opcode == OP_PUSHDATA2) {
             len_field_size = 2;
             if (pos + len_field_size > script_bytes.size()) {
                 log_message("WARNING", "Thread " + thread_id_to_string(std::this_thread::get_id()) + ": Script parse error: Missing PUSHDATA2 length bytes. Script: " + script_hex.substr(0, std::min((size_t)100, script_hex.length())) + "..., pos: " + std::to_string((pos - 1) * 2) + ".");
                 break; // Stop parsing
             }
             // Read 2 bytes little endian
             data_len = script_bytes[pos] | (script_bytes[pos+1] << 8);
             pos += len_field_size;
             data_ptr = script_bytes.data() + pos;
             pos += data_len;
             is_push = true;
        } else if (opcode == OP_PUSHDATA4) {
             len_field_size = 4;
             if (pos + len_field_size > script_bytes.size()) {
                 log_message("WARNING", "Thread " + thread_id_to_string(std::this_thread::get_id()) + ": Script parse error: Missing PUSHDATA4 length bytes. Script: " + script_hex.substr(0, std::min((size_t)100, script_hex.length())) + "..., pos: " + std::to_string((pos - 1) * 2) + ".");
                 break; // Stop parsing
             }
             // Read 4 bytes little endian
             data_len = script_bytes[pos] | (script_bytes[pos+1] << 8) | (script_bytes[pos+2] << 16) | (static_cast<size_t>(script_bytes[pos+3]) << 24); // Cast pos+3 to size_t before shift
             pos += len_field_size;
             data_ptr = script_bytes.data() + pos;
             pos += data_len;
             is_push = true;
        } else {
            // Non-push opcode, just skip the opcode byte itself (pos already incremented)
            // For a full parser, you'd decode the opcode and its size
            // Assuming basic opcodes are 1 byte if not a known push opcode.
        }

        // Check if reading data goes past script length (for push opcodes)
        // Adjusted check to be relative to the start of the data segment
        if (is_push && data_ptr && (data_ptr + data_len > script_bytes.data() + script_bytes.size())) {
             log_message("WARNING", "Thread " + thread_id_to_string(std::this_thread::get_id()) + ": Script parse error: Data push (len " + std::to_string(data_len) + ") goes past end of script. Script: " + script_hex.substr(0, std::min((size_t)100, script_hex.length())) + "..., opcode pos: " + std::to_string((pos - data_len - len_field_size -1) * 2) + ", data starts at byte " + std::to_string(pos - data_len) + ", script size " + std::to_string(script_bytes.size()));
             break; // Stop parsing this script
        }


        // Add data push to the list
        if (is_push) {
            if (data_len > 0 && data_ptr) {
                 std::vector<unsigned char> data_vec(data_ptr, data_ptr + data_len);
                 data_pushes.push_back(bytes_to_hex(data_vec));
            } else { // OP_0 or empty push
                 data_pushes.push_back("");
            }
        }
    }
    return data_pushes;
}

// Recursive helper to extract pubkeys from a script hex, including potential nested scripts
// Returns a set of unique pubkey strings
std::unordered_set<std::string> extract_pubkeys_recursive(const std::string& script_hex, int depth = 0) {
    std::unordered_set<std::string> found_pubkeys;
    if (depth > 10) { // Prevent infinite recursion for malicious scripts
        log_message("WARNING", "Thread " + thread_id_to_string(std::this_thread::get_id()) + ": Max recursion depth reached in extract_pubkeys_recursive for script: " + script_hex.substr(0, std::min((size_t)100, script_hex.length())) + "...");
        return found_pubkeys;
    }

    std::vector<std::string> pushed_data = parse_script_hex(script_hex);

    for (size_t i = 0; i < pushed_data.size(); ++i) {
        const std::string& data_hex = pushed_data[i];

        // 1. Check if the push itself is a valid pubkey
        if (is_valid_pubkey_hex(data_hex)) {
            found_pubkeys.insert(data_hex);
        }

        // 2. Check if this push could be a nested script (Redeem Script or Witness Script)
        // Original Python logic only checks the *last* push for redeem/witness script.
        // Let's follow that for direct translation fidelity, although a more robust
        // parser might identify known script types (P2SH, P2WSH) and parse the correct push.
        if (i == pushed_data.size() - 1 && // Is the last push?
            !is_valid_pubkey_hex(data_hex) && // Is NOT already a pubkey
            data_hex.length() >= 4 && data_hex.length() % 2 == 0) // Looks like potential hex data
        {
             // Recursively try to parse this push's data as a script
             std::unordered_set<std::string> nested_keys = extract_pubkeys_recursive(data_hex, depth + 1);
             found_pubkeys.insert(nested_keys.begin(), nested_keys.end());
        }
    }

    return found_pubkeys;
}


// --- RPC Request Function ---
// Helper function required by libcurl to write received data
size_t my_curl_write_callback(char* contents, size_t size, size_t nmemb, void* userp) {
    static_cast<std::string*>(userp)->append(contents, size * nmemb);
    return size * nmemb;
}

// RPC call wrapper
// Returns nlohmann::json object on success.
// Returns nlohmann::json() (null type) on ignorable errors or other non-threshold errors.
// Throws std::runtime_error on critical errors or threshold failures after waiting.
json rpc_request(const std::string& method, const json& params) {
    CURL* curl = nullptr;
    CURLcode res = CURLE_OK;
    std::string read_buffer;

    // Build JSON payload using nlohmann::json
    json payload;
    payload["jsonrpc"] = "1.0";
    payload["id"] = "curl_rpc_req_" + thread_id_to_string(std::this_thread::get_id()) + "_" + std::to_string(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count()); // Add timestamp
    payload["method"] = method;
    payload["params"] = params;
    std::string payload_str = payload.dump(); // Serialize JSON to string

    // Retry loop
    int attempt = 0;
    const int max_attempts = 5;

    while (attempt < max_attempts) {
        curl = curl_easy_init();
        if (!curl) {
            // Critical initialization error
            log_message("CRITICAL", C_RED + "Thread " + thread_id_to_string(std::this_thread::get_id()) + ": CURL easy init failed!" + C_RESET);
            throw std::runtime_error("CURL easy init failed"); // Cannot proceed
        }

        read_buffer.clear(); // Clear buffer for retry

        std::string auth_string = g_rpc_config.user + ":" + g_rpc_config.password;
        curl_easy_setopt(curl, CURLOPT_URL, g_rpc_config.url.c_str());
        curl_easy_setopt(curl, CURLOPT_USERPWD, auth_string.c_str());
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payload_str.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, my_curl_write_callback); // Correctly passing function pointer with new name
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &read_buffer);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 120L); // 120 seconds timeout

        res = curl_easy_perform(curl);
        curl_easy_cleanup(curl); // Clean up handle after each attempt

        if (res != CURLE_OK) {
            // HTTP/Network level error
            log_message("ERROR", "Thread " + thread_id_to_string(std::this_thread::get_id()) + ": RPC request failed (" + method + ", attempt " + std::to_string(attempt + 1) + "/" + std::to_string(max_attempts) + "): " + curl_easy_strerror(res));

            g_rpc_consecutive_failures.fetch_add(1, std::memory_order_seq_cst);
            int current_failures = g_rpc_consecutive_failures.load(std::memory_order_seq_cst);

            if (current_failures >= RPC_FAILURE_THRESHOLD) {
                 // Threshold reached due to network error
                 log_message("CRITICAL", "\nRPC connection consecutive failures (" + std::to_string(RPC_FAILURE_THRESHOLD) + ") reached due to network error. Please check your node and config.");
                 std::cerr << "\n" << C_RED << "RPC connection consecutive failures (" << RPC_FAILURE_THRESHOLD << ") reached due to network error. Please check your node and config." << C_RESET << std::endl;
                 std::cerr << C_YELLOW << "Press ENTER to continue... (or press Ctrl+C to exit)" << C_RESET << std::endl;

                 // --- Wait for user input ---
                 // WARNING: std::cin is NOT THREAD-SAFE. Locking access as a workaround.
                 try {
                     std::lock_guard<std::mutex> lock(g_state_mutex); // Lock while reading from cin
                     std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n'); // Clear buffer
                     std::cin.get(); // Wait for Enter key
                 } catch (const std::exception& e) {
                     log_message("CRITICAL", "Error waiting for user input: " + std::string(e.what()));
                     throw std::runtime_error("Error waiting for user input: " + std::string(e.what()));
                 }

                 // After waiting, reset the counter and retry
                 g_rpc_consecutive_failures.store(0, std::memory_order_seq_cst);
                 std::cerr << C_YELLOW << "Continuing execution..." << C_RESET << std::endl;
                 log_message("INFO", "RPC failure counter reset, continuing execution.");
                 std::this_thread::sleep_for(std::chrono::seconds(2));
                 attempt++; // Move to next attempt in the loop
                 continue; // Go to start of while loop
            }

            // Not reached threshold, just a regular network failure retry
            std::this_thread::sleep_for(std::chrono::seconds(10));
            attempt++;
            continue; // Go to start of while loop
        }

        // HTTP request was successful, now parse JSON response
        json response_json;
        try {
            // Use json::parse
            response_json = json::parse(read_buffer); // Correctly call the parse function
        } catch (const json::parse_error& e) {
             // JSON parsing error
             log_message("ERROR", "Thread " + thread_id_to_string(std::this_thread::get_id()) + ": Failed to parse RPC response JSON (" + method + ", attempt " + std::to_string(attempt + 1) + "/" + std::to_string(max_attempts) + "): " + e.what() + ". Response (first 200 chars): " + read_buffer.substr(0, std::min((size_t)200, read_buffer.length())) + "...");

             g_rpc_consecutive_failures.fetch_add(1, std::memory_order_seq_cst);
             int current_failures = g_rpc_consecutive_failures.load(std::memory_order_seq_cst);

             if (current_failures >= RPC_FAILURE_THRESHOLD) {
                  // Threshold reached due to JSON parsing error
                  log_message("CRITICAL", "\nRPC consecutive JSON parse failures (" + std::to_string(RPC_FAILURE_THRESHOLD) + ") reached. Please check RPC server response.");
                  std::cerr << "\n" << C_RED << "RPC consecutive JSON parse failures (" << RPC_FAILURE_THRESHOLD << ") reached. Please check RPC server response." << C_RESET << std::endl;
                  std::cerr << C_YELLOW << "Press ENTER to continue... (or press Ctrl+C to exit)" << C_RESET << std::endl;

                   // --- Wait for user input ---
                   try {
                       std::lock_guard<std::mutex> lock(g_state_mutex); // Lock while reading from cin
                       std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
                       std::cin.get();
                   } catch (const std::exception& e_wait) {
                        log_message("CRITICAL", "Error waiting for user input after JSON error: " + std::string(e_wait.what()));
                        throw std::runtime_error("Error waiting for user input: " + std::string(e_wait.what()));
                   }

                   // After waiting, reset the counter and retry
                   g_rpc_consecutive_failures.store(0, std::memory_order_seq_cst);
                   std::cerr << C_YELLOW << "Continuing execution..." << C_RESET << std::endl;
                   log_message("INFO", "RPC failure counter reset, continuing execution.");
                   std::this_thread::sleep_for(std::chrono::seconds(2));
                   attempt++; // Move to next attempt
                   continue; // Go to start of while loop

             }
             // Not reached threshold, regular parse failure retry
             std::this_thread::sleep_for(std::chrono::seconds(10));
             attempt++;
             continue; // Go to start of while loop
        }

        // JSON parsed successfully, check for RPC error field
        if (response_json.contains("error") && !response_json["error"].is_null()) {
            const auto& error = response_json["error"];
            std::string error_message = error.contains("message") ? error["message"].get<std::string>() : "Unknown error";
            int error_code = error.contains("code") ? error["code"].get<int>() : -9999;

            // Check ignorable errors
            bool is_ignorable = false;
            // Common ignorable errors: -5 (Invalid address), -8 (Invalid parameter, maybe bad txid format), -25 (Missing inputs for signing), -3 (Invalid/missing hex, e.g. in getrawtransaction with verbose=true for invalid txid)
            // Check for "No such mempool or blockchain transaction" specifically
            if (error_code == -5 || error_code == -8 || error_code == -25 || error_code == -3 ||
                error_message.find("No such mempool or blockchain transaction") != std::string::npos ||
                error_message.find("Transaction not found") != std::string::npos) // Bitcoind 24+ might use "Transaction not found"
            {
                 is_ignorable = true;
            }

            if (is_ignorable) {
                log_message("WARNING", "Thread " + thread_id_to_string(std::this_thread::get_id()) + ": RPC error (ignorable) (" + method + "): Code " + std::to_string(error_code) + ", Msg: " + error_message);
                // Ignorable error. Reset consecutive failure count as we got a valid RPC response, but signal skip to caller.
                g_rpc_consecutive_failures.store(0, std::memory_order_seq_cst);
                return nullptr; // Indicate ignorable error / skip by returning a null JSON value
            } else {
                 // Non-ignorable RPC error
                 log_message("ERROR", "Thread " + thread_id_to_string(std::this_thread::get_id()) + ": RPC error (" + method + ", attempt " + std::to_string(attempt + 1) + "/" + std::to_string(max_attempts) + "): Code " + std::to_string(error_code) + ", Msg: " + error_message);

                 g_rpc_consecutive_failures.fetch_add(1, std::memory_order_seq_cst);
                 int current_failures = g_rpc_consecutive_failures.load(std::memory_order_seq_cst);

                 if (current_failures >= RPC_FAILURE_THRESHOLD) {
                      // Threshold reached due to non-ignorable RPC error
                      log_message("CRITICAL", "\nRPC consecutive errors (" + std::to_string(RPC_FAILURE_THRESHOLD) + ") reached. Please check your node logs.");
                      std::cerr << "\n" << C_RED << "RPC consecutive errors (" << RPC_FAILURE_THRESHOLD << ") reached. Please check your node logs." << C_RESET << std::endl;
                      std::cerr << C_YELLOW << "Press ENTER to continue... (or press Ctrl+C to exit)" << C_RESET << std::endl;
                       // --- Wait for user input ---
                       try {
                           std::lock_guard<std::mutex> lock(g_state_mutex); // Lock while reading from cin
                           std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
                           std::cin.get();
                       } catch (const std::exception& e_wait) {
                            log_message("CRITICAL", "Error waiting for user input after RPC error: " + std::string(e_wait.what()));
                            throw std::runtime_error("Error waiting for user input: " + std::string(e_wait.what()));
                       }

                       // After waiting, reset the counter and retry
                       g_rpc_consecutive_failures.store(0, std::memory_order_seq_cst);
                       std::cerr << C_YELLOW << "Continuing execution..." << C_RESET << std::endl;
                       log_message("INFO", "RPC failure counter reset, continuing execution.");
                       std::this_thread::sleep_for(std::chrono::seconds(2));
                       attempt++; // Move to next attempt
                       continue; // Go to start of while loop
                 }

                 // Not reached threshold, regular RPC error retry
                 std::this_thread::sleep_for(std::chrono::seconds(10));
                 attempt++;
                 continue; // Go to start of while loop
            }
        }

        // Success! No HTTP, JSON, or RPC error. Reset failure counter.
        g_rpc_consecutive_failures.store(0, std::memory_order_seq_cst);

        if (response_json.contains("result")) {
             return response_json["result"]; // Return the result JSON object
        } else {
             // RPC success but result is missing (might happen for some methods like sendrawtransaction)
             log_message("WARNING", "Thread " + thread_id_to_string(std::this_thread::get_id()) + ": RPC result field missing for method " + method);
             return nullptr; // Indicate success but no meaningful result
        }

    } // End retry while loop

    // If loop finishes, all attempts failed after handling threshold waits
    log_message("CRITICAL", "Thread " + thread_id_to_string(std::this_thread::get_id()) + ": RPC request failed after all attempts (" + method + "). Giving up on this call.");
    // Indicate final failure by throwing, as waits were handled and it still failed
    throw std::runtime_error("RPC request failed after multiple retries and waits: " + method);
}

// Get block hash (wraps rpc_request and checks result)
// Returns block hash string on success, empty string on failure/skip
std::string get_block_hash(int block_height) {
    json params = {block_height};
    json result;
    try {
       result = rpc_request("getblockhash", params);
    } catch (const std::exception& e) {
        // Propagate critical errors from rpc_request up
        throw;
    }


    if (result.is_null()) {
        // RPC was ignorable error or had no result field (treated as skip)
        return "";
    }
    if (result.is_string()) {
        return result.get<std::string>();
    }

    // If result is not string or null, it's an unexpected success result type
    log_message("ERROR", "Thread " + thread_id_to_string(std::this_thread::get_id()) + ": getblockhash returned unexpected result type for block " + std::to_string(block_height) + ": " + result.type_name());
    return ""; // Indicate failure due to unexpected type
}

// Get block data (wraps rpc_request and checks result)
// Returns block JSON object on success, null JSON object on failure/skip
json get_block(const std::string& block_hash) {
     if (block_hash.empty()) return nullptr; // Don't request if hash is empty

    json params = {block_hash, 2}; // verbosity 2
    json result;
    try {
       result = rpc_request("getblock", params);
    } catch (const std::exception& e) {
        // Propagate critical errors from rpc_request up
        throw;
    }


    if (result.is_null()) {
        // RPC was ignorable error or had no result field (treated as skip)
        return nullptr;
    }
    if (result.is_object()) {
        return result; // Return the block JSON object
    }
    // If result is not object or null, it's an unexpected success result type
    log_message("ERROR", "Thread " + thread_id_to_string(std::this_thread::get_id()) + ": getblock returned unexpected result type for hash " + block_hash + ": " + result.type_name());
    return nullptr; // Indicate failure due to unexpected type
}

// Load RPC config from JSON file
int load_rpc_config(const std::string& filename) {
    std::ifstream config_file(filename);
    if (!config_file.is_open()) {
        log_message("CRITICAL", C_RED + "Error: Could not open RPC config file: " + filename + C_RESET);
        std::cerr << C_RED + "Error: Could not open RPC config file: " << filename << C_RESET << std::endl;
        return -1;
    }

    try {
        json config_json = json::parse(config_file);

        if (config_json.contains("rpc_host") && config_json["rpc_host"].is_string())
            g_rpc_config.host = config_json["rpc_host"].get<std::string>();
        if (config_json.contains("rpc_port") && config_json["rpc_port"].is_number_integer())
            g_rpc_config.port = config_json["rpc_port"].get<int>();
        if (config_json.contains("rpc_user") && config_json["rpc_user"].is_string())
            g_rpc_config.user = config_json["rpc_user"].get<std::string>();
        if (config_json.contains("rpc_password") && config_json["rpc_password"].is_string())
            g_rpc_config.password = config_json["rpc_password"].get<std::string>();
        if (config_json.contains("num_workers") && config_json["num_workers"].is_number_integer())
             g_rpc_config.num_workers = std::max(1, config_json["num_workers"].get<int>()); // Ensure at least 1 worker

        if (g_rpc_config.user.empty() || g_rpc_config.password.empty()) {
            log_message("CRITICAL", C_RED + "Error: RPC user and password must be specified in the config file." + C_RESET);
            std::cerr << C_RED + "Error: RPC user and password must be specified in the config file." << C_RESET << std::endl;
            return -1;
        }

        g_rpc_config.url = "http://" + g_rpc_config.host + ":" + std::to_string(g_rpc_config.port);

        log_message("INFO", "Successfully loaded RPC config. RPC URL: " + g_rpc_config.url + ", Workers: " + std::to_string(g_rpc_config.num_workers));
        std::cerr << C_GREEN << "Successfully loaded RPC config." << C_RESET << " RPC URL: " << g_rpc_config.url << std::endl; // Also print to console
        std::cerr << C_CYAN << "Using " << g_rpc_config.num_workers << " worker threads." << C_RESET << std::endl; // Also print to console


    } catch (const json::parse_error& e) {
        log_message("CRITICAL", C_RED + "Error: Invalid JSON in RPC config file " + filename + ": " + e.what() + C_RESET);
        std::cerr << C_RED + "Error: Invalid JSON in RPC config file " + filename + ": " + e.what() + C_RESET << std::endl; // Also print to console
        return -1;
    } catch (const std::exception& e) {
         log_message("CRITICAL", C_RED + "Unknown error loading RPC config: " + e.what() + C_RESET);
         std::cerr << C_RED + "Unknown error loading RPC config: " + std::string(e.what()) + C_RESET << std::endl; // Also print to console
         return -1;
    }

    return 0;
}


// Worker thread function to process blocks
void process_block_worker(int start_block, int end_block, std::atomic<int>& next_block_index) {
    while (true) {
        int current_block_height;
        // Atomically get the next index and increment it. memory_order_seq_cst ensures total order.
        int index_to_process = next_block_index.fetch_add(1, std::memory_order_seq_cst);

        current_block_height = start_block + index_to_process;

        if (current_block_height > end_block) {
            break; // No more blocks to process
        }

        log_message("INFO", "Thread " + thread_id_to_string(std::this_thread::get_id()) + ": Starting block " + std::to_string(current_block_height));

        std::string block_hash;
        try {
            block_hash = get_block_hash(current_block_height);
        } catch (const std::exception& e) {
             // rpc_request for get_block_hash threw a critical error (e.g. Curl init failed, or threshold reached and wait failed)
             log_message("CRITICAL", "Thread " + thread_id_to_string(std::this_thread::get_id()) + ": Critical error getting block hash " + std::to_string(current_block_height) + ": " + e.what());
             // In a production app, you'd likely want to signal a global shutdown requested flag here.
             // For this example, just log and let the thread possibly exit or continue trying next block.
             g_processed_blocks_count.fetch_add(1, std::memory_order_seq_cst); // Count as processed/skipped
             continue; // Try to get the next block if thread survives
        }


        if (block_hash.empty()) {
            log_message("WARNING", "Thread " + thread_id_to_string(std::this_thread::get_id()) + ": Skipping block " + std::to_string(current_block_height) + " due to failure getting hash or ignorable RPC error.");
            g_processed_blocks_count.fetch_add(1, std::memory_order_seq_cst); // Count as processed/skipped
            continue; // Move to next block
        }

        json block_json;
        try {
            block_json = get_block(block_hash);
        } catch (const std::exception& e) {
             // rpc_request for get_block threw a critical error
             log_message("CRITICAL", "Thread " + thread_id_to_string(std::this_thread::get_id()) + ": Critical error getting block data " + std::to_string(current_block_height) + " (" + block_hash + "): " + e.what());
             g_processed_blocks_count.fetch_add(1, std::memory_order_seq_cst); // Count as processed/skipped
             continue; // Try to get the next block
        }


        if (block_json.is_null()) { // Check if get_block returned a null JSON object (indicating skip/ignorable error)
             log_message("WARNING", "Thread " + thread_id_to_string(std::this_thread::get_id()) + ": Skipping block " + std::to_string(current_block_height) + " (" + block_hash + ") due to failure getting block data or ignorable RPC error.");
            g_processed_blocks_count.fetch_add(1, std::memory_order_seq_cst); // Count as processed/skipped
            continue; // Move to next block
        }

        // --- Process Block Data (JSON traversal) ---
        std::unordered_set<std::string> block_pubkeys_set; // Set for unique keys in THIS block

        try { // Catch potential exceptions during JSON access or script parsing
            if (block_json.contains("tx") && block_json["tx"].is_array()) {
                for (const auto& tx : block_json["tx"]) {
                    if (!tx.is_object()) continue;

                    // Process vin
                    if (tx.contains("vin") && tx["vin"].is_array()) {
                         // Check if it's a coinbase transaction's vin
                         bool is_coinbase = false;
                         if (tx["vin"].size() == 1 && tx["vin"][0].is_object() && tx["vin"][0].contains("coinbase")) {
                              is_coinbase = true;
                         }

                        if (!is_coinbase) {
                            for (const auto& vin : tx["vin"]) {
                                if (!vin.is_object()) continue;

                                // From scriptSig
                                if (vin.contains("scriptSig") && vin["scriptSig"].is_object() && vin["scriptSig"].contains("hex") && vin["scriptSig"]["hex"].is_string()) {
                                    std::string scriptSig_hex = vin["scriptSig"]["hex"].get<std::string>();
                                    // Apply recursive extraction logic to scriptSig pushes
                                    std::unordered_set<std::string> script_keys = extract_pubkeys_recursive(scriptSig_hex);
                                    block_pubkeys_set.insert(script_keys.begin(), script_keys.end());
                                }

                                // From txinwitness
                                if (vin.contains("txinwitness") && vin["txinwitness"].is_array()) {
                                    const auto& witness_stack = vin["txinwitness"];
                                    // Process witness stack items
                                    for (size_t k = 0; k < witness_stack.size(); ++k) {
                                        const auto& item = witness_stack[k];
                                        if (!item.is_string()) continue;
                                        std::string item_hex = item.get<std::string>();

                                        // Check if this item itself is a valid pubkey
                                        if (is_valid_pubkey_hex(item_hex)) {
                                            block_pubkeys_set.insert(item_hex);
                                        }

                                        // If it's the last item, check if it could be a witness script
                                        // Original logic: only last item is considered as potential witness script
                                        if (k == witness_stack.size() - 1 &&
                                            !is_valid_pubkey_hex(item_hex) && // It's not a pubkey itself
                                            item_hex.length() >= 4 && item_hex.length() % 2 == 0) // Looks like hex data
                                        {
                                            // Recursively try to parse this item's data as a script (Witness Script)
                                            std::unordered_set<std::string> witness_script_keys = extract_pubkeys_recursive(item_hex, 0); // Start new depth
                                            block_pubkeys_set.insert(witness_script_keys.begin(), witness_script_keys.end());
                                        }
                                    }
                                }
                            }
                        }
                    }

                    // Process vout
                    if (tx.contains("vout") && tx["vout"].is_array()) {
                        for (const auto& vout : tx["vout"]) {
                            if (!vout.is_object()) continue;

                            if (vout.contains("scriptPubKey") && vout["scriptPubKey"].is_object() && vout["scriptPubKey"].contains("hex") && vout["scriptPubKey"]["hex"].is_string()) {
                                std::string scriptPubKey_hex = vout["scriptPubKey"]["hex"].get<std::string>();
                                // For scriptPubKey, we only extract DIRECTLY pushed pubkeys, no recursive parsing based on original Python logic.
                                std::vector<std::string> scriptPubKey_pushes = parse_script_hex(scriptPubKey_hex);
                                for (const auto& push_hex : scriptPubKey_pushes) {
                                    if (is_valid_pubkey_hex(push_hex)) {
                                         block_pubkeys_set.insert(push_hex);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        } catch (const json::exception& e) {
             log_message("ERROR", "Thread " + thread_id_to_string(std::this_thread::get_id()) + ": JSON access error during block processing for block " + std::to_string(current_block_height) + ": " + e.what());
             // This is a processing error, not RPC error, but the block is effectively skipped for key extraction.
        } catch (const std::exception& e) {
             log_message("ERROR", "Thread " + thread_id_to_string(std::this_thread::get_id()) + ": Standard exception during block processing for block " + std::to_string(current_block_height) + ": " + e.what());
              // Same as above, block effectively skipped for key extraction.
        }


        // Write unique keys from this block to the output file and update global counts
        size_t num_keys_extracted_this_block = block_pubkeys_set.size();
        if (num_keys_extracted_this_block > 0) {
             std::lock_guard<std::mutex> lock(g_state_mutex); // Lock file access and counters together
             for (const auto& key : block_pubkeys_set) {
                 g_output_file << key << "\n";
             }
             // g_output_file.flush(); // Optional: flush immediately, can impact performance
         }

        // Update global counters
        g_total_keys_extracted_value.fetch_add(num_keys_extracted_this_block, std::memory_order_seq_cst);
        g_processed_blocks_count.fetch_add(1, std::memory_order_seq_cst); // Count as successfully processed (even if 0 keys found or had internal errors)

        log_message("DEBUG", "Thread " + thread_id_to_string(std::this_thread::get_id()) + ": Finished block " + std::to_string(current_block_height) +
                    ". Extracted " + std::to_string(num_keys_extracted_this_block) + " keys.");

    } // End while loop for blocks

    log_message("INFO", "Thread " + thread_id_to_string(std::this_thread::get_id()) + " finished processing loop.");
}


int main(int argc, char* argv[]) {
    // Disable sync with stdio for potentially faster output (but don't mix cout/printf)
    std::ios_base::sync_with_stdio(false);
    std::cin.tie(NULL); // Untie cin from cout
    std::cerr.tie(NULL); // Untie cerr from cout

    if (argc != 4) {
        std::cerr << C_YELLOW << "Usage: " << argv[0] << " <start_block> <end_block> <output_file>" << C_RESET << std::endl;
        return 1;
    }

    int start_block, end_block;
    std::string output_filename = argv[3];

    try {
        start_block = std::stoi(argv[1]);
        end_block = std::stoi(argv[2]);
    } catch (const std::invalid_argument& e) {
        log_message("CRITICAL", C_RED + "Error: Start and end block must be integers. " + e.what() + C_RESET);
        std::cerr << C_RED + "Error: Start and end block must be integers. " + std::string(e.what()) + C_RESET << std::endl;
        return EXIT_FAILURE;
    } catch (const std::out_of_range& e) {
         log_message("CRITICAL", C_RED + "Error: Start or end block out of integer range. " + e.what() + C_RESET);
         std::cerr << C_RED + "Error: Start or end block out of integer range. " + std::string(e.what()) + C_RESET << std::endl;
         return EXIT_FAILURE;
    }


    if (start_block < 0 || end_block < start_block) {
        log_message("CRITICAL", C_RED + "Error: Invalid block range." + C_RESET);
        std::cerr << C_RED + "Error: Invalid block range." + C_RESET << std::endl;
        return EXIT_FAILURE;
    }

    // Open log file BEFORE threads are created
    // Use std::ios::app to append to the file if it already exists
    g_log_file.open(LOG_FILE, std::ios::app);
    if (!g_log_file.is_open()) {
        // Log file is not essential for program functionality, but warn the user
        std::cerr << C_YELLOW << "Warning: Could not open log file " << LOG_FILE << ". Detailed logging (DEBUG, WARNING) will be unavailable." << C_RESET << std::endl;
        // Continue execution
    } else {
         // Initial log message to file
         log_message("INFO", "Log file opened: " + LOG_FILE);
    }


    // Load RPC config
    if (load_rpc_config(RPC_CONFIG_FILE) != 0) { // load_rpc_config is now defined before main
        if (g_log_file.is_open()) g_log_file.close(); // Close log file before exiting
        return EXIT_FAILURE; // Error loading config
    }

    // Initialize libcurl global state (call once)
    CURLcode curl_init_res = curl_global_init(CURL_GLOBAL_DEFAULT);
    if (curl_init_res != CURLE_OK) {
        log_message("CRITICAL", C_RED + "Error initializing libcurl: " + curl_easy_strerror(curl_init_res) + C_RESET);
        std::cerr << C_RED + "Error initializing libcurl: " + std::string(curl_easy_strerror(curl_init_res)) + C_RESET << std::endl;
        if (g_log_file.is_open()) g_log_file.close(); // Close log file before exiting
        return EXIT_FAILURE;
    }

    // Compile regex (call once)
    compile_pubkey_regex(); // Exits if fails internally

    // Open output file
    g_output_file.open(output_filename);
    if (!g_output_file.is_open()) {
        log_message("CRITICAL", C_RED + "Error: Could not open output file " + output_filename + C_RESET);
        std::cerr << C_RED + "Error: Could not open output file " + output_filename + C_RESET << std::endl;
        curl_global_cleanup();
        if (g_log_file.is_open()) g_log_file.close(); // Close log file before exiting
        return EXIT_FAILURE;
    }

    // Reset global atomic counters
    g_total_keys_extracted_value.store(0, std::memory_order_seq_cst);
    g_processed_blocks_count.store(0, std::memory_order_seq_cst);
    g_rpc_consecutive_failures.store(0, std::memory_order_seq_cst);


    int total_blocks_to_process = end_block - start_block + 1;

    auto start_time = std::chrono::high_resolution_clock::now();
    auto last_report_time = start_time;
    long long last_report_keys = 0;
    int last_report_blocks = 0;


    std::cerr << C_CYAN << "Starting block processing from " << start_block << " to " << end_block << "..." << C_RESET << std::endl;
    log_message("INFO", "Starting block processing from " + std::to_string(start_block) + " to " + std::to_string(end_block) + "...");

    // --- Thread Pool Creation ---
    std::vector<std::thread> workers;
    workers.reserve(g_rpc_config.num_workers);

    // Atomic counter to distribute blocks among threads (index relative to start_block)
    std::atomic<int> next_block_index = 0;

    try {
        for (int i = 0; i < g_rpc_config.num_workers; ++i) {
            // Pass start_block, end_block, and the atomic index by reference
            workers.emplace_back(process_block_worker, start_block, end_block, std::ref(next_block_index));
        }

        // Main thread loop for progress reporting
        while (g_processed_blocks_count.load(std::memory_order_seq_cst) < total_blocks_to_process) {
            auto current_time = std::chrono::high_resolution_clock::now();
            std::chrono::duration<double> elapsed_seconds_report = current_time - last_report_time;

            // Report progress periodically (e.g., every 5 seconds or after significant progress)
            long long current_total_keys = g_total_keys_extracted_value.load(std::memory_order_seq_cst);
            int current_processed_blocks = g_processed_blocks_count.load(std::memory_order_seq_cst);

            // Use a small epsilon for double comparison, or check if duration is meaningful
            if (elapsed_seconds_report.count() >= 5.0 ||
                (current_processed_blocks - last_report_blocks) >= std::max(1, total_blocks_to_process / 500) || // Report every ~0.2% blocks
                (current_total_keys - last_report_keys) >= 50000 || // Report every 50k keys
                current_processed_blocks == total_blocks_to_process) // Always report final state
            {
                 std::chrono::duration<double> total_elapsed_seconds = current_time - start_time;

                 double report_duration = elapsed_seconds_report.count();
                 long long report_keys_delta = current_total_keys - last_report_keys;
                 int report_blocks_delta = current_processed_blocks - last_report_blocks;

                 double key_rate_sec = report_duration > 1e-6 ? (double)report_keys_delta / report_duration : 0;
                 double block_rate_sec = report_duration > 1e-6 ? (double)report_blocks_delta / report_duration : 0;
                 double overall_elapsed = total_elapsed_seconds.count();
                 double overall_key_rate = overall_elapsed > 1e-6 ? (double)current_total_keys / overall_elapsed : 0;
                 double overall_block_rate = overall_elapsed > 1e-6 ? (double)current_processed_blocks / overall_elapsed : 0;


                 // Use std::cerr with \r and flush for scrolling effect
                 std::stringstream progress_ss;
                 progress_ss << "\r" << C_YELLOW << "进度: 完成区块 " << current_processed_blocks << "/" << total_blocks_to_process
                           << ", 总计提取 " << current_total_keys << " 个公钥. "
                           << "当前速度: " << std::fixed << std::setprecision(2) << key_rate_sec << " keys/s, " << block_rate_sec << " blocks/s. "
                           << "总体速度: " << overall_key_rate << " keys/s, " << overall_block_rate << " blocks/s."
                           << C_RESET;

                 std::string progress_str = progress_ss.str();
                 // Pad with spaces to clear previous output on the same line
                 const int max_line_width = 150; // Adjust based on expected max line length
                 if (progress_str.length() < max_line_width) {
                     progress_str.append(max_line_width - progress_str.length(), ' ');
                 } else {
                     // If line is longer than max_line_width, trim it or ensure terminal wrap correctly
                     progress_str = progress_str.substr(0, max_line_width); // Simple trim
                 }
                 std::cerr << progress_str;
                 std::cerr.flush(); // Important for \r

                 last_report_time = current_time;
                 last_report_keys = current_total_keys;
                 last_report_blocks = current_processed_blocks;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(50)); // Sleep briefly to avoid busy waiting
        }

    } catch (const std::exception& e) {
        // Catch any unexpected exceptions that might escape workers (less likely with the current structure)
        log_message("CRITICAL", C_RED + "Main thread caught unexpected exception during processing loop: " + e.what() + C_RESET);
        std::cerr << "\n" << C_RED + "Main thread caught unexpected exception during processing loop: " + std::string(e.what()) + C_RESET << std::endl;
        // Consider setting a global error flag here and signaling workers to exit gracefully
    }


    // Join threads (wait for them to finish)
    // This loop will execute after the progress loop finishes (all blocks assigned/processed)
    // Or if an exception was caught and not re-thrown immediately.
    for (std::thread& worker : workers) {
        if (worker.joinable()) {
            worker.join();
        }
    }

    // Print a final newline after the progress reporting finishes
    std::cerr << std::endl;

    auto end_time = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> total_duration = end_time - start_time;

    long long final_total_keys = g_total_keys_extracted_value.load(std::memory_order_seq_cst);
    int final_processed_blocks = g_processed_blocks_count.load(std::memory_order_seq_cst);

    std::cerr << "\n" << C_GREEN << "--- Processing Complete ---" << C_RESET << std::endl;
    log_message("INFO", "--- Processing Complete ---");
    std::cerr << "Processed block range: " << C_CYAN << start_block << C_RESET << " - " << C_CYAN << end_block << C_RESET << std::endl;
    log_message("INFO", "Processed block range: " + std::to_string(start_block) + " - " + std::to_string(end_block));
    std::cerr << "Completed/Skipped blocks: " << C_GREEN << final_processed_blocks << C_RESET << "/" << total_blocks_to_process << std::endl;
    log_message("INFO", "Completed/Skipped blocks: " + std::to_string(final_processed_blocks) + "/" + std::to_string(total_blocks_to_process));
    std::cerr << "Total keys extracted: " << C_GREEN << final_total_keys << C_RESET << std::endl;
    log_message("INFO", "Total keys extracted: " + std::to_string(final_total_keys));
    std::cerr << "Total time: " << C_CYAN << std::fixed << std::setprecision(2) << total_duration.count() << " seconds" << C_RESET << std::endl;
    log_message("INFO", "Total time: " + std::to_string(total_duration.count()) + " seconds");
    if (total_duration.count() > 0) {
        double final_key_rate = (double)final_total_keys / total_duration.count();
        double final_block_rate = (double)final_processed_blocks / total_duration.count();
        std::cerr << "Average speed: " << C_GREEN << std::fixed << std::setprecision(2) << final_key_rate << " keys/second" << C_RESET
                  << ", " << C_GREEN << final_block_rate << " blocks/second" << C_RESET << std::endl;
        log_message("INFO", "Average speed: " + std::to_string(final_key_rate) + " keys/second, " + std::to_string(final_block_rate) + " blocks/second");
    }


    // Cleanup
    if (g_output_file.is_open()) {
        g_output_file.flush(); // Ensure any buffered data is written
        g_output_file.close();
    }
    if (g_log_file.is_open()) {
        // Final log message to file (won't appear on console)
        log_message("INFO", "Log file closed."); // This message might not be fully written depending on flush/close order
        g_log_file.close();
    }
    curl_global_cleanup(); // Cleanup libcurl global state

    return EXIT_SUCCESS;
}
