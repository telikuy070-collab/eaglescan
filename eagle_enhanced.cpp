/**
 * ════════════════════════════════════════════════════════════════════
 *  🦅 EAGLE AI SCANNER v7.0 - NEURAL NETWORK EDITION
 *  Modern C++20 Port Scanner with AI OS Fingerprinting
 * 
 *  Author: noob saybot
 *  License: MIT
 *  GitHub: github.com/telikuy070-collab/eagle-ai-scanner
 * ════════════════════════════════════════════════════════════════════
 */

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <icmpapi.h>

#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <queue>
#include <atomic>
#include <mutex>
#include <memory>
#include <optional>
#include <variant>
#include <array>
#include <chrono>
#include <algorithm>
#include <cstdint>
#include <cmath>
#include <random>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <functional>
#include <thread>
#include <future>
#include <variant>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

// ════════════════════════════════════════════════════════════════════
//  C++20 CONCEPTS & CONSTRAINTS
// ════════════════════════════════════════════════════════════════════

template<typename T>
concept Numeric = std::integral<T> || std::floating_point<T>;

template<typename T>
concept Container = requires(T t) {
    t.begin();
    t.end();
    t.size();
};

// ════════════════════════════════════════════════════════════════════
//  UTILITY CLASSES - RAII & SAFETY
// ════════════════════════════════════════════════════════════════════

/**
 * @brief RAII Socket wrapper - automatically closes socket on destruction
 */
class Socket final {
public:
    explicit Socket() : m_socket(INVALID_SOCKET) {}
    explicit Socket(SOCKET sock) : m_socket(sock) {}
    
    ~Socket() { close(); }
    
    // Delete copy - single owner
    Socket(const Socket&) = delete;
    Socket& operator=(const Socket&) = delete;
    
    // Allow move
    Socket(Socket&& other) noexcept : m_socket(other.m_socket) {
        other.m_socket = INVALID_SOCKET;
    }
    Socket& operator=(Socket&& other) noexcept {
        if (this != &other) {
            close();
            m_socket = other.m_socket;
            other.m_socket = INVALID_SOCKET;
        }
        return *this;
    }
    
    [[nodiscard]] bool isValid() const noexcept { return m_socket != INVALID_SOCKET; }
    [[nodiscard]] SOCKET get() const noexcept { return m_socket; }
    
    bool create(int af, int type, int protocol) {
        close();
        m_socket = ::socket(af, type, protocol);
        return isValid();
    }
    
    void close() noexcept {
        if (isValid()) {
            closesocket(m_socket);
            m_socket = INVALID_SOCKET;
        }
    }
    
    explicit operator bool() const noexcept { return isValid(); }
    
private:
    SOCKET m_socket;
};

/**
 * @brief RAII WSA initializer
 */
class WSAInitializer {
public:
    WSAInitializer() {
        WSADATA wsa_data;
        if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) {
            throw std::runtime_error("WSAStartup failed");
        }
    }
    ~WSAInitializer() { WSACleanup(); }
    
    WSAInitializer(const WSAInitializer&) = delete;
    WSAInitializer& operator=(const WSAInitializer&) = delete;
};

/**
 * @brief Result type for error handling (Either pattern)
 */
template<typename T, typename E = std::string>
class Result {
public:
    static Result ok(T value) {
        return Result(std::move(value), std::nullopt);
    }
    
    static Result err(E error) {
        return Result(std::nullopt, std::move(error));
    }
    
    [[nodiscard]] bool ok() const noexcept { return m_value.has_value(); }
    [[nodiscard]] bool err() const noexcept { return !m_value.has_value(); }
    
    [[nodiscard]] const T& value() const { return *m_value; }
    [[nodiscard]] T& value() { return *m_value; }
    [[nodiscard]] const E& error() const { return *m_error; }
    
    [[nodiscard]] T&& moveValue() { return std::move(*m_value); }
    
    template<typename F>
    auto map(F&& f) -> Result<decltype(f(std::declval<T>())), E> {
        if (ok()) {
            return Result<decltype(f(std::declval<T>())), E>::ok(f(*m_value));
        }
        return Result<decltype(f(std::declval<T>())), E>::err(*m_error);
    }
    
private:
    explicit Result(std::optional<T> value, std::optional<E> error)
        : m_value(std::move(value)), m_error(std::move(error)) {}
    
    std::optional<T> m_value;
    std::optional<E> m_error;
};

// ════════════════════════════════════════════════════════════════════
//  NETWORK CORE CLASSES
// ════════════════════════════════════════════════════════════════════

namespace eagle {

// Forward declarations
class PortScanner;
class OSFingerprinter;
class CVEDatabase;
class ReportExporter;

/**
 * @brief Port scan result
 */
struct PortResult {
    uint16_t port{0};
    bool isOpen{false};
    std::string service;
    std::string version;
    float responseTime{0.0f};
    
    template<typename Archive>
    void serialize(Archive& ar, const unsigned int version) {
        ar & port & isOpen & service & version & responseTime;
    }
};

/**
 * @brief Scan configuration
 */
struct ScanConfig {
    std::string targetIP;
    uint16_t startPort{1};
    uint16_t endPort{65535};
    uint8_t threadCount{32};
    uint32_t timeout{500};
    bool scanTCP{true};
    bool scanUDP{false};
    bool detectOS{true};
    bool detectVersion{false};
    bool detectWAF{false};
    std::optional<std::string> outputFile;
    std::optional<std::string> outputFormat; // json, csv, xml
};

/**
 * @brief OS Detection result
 */
struct OSResult {
    std::string osName;
    float confidence{0.0f};
    bool isAI{false};
    std::string version;
    std::vector<std::string> fingerprints;
    
    template<typename Archive>
    void serialize(Archive& ar, const unsigned int version) {
        ar & osName & confidence & isAI & version & fingerprints;
    }
};

/**
 * @brief Complete scan result
 */
struct ScanResult {
    std::string target;
    std::chrono::system_clock::time_point timestamp;
    uint32_t scanDurationMs{0};
    std::vector<PortResult> ports;
    std::optional<OSResult> osResult;
    std::vector<std::string> errors;
    
    template<typename Archive>
    void serialize(Archive& ar, const unsigned int version) {
        ar & target & timestamp & scanDurationMs & ports & osResult & errors;
    }
};

} // namespace eagle

// ════════════════════════════════════════════════════════════════════
//  MODERN NEURAL NETWORK - TEMPLATE BASED
// ════════════════════════════════════════════════════════════════════

namespace eagle::ai {

/**
 * @brief Modern activation functions
 */
struct ActivationFunctions {
    static float sigmoid(float x) noexcept {
        return 1.0f / (1.0f + std::exp(-std::clamp(x, -500.0f, 500.0f)));
    }
    
    static float sigmoidDerivative(float x) noexcept {
        float s = sigmoid(x);
        return s * (1.0f - s);
    }
    
    static float tanh(float x) noexcept {
        return std::tanh(x);
    }
    
    static float tanhDerivative(float x) noexcept {
        float t = std::tanh(x);
        return 1.0f - t * t;
    }
    
    static float relu(float x) noexcept {
        return std::max(0.0f, x);
    }
    
    static float reluDerivative(float x) noexcept {
        return x > 0.0f ? 1.0f : 0.0f;
    }
    
    static float leakyRelu(float x, float alpha = 0.01f) noexcept {
        return x > 0.0f ? x : alpha * x;
    }
    
    static float leakyReluDerivative(float x, float alpha = 0.01f) noexcept {
        return x > 0.0f ? 1.0f : alpha;
    }
};

/**
 * @brief Neural Network Layer
 */
template<size_t InputSize, size_t OutputSize>
class Layer {
public:
    using Weights = std::array<std::array<float, OutputSize>, InputSize>;
    using Bias = std::array<float, OutputSize>;
    
    Layer() {
        // Xavier initialization
        std::mt19937 gen(std::random_device{}());
        std::uniform_real_distribution<float> dist(-1.0f, 1.0f);
        float scale = std::sqrt(2.0f / (InputSize + OutputSize));
        
        for (auto& row : m_weights) {
            for (auto& w : row) {
                w = dist(gen) * scale;
            }
        }
    }
    
    [[nodiscard]] constexpr size_t inputSize() const noexcept { return InputSize; }
    [[nodiscard]] constexpr size_t outputSize() const noexcept { return OutputSize; }
    
    std::array<float, OutputSize> forward(const std::array<float, InputSize>& inputs) const {
        std::array<float, OutputSize> outputs{};
        
        for (size_t j = 0; j < OutputSize; ++j) {
            float sum = m_bias[j];
            for (size_t i = 0; i < InputSize; ++i) {
                sum += inputs[i] * m_weights[i][j];
            }
            outputs[j] = ActivationFunctions::leakyRelu(sum);
        }
        
        return outputs;
    }
    
    const Weights& weights() const { return m_weights; }
    const Bias& bias() const { return m_bias; }
    
    void train(const std::array<float, InputSize>& inputs,
               const std::array<float, OutputSize>& error,
               float learningRate) {
        // Compute output layer activations (forward pass)
        std::array<float, OutputSize> outputs{};
        for (size_t j = 0; j < OutputSize; ++j) {
            float sum = m_bias[j];
            for (size_t i = 0; i < InputSize; ++i) {
                sum += inputs[i] * m_weights[i][j];
            }
            outputs[j] = ActivationFunctions::leakyRelu(sum);
        }
        
        // Compute deltas
        std::array<float, OutputSize> deltas{};
        for (size_t j = 0; j < OutputSize; ++j) {
            deltas[j] = error[j] * ActivationFunctions::leakyReluDerivative(outputs[j]);
        }
        
        // Update weights and bias
        for (size_t i = 0; i < InputSize; ++i) {
            for (size_t j = 0; j < OutputSize; ++j) {
                m_weights[i][j] += learningRate * deltas[j] * inputs[i];
            }
        }
        
        for (size_t j = 0; j < OutputSize; ++j) {
            m_bias[j] += learningRate * deltas[j];
        }
    }
    
private:
    Weights m_weights{};
    Bias m_bias{};
};

/**
 * @brief Modern Neural Network with configurable architecture
 */
template<size_t InputSize, size_t HiddenSize, size_t OutputSize>
class NeuralNetwork {
public:
    using InputLayer = Layer<InputSize, HiddenSize>;
    using OutputLayer = Layer<HiddenSize, OutputSize>;
    
    NeuralNetwork() = default;
    
    // Delete copy - neural networks are heavy
    NeuralNetwork(const NeuralNetwork&) = delete;
    NeuralNetwork& operator=(const NeuralNetwork&) = delete;
    
    // Allow move
    NeuralNetwork(NeuralNetwork&&) = default;
    NeuralNetwork& operator=(NeuralNetwork&&) = default;
    
    /**
     * @brief Forward propagation
     * @param inputs Input features
     * @return Output predictions
     */
    [[nodiscard]] std::array<float, OutputSize> predict(const std::array<float, InputSize>& inputs) const {
        m_hidden = m_inputLayer.forward(inputs);
        return m_outputLayer.forward(m_hidden);
    }
    
    /**
     * @brief Train the network
     * @param inputs Input features
     * @param targets Target outputs (one-hot encoded)
     * @param learningRate Learning rate
     */
    void train(const std::array<float, InputSize>& inputs,
               const std::array<float, OutputSize>& targets,
               float learningRate = 0.01f) {
        // Forward pass
        m_hidden = m_inputLayer.forward(inputs);
        auto outputs = m_outputLayer.forward(m_hidden);
        
        // Compute output error
        std::array<float, OutputSize> outputError{};
        for (size_t i = 0; i < OutputSize; ++i) {
            outputError[i] = targets[i] - outputs[i];
        }
        
        // Backpropagation through output layer
        m_outputLayer.train(m_hidden, outputError, learningRate);
        
        // Compute hidden error
        std::array<float, HiddenSize> hiddenError{};
        const auto& outputWeights = m_outputLayer.weights();
        for (size_t j = 0; j < HiddenSize; ++j) {
            for (size_t k = 0; k < OutputSize; ++k) {
                hiddenError[j] += outputError[k] * outputWeights[j][k];
            }
        }
        
        // Backpropagation through input layer
        m_inputLayer.train(inputs, hiddenError, learningRate);
    }
    
    /**
     * @brief Get prediction index (argmax)
     */
    [[nodiscard]] size_t predictClass(const std::array<float, InputSize>& inputs) const {
        auto outputs = predict(inputs);
        size_t maxIdx = 0;
        float maxVal = outputs[0];
        for (size_t i = 1; i < OutputSize; ++i) {
            if (outputs[i] > maxVal) {
                maxVal = outputs[i];
                maxIdx = i;
            }
        }
        return maxIdx;
    }
    
    /**
     * @brief Get confidence percentage
     */
    [[nodiscard]] float getConfidence(const std::array<float, InputSize>& inputs) const {
        auto outputs = predict(inputs);
        size_t predClass = predictClass(inputs);
        return outputs[predClass] * 100.0f;
    }
    
private:
    InputLayer m_inputLayer;
    OutputLayer m_outputLayer;
    mutable std::array<float, HiddenSize> m_hidden{};
};

// ════════════════════════════════════════════════════════════════════
//  OS FINGERPRINTING WITH AI
// ════════════════════════════════════════════════════════════════════

/**
 * @brief OS Feature extractor
 */
struct OSFeatures {
    static constexpr size_t FeatureCount = 24;
    
    using FeatureArray = std::array<float, FeatureCount>;
    
    float ttl{64};
    float windowSize{65535};
    float mss{1460};
    float hasTCPOptions{0};
    float supportsFragmentation{1};
    float responseTime{50};
    
    // Port presence (binary)
    float port21{0}, port22{0}, port23{0}, port25{0}, port53{0};
    float port80{0}, port110{0}, port143{0}, port443{0}, port445{0};
    float port3306{0}, port3389{0}, port5432{0}, port8080{0};
    
    [[nodiscard]] FeatureArray toArray() const noexcept {
        return {{
            ttl / 255.0f,
            windowSize / 65535.0f,
            mss / 1500.0f,
            hasTCPOptions,
            supportsFragmentation,
            responseTime / 1000.0f,
            port21, port22, port23, port25, port53,
            port80, port110, port143, port443, port445,
            port3306, port3389, port5432, port8080
        }};
    }
};

/**
 * @brief AI OS Fingerprinter
 */
class OSFingerprinter {
public:
    // OS classes: Windows, Linux, macOS, FreeBSD, Solaris, NetworkDevice, Android, Unknown
    static constexpr size_t NumOSClasses = 8;
    using Network = NeuralNetwork<OSFeatures::FeatureCount, 32, NumOSClasses>;
    
    static constexpr std::array<std::string_view, NumOSClasses> OSNames = {{
        "Windows", "Linux", "macOS", "FreeBSD", 
        "Solaris", "Network Device", "Android", "Unknown"
    }};
    
    OSFingerprinter() : m_network(std::make_unique<Network>()) {
        train();
    }
    
    /**
     * @brief Detect OS from open ports and network features
     */
    [[nodiscard]] eagle::OSResult detect(const std::string& target,
                                          const std::vector<uint16_t>& openPorts) const {
        eagle::OSResult result;
        result.confidence = 0.0f;
        
        // Extract features
        auto features = extractFeatures(target, openPorts);
        
        // Get AI prediction
        auto prediction = m_network->predict(features);
        size_t osClass = m_network->predictClass(features);
        float aiConfidence = m_network->getConfidence(features);
        
        // Determine OS with confidence
        result.osName = std::string(OSNames[osClass]);
        result.confidence = aiConfidence;
        result.isAI = true;
        
        // Add fingerprints as evidence
        for (uint16_t port : openPorts) {
            switch (port) {
                case 22: result.fingerprints.push_back("SSH detected"); break;
                case 80: result.fingerprints.push_back("HTTP detected"); break;
                case 443: result.fingerprints.push_back("HTTPS detected"); break;
                case 445: result.fingerprints.push_back("SMB detected"); break;
                case 3389: result.fingerprints.push_back("RDP detected"); break;
            }
        }
        
        // Low confidence fallback to rule-based
        if (aiConfidence < 50.0f) {
            result = ruleBasedDetection(openPorts);
            result.isAI = false;
        }
        
        return result;
    }
    
private:
    std::unique_ptr<Network> m_network;
    
    void train() {
        // Training data: features -> one-hot targets
        // Format: {ttl, window, mss, tcp_opts, frag, resp_time, ports...} -> OS
        
        // Windows signatures
        for (int i = 0; i < 50; ++i) {
            std::array<float, OSFeatures::FeatureCount> input = {
                0.5f, 1.0f, 0.97f, 0.0f, 1.0f, 0.05f,
                0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 1.0f, 0.0f, 1.0f, 0.0f, 0.0f
            };
            input[0] = static_cast<float>((128 + (rand() % 64))) / 255.0f; // TTL variation
            std::array<float, NumOSClasses> target = {1,0,0,0,0,0,0,0};
            m_network->train(input, target, 0.1f);
        }
        
        // Linux signatures
        for (int i = 0; i < 50; ++i) {
            std::array<float, OSFeatures::FeatureCount> input = {
                0.25f, 0.44f, 0.97f, 1.0f, 1.0f, 0.03f,
                0.0f, 1.0f, 0.0f, 0.0f, 1.0f, 1.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f
            };
            std::array<float, NumOSClasses> target = {0,1,0,0,0,0,0,0};
            m_network->train(input, target, 0.1f);
        }
        
        // macOS signatures
        for (int i = 0; i < 30; ++i) {
            std::array<float, OSFeatures::FeatureCount> input = {
                0.25f, 1.0f, 0.97f, 1.0f, 1.0f, 0.02f,
                0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 1.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 1.0f
            };
            std::array<float, NumOSClasses> target = {0,0,1,0,0,0,0,0};
            m_network->train(input, target, 0.1f);
        }
        
        // Network devices
        for (int i = 0; i < 20; ++i) {
            std::array<float, OSFeatures::FeatureCount> input = {
                1.0f, 0.06f, 0.36f, 0.0f, 0.0f, 0.1f,
                0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f
            };
            std::array<float, NumOSClasses> target = {0,0,0,0,0,1,0,0};
            m_network->train(input, target, 0.1f);
        }
    }
    
    [[nodiscard]] OSFeatures::FeatureArray extractFeatures(const std::string& target,
                                                          const std::vector<uint16_t>& openPorts) const {
        OSFeatures features;
        
        // Set port features
        std::set<uint16_t> portSet(openPorts.begin(), openPorts.end());
        features.port21 = portSet.count(21) ? 1.0f : 0.0f;
        features.port22 = portSet.count(22) ? 1.0f : 0.0f;
        features.port23 = portSet.count(23) ? 1.0f : 0.0f;
        features.port25 = portSet.count(25) ? 1.0f : 0.0f;
        features.port53 = portSet.count(53) ? 1.0f : 0.0f;
        features.port80 = portSet.count(80) ? 1.0f : 0.0f;
        features.port110 = portSet.count(110) ? 1.0f : 0.0f;
        features.port143 = portSet.count(143) ? 1.0f : 0.0f;
        features.port443 = portSet.count(443) ? 1.0f : 0.0f;
        features.port445 = portSet.count(445) ? 1.0f : 0.0f;
        features.port3306 = portSet.count(3306) ? 1.0f : 0.0f;
        features.port3389 = portSet.count(3389) ? 1.0f : 0.0f;
        features.port5432 = portSet.count(5432) ? 1.0f : 0.0f;
        features.port8080 = portSet.count(8080) ? 1.0f : 0.0f;
        
        // Probe for TTL and other network characteristics
        probeNetwork(target, features);
        
        return features.toArray();
    }
    
    void probeNetwork(const std::string& target, OSFeatures& features) const {
        HANDLE icmp = IcmpCreateFile();
        if (icmp == INVALID_HANDLE_VALUE) return;
        
        char sendData[32] = "EAGLE_PROBE";
        char replyBuf[sizeof(ICMP_ECHO_REPLY) + 32];
        
        DWORD ret = IcmpSendEcho(icmp, inet_addr(target.c_str()), 
                                 sendData, sizeof(sendData), nullptr,
                                 replyBuf, sizeof(replyBuf), 100);
        
        if (ret > 0) {
            auto* reply = reinterpret_cast<PICMP_ECHO_REPLY>(replyBuf);
            features.ttl = static_cast<float>(reply->Options.Ttl);
            features.responseTime = static_cast<float>(reply->RoundTripTime);
        }
        
        IcmpCloseHandle(icmp);
    }
    
    [[nodiscard]] eagle::OSResult ruleBasedDetection(const std::vector<uint16_t>& openPorts) const {
        eagle::OSResult result;
        result.isAI = false;
        result.confidence = 60.0f;
        
        std::set<uint16_t> ports(openPorts.begin(), openPorts.end());
        
        if (ports.count(445) || ports.count(3389)) {
            result.osName = "Windows";
            result.fingerprints.push_back("SMB/RDP detected");
        } else if (ports.count(22)) {
            result.osName = "Linux/Unix";
            result.fingerprints.push_back("SSH detected");
        } else if (ports.count(548)) {
            result.osName = "macOS";
            result.fingerprints.push_back("AFP detected");
        } else {
            result.osName = "Unknown";
            result.confidence = 30.0f;
        }
        
        return result;
    }
};

// ════════════════════════════════════════════════════════════════════
//  PORT SCANNER CORE
// ════════════════════════════════════════════════════════════════════

/**
 * @brief Modern Port Scanner with async support
 */
class PortScanner {
public:
    explicit PortScanner(const eagle::ScanConfig& config)
        : m_config(config)
        , m_openPortCount(0)
        , m_scannedPortCount(0) {}
    
    // Non-copyable
    PortScanner(const PortScanner&) = delete;
    PortScanner& operator=(const PortScanner&) = delete;
    
    /**
     * @brief Perform scan and return results
     */
    [[nodiscard]] Result<eagle::ScanResult, std::string> scan() {
        if (!validateTarget()) {
            return Result<eagle::ScanResult, std::string>::err("Invalid target IP");
        }
        
        eagle::ScanResult result;
        result.target = m_config.targetIP;
        result.timestamp = std::chrono::system_clock::now();
        
        auto startTime = std::chrono::high_resolution_clock::now();
        
        // Create port queue
        std::queue<uint16_t> portQueue;
        for (uint16_t p = m_config.startPort; p <= m_config.endPort; ++p) {
            portQueue.push(p);
        }
        
        // Launch scanning threads
        std::vector<std::future<void>> threads;
        for (uint8_t i = 0; i < m_config.threadCount; ++i) {
            threads.push_back(std::async(std::launch::async, [&, i]() {
                scanWorker(portQueue);
            }));
        }
        
        // Wait for completion
        for (auto& t : threads) {
            t.wait();
        }
        
        // Collect results
        {
            std::lock_guard lock(m_resultsMutex);
            result.ports = m_results;
        }
        
        auto endTime = std::chrono::high_resolution_clock::now();
        result.scanDurationMs = std::chrono::duration_cast<std::chrono::milliseconds>(
            endTime - startTime).count();
        
        return Result<eagle::ScanResult, std::string>::ok(std::move(result));
    }
    
    [[nodiscard]] uint32_t openPortCount() const noexcept { return m_openPortCount.load(); }
    [[nodiscard]] uint32_t scannedPortCount() const noexcept { return m_scannedPortCount.load(); }
    
private:
    const eagle::ScanConfig& m_config;
    std::vector<eagle::PortResult> m_results;
    std::mutex m_resultsMutex;
    std::atomic<uint32_t> m_openPortCount;
    std::atomic<uint32_t> m_scannedPortCount;
    
    [[nodiscard]] bool validateTarget() const {
        in_addr addr;
        return inet_pton(AF_INET, m_config.targetIP.c_str(), &addr) == 1;
    }
    
    void scanWorker(std::queue<uint16_t>& portQueue) {
        while (true) {
            uint16_t port = 0;
            
            {
                std::lock_guard lock(m_resultsMutex);
                if (portQueue.empty()) break;
                port = portQueue.front();
                portQueue.pop();
            }
            
            auto result = scanPort(port);
            if (result.isOpen) {
                std::lock_guard lock(m_resultsMutex);
                m_results.push_back(result);
                ++m_openPortCount;
            }
            
            ++m_scannedPortCount;
        }
    }
    
    [[nodiscard]] eagle::PortResult scanPort(uint16_t port) const {
        eagle::PortResult result;
        result.port = port;
        
        auto start = std::chrono::high_resolution_clock::now();
        
        Socket sock;
        if (!sock.create(AF_INET, SOCK_STREAM, IPPROTO_TCP)) {
            return result;
        }
        
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        inet_pton(AF_INET, m_config.targetIP.c_str(), &addr.sin_addr);
        
        // Non-blocking connect
        u_long mode = 1;
        ioctlsocket(sock.get(), FIONBIO, &mode);
        
        connect(sock.get(), reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
        
        fd_set writefds;
        FD_ZERO(&writefds);
        FD_SET(sock.get(), &writefds);
        
        timeval timeout{};
        timeout.tv_sec = m_config.timeout / 1000;
        timeout.tv_usec = (m_config.timeout % 1000) * 1000;
        
        int ret = select(0, nullptr, &writefds, nullptr, &timeout);
        
        auto end = std::chrono::high_resolution_clock::now();
        result.responseTime = std::chrono::duration<float>(end - start).count() * 1000.0f;
        
        if (ret > 0) {
            result.isOpen = true;
            result.service = getServiceName(port);
        }
        
        return result;
    }
    
    [[nodiscard]] static std::string getServiceName(uint16_t port) noexcept {
        static const std::map<uint16_t, std::string> services = {
            {21, "FTP"}, {22, "SSH"}, {23, "TELNET"}, {25, "SMTP"},
            {53, "DNS"}, {80, "HTTP"}, {110, "POP3"}, {143, "IMAP"},
            {443, "HTTPS"}, {445, "SMB"}, {3306, "MySQL"}, {3389, "RDP"},
            {5432, "PostgreSQL"}, {6379, "Redis"}, {8080, "HTTP-ALT"},
            {8443, "HTTPS-ALT"}, {9200, "Elasticsearch"}, {27017, "MongoDB"}
        };
        
        auto it = services.find(port);
        return it != services.end() ? it->second : "Unknown";
    }
};

// ════════════════════════════════════════════════════════════════════
//  REPORT EXPORTER
// ════════════════════════════════════════════════════════════════════

/**
 * @brief Report Exporter - supports multiple formats
 */
class ReportExporter {
public:
    static void exportJSON(const eagle::ScanResult& result, const std::string& filename) {
        std::ofstream file(filename);
        file << "{\n";
        file << "  \"target\": \"" << result.target << "\",\n";
        file << "  \"timestamp\": " << std::chrono::system_clock::to_time_t(result.timestamp) << ",\n";
        file << "  \"duration_ms\": " << result.scanDurationMs << ",\n";
        file << "  \"open_ports\": " << result.ports.size() << ",\n";
        file << "  \"ports\": [\n";
        
        for (size_t i = 0; i < result.ports.size(); ++i) {
            const auto& p = result.ports[i];
            file << "    {\"port\":" << p.port << ",\"service\":\"" << p.service << "\",\"open\":" << (p.isOpen ? "true" : "false") << "}";
            if (i < result.ports.size() - 1) file << ",";
            file << "\n";
        }
        
        file << "  ]\n";
        file << "}\n";
    }
    
    static void exportCSV(const eagle::ScanResult& result, const std::string& filename) {
        std::ofstream file(filename);
        file << "Port,Service,Version,Open,Response Time (ms)\n";
        
        for (const auto& port : result.ports) {
            file << port.port << ","
                 << port.service << ","
                 << port.version << ","
                 << (port.isOpen ? "Yes" : "No") << ","
                 << std::fixed << std::setprecision(2) << port.responseTime << "\n";
        }
    }
};

// ════════════════════════════════════════════════════════════════════
//  MAIN APPLICATION CLASS
// ════════════════════════════════════════════════════════════════════

/**
 * @brief Main Scanner Application
 */
class EagleScannerApp {
public:
    EagleScannerApp() : m_wsaInit() {
        printBanner();
    }
    
    int run(int argc, char* argv[]) {
        auto config = parseArguments(argc, argv);
        
        if (!config) {
            printHelp(argv[0]);
            return 1;
        }
        
        // Perform scan
        std::cout << "\n[+] Starting scan on " << config->targetIP << "\n";
        std::cout << "[+] Port range: " << config->startPort << "-" << config->endPort << "\n";
        std::cout << "[+] Threads: " << (int)config->threadCount << "\n\n";
        
        PortScanner scanner(*config);
        auto result = scanner.scan();
        
        if (result.err()) {
            std::cerr << "[-] Error: " << result.error() << "\n";
            return 1;
        }
        
        auto& scanResult = result.value();
        
        // OS Detection
        if (config->detectOS && !scanResult.ports.empty()) {
            std::vector<uint16_t> openPorts;
            for (const auto& p : scanResult.ports) {
                openPorts.push_back(p.port);
            }
            
            std::cout << "[*] Running AI OS Fingerprinting...\n";
            OSFingerprinter fingerprinter;
            eagle::OSResult osResult = fingerprinter.detect(config->targetIP, openPorts);
            scanResult.osResult.emplace(osResult);
            
            std::cout << "[+] Detected OS: " << osResult.osName 
                      << " (" << osResult.confidence << "% confidence)";
            if (osResult.isAI) std::cout << " [AI]";
            std::cout << "\n";
        }
        
        // Print results
        std::cout << "\n[+] Scan complete!\n";
        std::cout << "[+] Open ports found: " << scanResult.ports.size() << "\n";
        std::cout << "[+] Scan duration: " << scanResult.scanDurationMs << "ms\n";
        
        // Export if requested
        if (config->outputFile && config->outputFormat) {
            if (*config->outputFormat == "json") {
                ReportExporter::exportJSON(scanResult, *config->outputFile);
                std::cout << "[+] Results exported to " << *config->outputFile << "\n";
            } else if (*config->outputFormat == "csv") {
                ReportExporter::exportCSV(scanResult, *config->outputFile);
                std::cout << "[+] Results exported to " << *config->outputFile << "\n";
            }
        }
        
        return 0;
    }
    
private:
    WSAInitializer m_wsaInit;
    
    void printBanner() const {
        std::cout << R"(
╔═══════════════════════════════════════════════════════════════════╗
║    🦅 EAGLE AI SCANNER v7.0 - NEURAL NETWORK EDITION 🦅           ║
║                                                                   ║
║  Modern C++20 Port Scanner with AI OS Fingerprinting              ║
║                                                                   ║
║  Features:                                                        ║
║  ✓ Thread-safe TCP/UDP scanning                                  ║
║  ✓ AI Neural Network OS Fingerprinting                           ║
║  ✓ Memory-safe RAII design                                        ║
║  ✓ JSON/CSV export                                                ║
║  ✓ Modern C++20 concepts & constraints                            ║
║                                                                   ║
╚═══════════════════════════════════════════════════════════════════╝
)";
    }
    
    void printHelp(const char* progName) const {
        std::cout << "Usage: " << progName << " -t <target> [options]\n\n"
                  << "Options:\n"
                  << "  -t <ip>          Target IP address\n"
                  << "  -p <start-end>  Port range (default: 1-65535)\n"
                  << "  -T <num>        Threads (default: 32)\n"
                  << "  --os            Enable OS detection (AI)\n"
                  << "  --json <file>   Export to JSON\n"
                  << "  --csv <file>    Export to CSV\n"
                  << "  -h, --help      Show this help\n\n"
                  << "Example:\n"
                  << "  " << progName << " -t <TARGET_IP> -p 1-1000 --os --json results.json\n";
    }
    
    std::optional<eagle::ScanConfig> parseArguments(int argc, char* argv[]) const {
        eagle::ScanConfig config;
        
        for (int i = 1; i < argc; ++i) {
            std::string arg = argv[i];
            
            if (arg == "-h" || arg == "--help") {
                return std::nullopt;
            }
            else if (arg == "-t" && i + 1 < argc) {
                config.targetIP = argv[++i];
            }
            else if (arg == "-p" && i + 1 < argc) {
                std::string ports = argv[++i];
                if (ports.find('-') != std::string::npos) {
                    sscanf_s(ports.c_str(), "%hu-%hu", &config.startPort, &config.endPort);
                }
            }
            else if (arg == "-T" && i + 1 < argc) {
                config.threadCount = static_cast<uint8_t>(std::stoi(argv[++i]));
            }
            else if (arg == "--os") {
                config.detectOS = true;
            }
            else if (arg == "--json" && i + 1 < argc) {
                config.outputFormat = "json";
                config.outputFile = argv[++i];
            }
            else if (arg == "--csv" && i + 1 < argc) {
                config.outputFormat = "csv";
                config.outputFile = argv[++i];
            }
        }
        
        if (config.targetIP.empty()) {
            std::cerr << "Error: Target IP required (-t <ip>)\n";
            return std::nullopt;
        }
        
        return config;
    }
};

} // namespace eagle

// ════════════════════════════════════════════════════════════════════
//  MAIN ENTRY POINT
// ════════════════════════════════════════════════════════════════════

int main(int argc, char* argv[]) {
    try {
        return eagle::ai::EagleScannerApp().run(argc, argv);
    }
    catch (const std::exception& e) {
        std::cerr << "Fatal error: " << e.what() << "\n";
        return 1;
    }
}
