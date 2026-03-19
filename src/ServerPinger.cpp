#include "ServerPinger.h"
#include "Utils.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <nlohmann/json.hpp>
#include <vector>
#include <cstring>
#include <string>
#include <chrono>
#include <thread>
#include <sstream>
#include <iomanip>
#include <stack>
#pragma comment(lib, "ws2_32.lib")

// 启用调试输出（0=关闭，1=打开）
#define ENABLE_DEBUG_OUTPUT 1

#if ENABLE_DEBUG_OUTPUT
#include <windows.h>
#define DEBUG_LOG(msg) { std::stringstream ss; ss << "[McPing] " << msg << "\n"; OutputDebugStringA(ss.str().c_str()); }
#else
#define DEBUG_LOG(msg)
#endif

using json = nlohmann::json;
using namespace std::chrono;

// 协议常量
const int PROTOCOL_VERSION = 772;          // 对应 C# 中的 772 (1.19.2)
const int DEFAULT_TIMEOUT = 10000;         // 默认超时 10 秒

// ---------- 辅助函数：将 JSON description 转换为纯文本（模仿 C# _ConvertJNodeToMcString）----------
static std::string ConvertJNodeToMcString(const json& node) {
    std::string result;
    std::stack<json> stack;
    stack.push(node);

    while (!stack.empty()) {
        json current = stack.top();
        stack.pop();

        if (current.is_object()) {
            // 处理 extra 数组（逆序压栈保持原始顺序）
            if (current.contains("extra") && current["extra"].is_array()) {
                const auto& extra = current["extra"];
                for (int i = extra.size() - 1; i >= 0; --i) {
                    if (!extra[i].is_null())
                        stack.push(extra[i]);
                }
            }
            // 处理 text 属性
            if (current.contains("text") && current["text"].is_string()) {
                // 忽略颜色代码（C# 中附加了颜色格式，但我们只取纯文本）
                result += current["text"].get<std::string>();
            }
        }
        else if (current.is_string()) {
            result += current.get<std::string>();
        }
        else if (current.is_array()) {
            const auto& arr = current;
            for (int i = arr.size() - 1; i >= 0; --i) {
                if (!arr[i].is_null())
                    stack.push(arr[i]);
            }
        }
        else {
            DEBUG_LOG("无法处理的 Motd 内容类型: " << current.type_name());
        }
    }
    DEBUG_LOG("处理 Motd 内容完成，结果：" << result);
    return result;
}

// ---------- 构建握手包（现代协议）----------
static std::vector<uint8_t> BuildHandshakePacket(const std::string& host, uint16_t port) {
    std::vector<uint8_t> packet;
    // 包 ID = 0 (handshake)
    WriteVarInt(packet, 0);
    // 协议版本（C# 中固定为 772）
    WriteVarInt(packet, PROTOCOL_VERSION);
    // 服务器地址长度
    WriteVarInt(packet, host.size());
    // 服务器地址
    packet.insert(packet.end(), host.begin(), host.end());
    // 服务器端口（大端序）
    packet.push_back((port >> 8) & 0xFF);
    packet.push_back(port & 0xFF);
    // 下一状态：1 = status
    WriteVarInt(packet, 1);

    // 最终包：长度前缀 + 包内容
    std::vector<uint8_t> finalPacket;
    WriteVarInt(finalPacket, packet.size());
    finalPacket.insert(finalPacket.end(), packet.begin(), packet.end());
    return finalPacket;
}

// ---------- 构建状态请求包----------
static std::vector<uint8_t> BuildStatusRequestPacket() {
    std::vector<uint8_t> packet;
    // 包 ID = 0 (status request)
    WriteVarInt(packet, 0);
    // 最终包：长度前缀 + 包内容
    std::vector<uint8_t> finalPacket;
    WriteVarInt(finalPacket, packet.size());
    finalPacket.insert(finalPacket.end(), packet.begin(), packet.end());
    return finalPacket;
}

// ---------- 现代协议探测（同步实现，对应 C# McPingService.PingAsync）----------
static bool PingModern(SOCKET sock, const std::string& host, uint16_t port, ServerStatus& status, long long& latencyMs) {
    DEBUG_LOG("开始现代协议探测...");
    auto start = high_resolution_clock::now();

    // 发送握手包
    auto handshake = BuildHandshakePacket(host, port);
    if (send(sock, (char*)handshake.data(), handshake.size(), 0) != handshake.size()) {
        DEBUG_LOG("握手包发送失败");
        return false;
    }
    DEBUG_LOG("握手包发送成功，长度=" << handshake.size());

    // 发送状态请求包
    auto request = BuildStatusRequestPacket();
    if (send(sock, (char*)request.data(), request.size(), 0) != request.size()) {
        DEBUG_LOG("状态请求包发送失败");
        return false;
    }
    DEBUG_LOG("状态请求包发送成功，长度=" << request.size());

    // 读取响应包长度（VarInt）
    int packetLen;
    if (!ReadVarInt(sock, packetLen)) {
        DEBUG_LOG("读取响应包长度失败");
        return false;
    }
    DEBUG_LOG("响应包长度=" << packetLen);

    // 读取包 ID（应为 0）
    int packetId;
    if (!ReadVarInt(sock, packetId) || packetId != 0) {
        DEBUG_LOG("读取包 ID 失败或不为 0: " << packetId);
        return false;
    }
    DEBUG_LOG("包 ID=" << packetId);

    // 读取 JSON 数据长度（VarInt）
    int jsonLen;
    if (!ReadVarInt(sock, jsonLen)) {
        DEBUG_LOG("读取 JSON 长度失败");
        return false;
    }
    DEBUG_LOG("JSON 长度=" << jsonLen);

    // 读取 JSON 数据
    std::vector<char> jsonBuf(jsonLen + 1, 0);
    int total = 0;
    while (total < jsonLen) {
        int recvd = recv(sock, &jsonBuf[total], jsonLen - total, 0);
        if (recvd <= 0) {
            DEBUG_LOG("读取 JSON 数据失败，已接收=" << total << " 期望=" << jsonLen);
            break;
        }
        total += recvd;
    }
    if (total != jsonLen) {
        DEBUG_LOG("JSON 数据不完整");
        return false;
    }
    DEBUG_LOG("JSON 数据接收完成");

    auto end = high_resolution_clock::now();
    latencyMs = duration_cast<milliseconds>(end - start).count();

    try {
        json j = json::parse(jsonBuf.data());
        DEBUG_LOG("原始 JSON: " << j.dump());

        // 处理 description 字段（如果为对象则转换为纯文本）
        if (j.contains("description") && j["description"].is_object()) {
            j["description"] = ConvertJNodeToMcString(j["description"]);
        }

        // 反序列化到 ServerStatus
        status.online = true;
        if (j.contains("version") && j["version"].is_object()) {
            status.version = j["version"]["name"].get<std::string>();
        }
        if (j.contains("players") && j["players"].is_object()) {
            status.players = j["players"]["online"].get<int>();
            status.maxPlayers = j["players"]["max"].get<int>();
        }
        if (j.contains("description")) {
            status.motd = j["description"].get<std::string>();
        }
        // 其他字段如 favicon、modinfo 等暂时忽略（与原有 ServerStatus 兼容）

        DEBUG_LOG("现代协议解析成功，版本=" << status.version << " 玩家=" << status.players << "/" << status.maxPlayers);
        return true;
    }
    catch (const std::exception& e) {
        DEBUG_LOG("JSON 解析异常: " << e.what());
        return false;
    }
}

// ---------- 旧版协议探测（对应 C# LegacyMcPingService.PingAsync，但已修正 UTF-16BE 解析）----------
static bool PingLegacy(SOCKET sock, const std::string& host, uint16_t port, ServerStatus& status) {
    DEBUG_LOG("尝试旧版协议探测...");
    uint8_t legacyReq[] = { 0xFE, 0x01 };
    if (send(sock, (char*)legacyReq, sizeof(legacyReq), 0) != sizeof(legacyReq)) {
        DEBUG_LOG("旧版请求发送失败");
        return false;
    }
    DEBUG_LOG("旧版请求发送成功");

    uint8_t buffer[2048];
    int received = recv(sock, (char*)buffer, sizeof(buffer), 0);
    if (received < 3) {
        DEBUG_LOG("旧版响应接收过短: " << received);
        return false;
    }
    if (buffer[0] != 0xFF) {
        DEBUG_LOG("旧版响应首字节不是 0xFF: " << (int)buffer[0]);
        return false;
    }

    int dataLen = received - 3;
    if (dataLen % 2 != 0) {
        DEBUG_LOG("旧版数据长度为奇数: " << dataLen);
        return false;
    }

    // 将 UTF-16BE 转换为 UTF-8
    std::vector<wchar_t> wide(dataLen / 2 + 1);
    for (int i = 0; i < dataLen / 2; i++) {
        wide[i] = (buffer[3 + i * 2] << 8) | buffer[3 + i * 2 + 1];
    }
    wide[dataLen / 2] = 0;
    int utf8Len = WideCharToMultiByte(CP_UTF8, 0, wide.data(), -1, NULL, 0, NULL, NULL);
    std::string utf8(utf8Len, 0);
    WideCharToMultiByte(CP_UTF8, 0, wide.data(), -1, &utf8[0], utf8Len, NULL, NULL);
    DEBUG_LOG("旧版原始 UTF8: " << utf8);

    // 按两个空字符分割（对应 C# 中的 Split(["\0\0\0"])，但 C# 逻辑有误，这里采用正确方式）
    std::vector<std::string> parts;
    size_t pos = 0;
    while (pos < utf8.size()) {
        size_t next = utf8.find('\0', pos);
        if (next == std::string::npos) break;
        parts.push_back(utf8.substr(pos, next - pos));
        pos = next + 1;
    }
    DEBUG_LOG("旧版分割后字段数: " << parts.size());

    // 根据 C# 代码，期望至少 6 个字段
    if (parts.size() >= 6) {
        try {
            status.online = true;
            status.version = parts[2];          // 对应 C# 中的 retPart[2]
            status.players = std::stoi(parts[5]); // 对应 C# 中的 retPart[5]
            status.maxPlayers = std::stoi(parts[4]); // 对应 C# 中的 retPart[4]
            status.motd = parts[3];              // 对应 C# 中的 retPart[3]
            status.latency = 0;                  // 旧版无延迟
            DEBUG_LOG("旧版解析成功，版本=" << status.version << " 玩家=" << status.players << "/" << status.maxPlayers);
            return true;
        }
        catch (const std::exception& e) {
            DEBUG_LOG("旧版解析异常: " << e.what());
            return false;
        }
    }
    DEBUG_LOG("旧版解析失败，字段数不足");
    return false;
}

// ---------- 主函数：PingServer（对外接口）----------
bool PingServer(const std::string& host, uint16_t port, ServerStatus& status) {
    DEBUG_LOG("PingServer 开始: host=" << host << " port=" << port);

    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        DEBUG_LOG("WSAStartup 失败");
        return false;
    }

    SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET) {
        DEBUG_LOG("socket 创建失败");
        WSACleanup();
        return false;
    }

    // 设置接收超时（与 C# 的 Timeout 对应）
    int timeout = DEFAULT_TIMEOUT;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    // 地址解析
    if (inet_pton(AF_INET, host.c_str(), &addr.sin_addr) != 1) {
        struct hostent* he = gethostbyname(host.c_str());
        if (!he) {
            DEBUG_LOG("DNS 解析失败: " << host);
            closesocket(sock);
            WSACleanup();
            return false;
        }
        memcpy(&addr.sin_addr, he->h_addr_list[0], he->h_length);
        DEBUG_LOG("DNS 解析成功: " << inet_ntoa(addr.sin_addr));
    }

    // 连接
    if (connect(sock, (sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        DEBUG_LOG("连接失败，错误码=" << WSAGetLastError());
        closesocket(sock);
        WSACleanup();
        return false;
    }
    DEBUG_LOG("连接成功");

    long long latency = 0;
    bool success = PingModern(sock, host, port, status, latency);
    if (!success) {
        DEBUG_LOG("现代协议失败，尝试旧版...");
        success = PingLegacy(sock, host, port, status);
    }
    else {
        status.latency = static_cast<int>(latency);
        DEBUG_LOG("现代协议成功，延迟=" << status.latency << "ms");
    }

    closesocket(sock);
    WSACleanup();
    return success;
}