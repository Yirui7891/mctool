// ServerPinger.h
#pragma once
#include <string>
#include <vector>
#include <cstdint>

struct ServerMod {
    std::string modid;
    std::string version;
};

struct ServerStatus {
    bool online = false;
    std::string motd;
    int players = 0;
    int maxPlayers = 0;
    std::string version;
    int latency = 0;

    // 新增字段
    std::string favicon_base64;          // base64 编码的图标数据
    std::vector<ServerMod> mods;         // 模组列表
    std::vector<std::string> playerList; // 玩家列表（预留）
};

bool PingServer(const std::string& host, uint16_t port, ServerStatus& status);