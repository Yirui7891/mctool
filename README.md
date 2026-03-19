一个电脑小工具
用于服务器监控，mc新闻，一键启动；deepseek提示词模板，项目结构文本一键变成文件
由yuanh4148, 开发，目标是在2026上半年完成


MCTool/

│

├── src/

│   ├── main.cpp                 // 程序入口（WinMain）

│   ├── MainWindow.h/cpp          // 主窗口（隐藏窗口，负责鼠标检测和线程管理）

│   ├── PopupWindow.h/cpp         // 弹窗窗口（UI布局、显示更新）

│   ├── Config.h/cpp              // 配置加载（使用nlohmann/json解析config.json）

│   ├── ServerPinger.h/cpp        // Minecraft服务器状态查询（原版协议）

│   ├── NewsFetcher.h/cpp         // 新闻获取（HTTP GET）

│   ├── GameLauncher.h/cpp        // 游戏启动（根据配置调用CreateProcess）

│   ├── ModuleManager.h/cpp       // 模块化扩展管理（预留）

│   └── Utils.h/cpp               // 工具函数（VarInt编解码、字符串转换等）

│

├── include/                      // 第三方库头文件

│   └── json.hpp                   // nlohmann/json 单头文件

│

├── resources/                     // 图标等资源（可选）

│

├── config.json                    // 配置文件（需与exe同目录）

├── CMakeLists.txt                 // CMake构建文件（或直接使用VS工程）

└── README.md                      // 使用说明
