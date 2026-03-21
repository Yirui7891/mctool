一个电脑小工具
用于服务器监控，mc新闻，一键启动；deepseek提示词模板，项目结构文本一键变成文件，可视化git
由yuanh4148, 开发，目标是在2026上半年完成


MCTool/

│

├── src/                      # 源代码目录

│   ├── Config.h              # 配置结构体声明，加载 config.json

│   ├── Config.cpp            # 配置解析实现（支持 game 节点可选）

│   ├── GameLauncher.h        # 游戏启动函数声明（无参，执行 start_game.bat）

│   ├── GameLauncher.cpp      # 启动游戏：调用 ShellExecute 执行同目录下的 start_game.bat

│   ├── MainWindow.h          # 主窗口类（隐藏窗口，负责鼠标检测和定时器）

│   ├── MainWindow.cpp        # 主窗口实现：鼠标边缘检测、服务器 ping 定时器、弹窗管理

│   ├── PopupWindow.h         # 弹窗类声明（含按钮悬停效果、退出按钮）

│   ├── PopupWindow.cpp       # 弹窗实现：自绘按钮、鼠标悬停变化（文字加粗、变色、边框亮化）

│   ├── ServerPinger.h        # 服务器状态结构体 + PingServer 函数声明

│   ├── ServerPinger.cpp      # 服务器 ping 实现（现代+旧版协议，带调试输出）

│   ├── Utils.h               # 工具函数声明（VarInt 编解码）

│   ├── Utils.cpp             # VarInt 编解码实现

│   ├── NewsFetcher.h         # （未使用）新闻获取函数声明

│   ├── NewsFetcher.cpp       # （未使用）新闻获取实现（HTTP GET）

│   └── main.cpp              # WinMain 入口，创建主窗口并运行消息循环

│

├── include/                  # 第三方库头文件

│   └── nlohmann/

│       └── json.hpp          # JSON 解析库（单头文件）

│

├── config.json               # 配置文件（可省略 game 节点，必须包含 server 和 ui 基本配置）

├── 编译.bat                  # 编译脚本（使用 MinGW g++，链接 ws2_32、wininet、gdi32，-mwindows 隐藏控制台）

└── README.md                 # （可选）项目说明

启动游戏部分的.bat文件需要手动放入根目录,下个版本可能会整理代码