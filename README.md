# WebRTC Tools

本项目旨在创建一系列 WebRTC 调试工具，帮助开发者测试和诊断 WebRTC 相关服务（如 STUN/TURN 服务器）。

## 工具列表

### 图形化界面 (app.py)

基于 Flet 的现代化跨平台图形界面工具。

#### 使用方法

```bash
uv run app.py
```

或者：

```bash
python app.py
```

### STUN/TURN 连接性测试 (main.py)

一个简单的 STUN 连接性测试工具，用于验证 STUN 服务器是否可用以及获取映射地址。

#### 使用方法

使用 `uv` 运行：

```bash
uv run main.py --host stun.allroundai.com --port 3478 --username uping --password uping
```

或者在激活虚拟环境后运行：

```bash
python main.py --host stun.allroundai.com --port 3478 --username uping --password uping
```

#### 参数说明

- `--host`: STUN/TURN 服务器地址 (默认: stun.allroundai.com)
- `--port`: 服务器端口 (默认: 3478)
- `--username`: 认证用户名 (可选)
- `--password`: 认证密码 (可选)
- `--timeout`: 超时时间 (秒)
- `--attempts`: 重试次数
