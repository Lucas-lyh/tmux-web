<div align="center">

# 🖥️ tmux-web

**Tmux session is all you need for agent.**

一台公网服务器，把所有服务器聚合，串起 tmux、远程节点和 AI Agent 工作流。 

![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB?logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Linux-111827?logo=linux&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-22c55e)
[![Tests](https://github.com/Lucas-lyh/tmux-web/actions/workflows/ci.yml/badge.svg)](https://github.com/Lucas-lyh/tmux-web/actions/workflows/ci.yml)

</div>

```text
  手机 / 浏览器 / AI Agent
            │
         tmux-web
            ├── 本机 tmux      → 随时接回工作现场
            ├── 远程节点       → gpu1:train / build:test
            ├── Pages          → Agent 生成的报告与图表
            └── Port Proxy     → 浏览本机开发服务
```

### 使用场景

> 去我刚申请的H100节点复现一下这篇论文的实验

> 把这个项目部署到我的生产服务器prod1到prod10上

> 开10个kimi session，让它们分工分析一下我的存储占用

### 有什么好玩的？

| | 特性 |
| --- | --- |
| ⌨️ 随身终端 | xterm.js 实时交互、移动端辅助按键、中文输入与断线重连 |
| 🌐 多机一屏 | 本机 tmux + 主动接入的远程节点，统一管理 `node:session` |
| 🔒 加密连接 | 节点默认使用 WSS，验证服务器证书，控制消息、终端和文件统一通过 TLS 传输 |
| 📦 文件直达 | 浏览器拖拽上传、点击文件路径下载； |
| 📊 状态速览 | CPU、内存、GPU、网络、磁盘，以及本机 Codex / Kimi Token 统计 |
| 🪄 Agent 汇聚 | 一个session一个agent，skill支持让agent直接访问任何联网节点 |
| 🗂️ 临时网页 | HTML 放进 `pages/` 即可展示报告；24 小时后自动清理 |
| 🔌 开发预览 | 登录后通过 `/port/<端口>/` 访问主机上的 HTTP、WebSocket、SSE 服务 |

### 三步启动

> codex/claude/kimi，给我部署https://github.com/Lucas-lyh/tmux-web

主机需要 **Linux、Python 3.11+、tmux**。无需 Node.js 或前端构建；终端前端从 CDN 加载 xterm.js，浏览器需能访问该 CDN。

```bash
# 1. 获取项目（Debian / Ubuntu 可用 sudo apt install tmux 安装 tmux）
git clone https://github.com/Lucas-lyh/tmux-web.git
cd tmux-web

# 2. 安装依赖
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt

# 3. 启动，按提示设置首次登录密码
.venv/bin/python server.py
```

打开 **http://localhost:59999**。首次密码至少 8 个字符；已有安装继续使用原来的密码。

| 环境变量 | 用途 |
| --- | --- |
| `TMUX_WEB_HOST` | 监听地址，默认 `0.0.0.0` |
| `TMUX_WEB_PORT` | 监听端口，默认 `59999` |
| `TMUX_WEB_PASSWORD` | 非交互部署时设置首次密码；已有 `.auth.json` 时不覆盖 |
| `TMUX_WEB_TLS_CERT` / `TMUX_WEB_TLS_KEY` | 同时设置证书链和私钥文件路径，启用原生 HTTPS/WSS |
| `TMUX_WEB_BASE` | CLI 服务地址，默认 `http://127.0.0.1:59999` |
| `TMUX_WEB_SECRET` | CLI 密钥文件路径，默认项目内的 `.node-secret` |

密码和令牌保存在本机忽略文件中，没有内置默认密码。上面的 HTTP 启动适合本机使用；跨网络访问应启用下面的 HTTPS/WSS 配置或使用 HTTPS 反向代理。服务拥有运行用户的终端和文件权限，适合个人使用。

### 让 Agent 访问你的任何服务器

仓库自带 [tmux-web-api](skills/tmux-web-api/SKILL.md)（操作会话 / 传文件）和 [tmux-web-page](skills/tmux-web-page/SKILL.md)（发布临时报告）。

如安装到 Codex：

> codex，把skill部署到你的技能库


### 远程节点接入

任意能连接主服务器的远程机器仅需 **Linux / Python 3.10+** 即可接入 tmux 网络，甚至无需 tmux 或第三方 Python 包。

先为主服务配置与访问域名匹配的证书，启用 HTTPS/WSS（也可以使用已有的 HTTPS 反向代理）：

```bash
export TMUX_WEB_TLS_CERT=/path/to/fullchain.pem
export TMUX_WEB_TLS_KEY=/path/to/privkey.pem
.venv/bin/python server.py
```

将新版 `node.py` 和主机的 `.node-secret` 通过可信通道复制到节点，把密钥存为权限 `600` 的 `~/.tmux-web-node-secret`，然后运行：

```bash
python3 node.py --server wss://hub.example.com:59999/ws-node \
  --token-file "$HOME/.tmux-web-node-secret" --name gpu1
```

通过 HTTPS 打开仪表盘时，nodes 面板的 **copy node key** 可复制节点密钥，**+ add a node** 可复制当前入口的连接命令。

证书使用私有 CA 时，节点额外传入 `--ca-file /path/to/ca.pem`，或设置 `TMUX_WEB_CA_FILE`。客户端始终验证证书链和主机名，最低 TLS 1.2，不自动降级到明文。公网反向代理入口通常使用 `wss://hub.example.com/ws-node`，记得转发 WebSocket Upgrade 和 Authorization 请求头。

浏览器使用对应的 `https://` 地址；CLI 设置 `TMUX_WEB_BASE=https://hub.example.com:59999`，私有 CA 可通过 `SSL_CERT_FILE=/path/to/ca.pem` 配置。节点令牌通过 TLS 握手中的 Bearer 请求头传递，不再出现在节点连接 URL 中。

**升级时先更新主服务并准备 TLS 入口，再更新节点。**旧服务不接受新的节点认证头，仅替换 `node.py` 无法建立加密连接。新版服务保留旧节点的认证兼容；新版节点只有显式指定 `--allow-insecure-ws` 才允许 `ws://`，供本机调试或已受保护的隧道使用，该选项本身不加密。

连接后即可在网页或 CLI 中使用 `gpu1:train`。节点密钥拥有完整管理权限，请保存在版本控制之外。TLS 保护传输内容，连接地址、时序和数据量仍然可见，不保证规避网络策略。主机重启后节点会自动重连；**节点进程退出或节点机器重启会丢失其会话**。

可选的 srun 校园网重连登录默认关闭；需要时显式设置 `TMUX_WEB_PORTAL_URL`、`TMUX_WEB_PORTAL_USER`、`TMUX_WEB_PORTAL_PASS`。更多参数见 `python3 node.py --help`。

### 开发

```bash
.venv/bin/python -m unittest discover -v
```

[MIT License](LICENSE) · Built for terminals, humans & agents.
