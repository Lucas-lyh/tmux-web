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
| 🔒 加密连接 | 原端口自动加密，控制消息、终端和文件统一通过 Noise 认证加密通道传输 |
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

密码和令牌保存在本机忽略文件中，没有内置默认密码。节点连接自动加密，无需额外配置；浏览器和普通 HTTP API 跨不可信网络访问时仍应使用 HTTPS。服务拥有运行用户的终端和文件权限，适合个人使用。

### 让 Agent 访问你的任何服务器

仓库自带 [tmux-web-api](skills/tmux-web-api/SKILL.md)（操作会话 / 传文件）和 [tmux-web-page](skills/tmux-web-page/SKILL.md)（发布临时报告）。

如安装到 Codex：

> codex，把skill部署到你的技能库


### 远程节点接入

任意能连接主服务器的 **Linux / Python 3.10+** 机器都可以接入，无需 tmux。**端口保持 `59999`，不用配置域名、证书或 CA。**

在仪表盘 nodes 面板点击 **+ add a node**，把复制的整条命令粘贴到节点执行即可。命令自动下载并校验脚本，节点名默认取主机名；首次运行自动在用户私有缓存中准备加密依赖，需要可用的 Python 包源与 pip 或 venv/ensurepip。后续启动复用缓存。已使用新版加密连接的节点旁会显示 **🔒**。

已有脚本和密钥的节点也可继续用原来的启动形式：

```bash
python3 node.py --server ws://hub-host:59999/ws-node \
  --token-file "$HOME/.tmux-web-node-secret" --name gpu1
```

`--token` 和 `TMUX_WEB_NODE_TOKEN` 仍可使用；复制出的连接命令已包含必要参数，不需要再手工创建配置文件。命令含节点凭据，请只在你自己的节点执行。

**加密默认开启且不能降级关闭。**虽然地址仍写 `ws://`，节点业务数据已经在 WebSocket 内通过 `Noise_NNpsk0_25519_ChaChaPoly_SHA256` 加密：复用现有随机节点密钥认证，每次连接生成临时密钥，校验每条消息并拒绝篡改或重放。节点名、会话列表、控制消息、终端输入输出和文件内容都在加密通道内；节点密钥不放进网络请求 URL 或 HTTP 请求头。

升级主服务后重新运行新版节点即可。服务端保留旧节点兼容用于迁移，旧节点不会因此自动变成加密连接。已有 HTTPS/WSS 入口也可继续使用，但它不是节点加密的前提。浏览器/API 的 HTTP 通道与节点通道分别处理；网络地址、握手、时序和数据量仍然可见，不保证规避网络策略。

主服务重启后节点会自动重连；**节点进程退出或机器重启会丢失其 shell 会话**。连接后可在网页或 CLI 中使用 `gpu1:train`。

可选的 srun 校园网重连登录默认关闭；需要时显式设置 `TMUX_WEB_PORTAL_URL`、`TMUX_WEB_PORTAL_USER`、`TMUX_WEB_PORTAL_PASS`。更多参数见 `python3 node.py --help`。

### 开发

```bash
.venv/bin/python -m unittest discover -v
```

[MIT License](LICENSE) · Built for terminals, humans & agents.
