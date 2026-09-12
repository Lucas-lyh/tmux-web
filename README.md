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
| 🔑 一键接入 | 短期一次性接入命令，自动保存节点专属凭据，可逐个撤销 |
| 📦 文件直达 | 拖拽上传、点击路径下载，传输绑定原会话；CLI 完整下载后才替换目标文件 |
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
| `TMUX_WEB_BASE` | CLI 服务地址，默认 `http://127.0.0.1:59999` |
| `TMUX_WEB_SECRET` | CLI 密钥文件路径，默认项目内的 `.node-secret` |

密码和令牌保存在本机忽略文件中，没有内置默认密码。节点连接自动加密，无需额外配置；浏览器和普通 HTTP API 跨不可信网络访问时仍应使用 HTTPS。服务拥有运行用户的终端和文件权限，适合个人使用。

### 让 Agent 访问你的任何服务器

仓库自带 [tmux-web-api](skills/tmux-web-api/SKILL.md)（操作会话 / 传文件）和 [tmux-web-page](skills/tmux-web-page/SKILL.md)（发布临时报告）。

如安装到 Codex：

> codex，把skill部署到你的技能库


### 远程节点接入

任意能连接主服务器的 **Linux / Python 3.8+** 机器都可以接入，无需 tmux。**端口保持 `59999`，不用配置域名、证书或 CA。**

在仪表盘 nodes 面板点击 **+ add a node**，把复制的整条命令粘贴到节点执行即可。命令自动下载并校验单个脚本，节点名默认取主机名。节点仅使用 Python 标准库，不需要 pip、venv、加密包、证书或额外命令行工具，也不会自动安装任何东西。已使用新版加密连接的节点旁会显示 **🔒**。

已有脚本和密钥的节点也可继续用原来的启动形式：

```bash
python3 node.py --server ws://hub-host:59999/ws-node \
  --token-file "$HOME/.tmux-web-node-secret" --name gpu1
```

`--token` 和 `TMUX_WEB_NODE_TOKEN` 仍可使用；复制出的连接命令已包含必要参数，不需要再手工创建配置文件。

新复制的命令有效期为 **10 分钟**，成功接入后即失效，不包含主服务的管理密钥。脚本在加密通道中自动换取仅限该节点的长期凭据，以 `0600` 权限保存在 `~/.local/state/tmux-web/node-credentials/`；断线重连和再次执行同一命令会复用已保存的凭据。节点面板可撤销在线或离线节点的专属凭据。历史共享密钥接入继续兼容，不会被自动轮换。

**加密默认开启且不能降级关闭，算法实现内置于 `node.py`。**虽然地址仍写 `ws://`，节点业务数据已经在 WebSocket 内通过 `Noise_NNpsk0_25519_ChaChaPoly_SHA256` 加密：每次连接生成临时密钥，校验每条消息并拒绝篡改或重放。节点名、会话列表、控制消息、终端输入输出和文件内容都在加密通道内；节点密钥不放进网络请求 URL 或 HTTP 请求头。专属凭据使用随机公开标识选择密钥，标识不包含节点名称或密钥内容。

升级主服务后重新运行新版节点即可。服务端保留旧节点兼容用于迁移，旧节点不会因此自动变成加密连接。节点链路固定使用普通 WebSocket 承载脚本内置的加密记录，不使用 TLS。浏览器/API 的 HTTP 通道与节点通道分别处理；网络地址、握手、时序和数据量仍然可见，不保证规避网络策略。

纯 Python 加密会增加大文件传输的 CPU 开销；实现经过公开测试向量与独立实现互操作验证，尚未经独立安全审计，Python 大整数运算不保证恒定时间。

主服务重启后节点会自动重连；**节点进程退出或机器重启会丢失其 shell 会话**。连接后可在网页或 CLI 中使用 `gpu1:train`。

网页改密码会立即撤销旧网页登录，并给当前浏览器签发新登录状态；终端连接会短暂断开，底层会话与节点密钥保留。

可选的 srun 校园网重连登录默认关闭；需要时显式设置 `TMUX_WEB_PORTAL_URL`、`TMUX_WEB_PORTAL_USER`、`TMUX_WEB_PORTAL_PASS`。更多参数见 `python3 node.py --help`。

### CLI 自动化

```bash
.venv/bin/python client.py run gpu1:train 'printf hello'
.venv/bin/python client.py download /tmp/result.bin ./result.bin --node gpu1
```

`run` 保留当前 shell 的环境变化，并以远端命令退出码退出。Python 调用方可用 `run_result()` 获取输出与退出码，原来的 `run()` 仍返回文本。命令结果取自终端回放，超长输出与全屏交互程序仍有回放限制。

代理只重写明确的 HTML 资源属性、CSS URL 和 JavaScript 模块引用，保留普通业务字符串；动态网络请求由浏览器 shim 处理。应用使用特殊加载器或自行构造资源路径时，应配置其原生 base path。

### 开发

候选版本的隔离启动、A/B 对照和历史节点兼容性验收见 [AB_TESTING.md](AB_TESTING.md)。

```bash
.venv/bin/python -m unittest discover -v
```

[MIT License](LICENSE) · Built for terminals, humans & agents.
