---
name: tmux-web-api
description: 通过 tmux-web CLI 和 HTTP/WebSocket API 管理本机及远程节点终端会话、执行命令、读取输出和传输文件。用于用户要求在已配置的 tmux-web 主机或节点上操作终端时。
---

# tmux-web 终端与节点

先确定用户的 tmux-web 克隆目录和服务地址。不要假定本机的个人路径、节点名称或凭据；项目未定位时询问实际路径。以下命令从项目根目录运行，默认服务地址为 `http://127.0.0.1:59999`。

## 优先使用客户端

`client.py` 读取项目内的 `.node-secret` 作 Bearer 认证；主服务首次成功启动时会生成此文件。服务地址不同则配置 `TMUX_WEB_BASE`，密钥文件在别处则配置 `TMUX_WEB_SECRET`（这是文件路径）。不要输出密钥或把其值写进文档、脚本、网页、聊天回复。

跨网络使用 HTTPS 服务地址；私有 CA 可通过 `SSL_CERT_FILE` 指定。默认的 HTTP 地址用于本机访问，不提供传输加密。

```bash
.venv/bin/python client.py sessions
.venv/bin/python client.py new demo
.venv/bin/python client.py run demo 'uname -a' --timeout 30
.venv/bin/python client.py capture demo 100
.venv/bin/python client.py send demo $'ls\n'
.venv/bin/python client.py upload ./result.csv
.venv/bin/python client.py download /tmp/result.csv ./result.csv
.venv/bin/python client.py kill demo
```

会话名没有前缀时指本机 tmux；`<节点名>:<会话名>` 指在线子节点。先列出会话或节点，确认实际节点名，再使用例如 `gpu1:train` 的名称。上传和下载使用 `--node gpu1` 选择节点：

```bash
.venv/bin/python client.py new gpu1:train
.venv/bin/python client.py run gpu1:train 'nvidia-smi' --timeout 60
.venv/bin/python client.py upload ./input.bin --node gpu1
.venv/bin/python client.py download /tmp/output.bin ./output.bin --node gpu1
```

- `run` 通过发送完成标记并轮询 `capture` 判断结束，只保留最近 300 行；长输出应先重定向到文件再下载。
- `run` 不适合 vim、less、htop 等全屏程序，也不提供可靠的远端命令退出码；需要判断成功时让命令输出明确的状态或检查产物。
- `send` 像键盘输入，换行表示回车。它不会等待命令执行结束。
- 只有用户要结束会话时才 `kill`；不要因一次命令完成就销毁用户原有会话。

## 原始接口

客户端未覆盖的需求再使用 API。HTTP 参数均为 query string，应使用 URL 编码。除登录接口外，以下操作需要 Cookie 或 `Authorization: Bearer <节点密钥>`。优先在代码中读取密钥并设置请求头，不在 shell 调试输出中展开凭据。

| 路径 | 参数 / 行为 |
| --- | --- |
| `/api/sessions` | 列出本机及节点会话，节点会话带 `node` 字段 |
| `/api/new` | `name`：创建会话 |
| `/api/send` | `name`、`text`：输入文本 |
| `/api/capture` | `name`、`lines`：返回去除 ANSI 转义的最近输出，默认 50、最大 2000 行 |
| `/api/kill` | `name`：销毁会话 |
| `/api/nodes` | 返回节点列表及加入密钥；展示结果时去掉 `secret` 字段 |
| `/api/download` | `path`、可选 `node`：下载文件，上限 1 GiB |

`capture` 是文本记录，不是完整终端屏幕状态。实时终端使用 `/ws?session=<URL编码会话名>`：二进制帧双向传输终端数据，文本帧 `{"type":"resize","cols":120,"rows":40}` 调整尺寸，认证同上。

上传使用 `/ws-upload`，可附 `?node=<节点名>`。连接后发送 JSON 头 `{"name":"input.bin","size":123}`，再发送对应字节数的二进制帧。收到 `{"ok":true,"path":"..."}` 后使用返回路径；失败时不要猜测目标路径。上传上限 2 GiB，临时文件约 24 小时清理。

## 新增节点

只有用户任务需要时才部署新节点。节点需要 Linux / Python 3.10+，无需 tmux；首次运行自动在用户私有缓存中准备 `noiseprotocol` 依赖（需要包源网络访问和 pip 或 venv/ensurepip）。

用户可在仪表盘 nodes 面板点 **+ add a node** 复制一条命令，自动下载校验脚本并启动；节点名默认使用主机名。不要把含凭据的复制命令贴进日志或聊天回复。已有脚本和密钥文件时：

```bash
python3 node.py --server ws://hub-host:59999/ws-node \
  --token-file "$HOME/.tmux-web-node-secret" --name gpu1
```

默认在现有 WebSocket 内使用 `Noise_NNpsk0_25519_ChaChaPoly_SHA256` 进行双向认证和加密，无需证书、域名或更换端口。节点只发送不含凭据和节点名的 `/ws-node?v=2` 升级请求，Noise 握手后才发送加密的注册信息。控制消息、终端数据和文件传输都受保护，认证失败或数据被篡改时关闭连接，不降级明文。

先更新主服务，再更新节点；旧节点兼容通道不会自动获得加密。`wss://` 仍支持作为额外外层 TLS，需要时可用 `--ca-file`，普通 `ws://` 节点连接不需要该配置。`TMUX_WEB_NODE_TOKEN` 和 `--token` 仍受支持，密钥文件方式能避免在命令参数里存放凭据。

浏览器与普通 HTTP API 不经过节点的 Noise 通道，跨不可信网络仍需 HTTPS。加密不隐藏网络地址、握手、时序和流量大小，不承诺规避网络策略。

主服务重启时节点会自动重连并重新注册现有会话。节点进程退出或机器重启会丢失节点会话；每个节点会话是一个 shell，没有 tmux 的窗口和面板。srun 校园网登录默认关闭，仅在显式配置 `TMUX_WEB_PORTAL_URL`、`TMUX_WEB_PORTAL_USER`、`TMUX_WEB_PORTAL_PASS` 时启用。
