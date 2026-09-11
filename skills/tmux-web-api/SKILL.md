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

只有用户任务需要时才部署新节点。节点需要 Linux / Python 3.10+，`node.py` 使用标准库，无需 tmux。通过可信通道复制脚本与节点密钥，密钥文件权限设为 `600`，在节点执行：

```bash
python3 node.py --server wss://hub.example.com:59999/ws-node \
  --token-file "$HOME/.tmux-web-node-secret" --name gpu1
```

先更新主服务，使其支持 Bearer 节点认证，并准备 TLS 入口。主服务可同时设置 `TMUX_WEB_TLS_CERT`、`TMUX_WEB_TLS_KEY` 启用 HTTPS/WSS，也可使用已有的 HTTPS 反向代理；域名需与证书匹配。

节点默认要求 `wss://`，最低 TLS 1.2，验证证书链和主机名，认证令牌放在请求头中，不放在 URL 中。私有 CA 使用 `--ca-file /path/to/ca.pem` 或 `TMUX_WEB_CA_FILE`。控制消息、终端数据和文件传输都经过同一 TLS 连接。

节点也支持 `TMUX_WEB_NODE_TOKEN`，文件方式可避免把密钥放在进程参数中。只有显式传入 `--allow-insecure-ws` 才允许 `ws://`，用于本机测试或已有加密隧道；不能因证书报错而自行降级或关闭验证。TLS 不隐藏目标地址、时序和流量大小，不承诺规避网络策略。

主服务重启时节点会自动重连并重新注册现有会话。节点进程退出或机器重启会丢失节点会话；每个节点会话是一个 shell，没有 tmux 的窗口和面板。srun 校园网登录默认关闭，仅在显式配置 `TMUX_WEB_PORTAL_URL`、`TMUX_WEB_PORTAL_USER`、`TMUX_WEB_PORTAL_PASS` 时启用。
