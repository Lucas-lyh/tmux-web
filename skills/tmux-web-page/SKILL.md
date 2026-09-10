---
name: tmux-web-page
description: 向已配置的 tmux-web 仪表盘发布短期 HTML 网页，展示报告、图表、状态面板或操作指引。用于用户希望在仪表盘查看可视化结果时，不用于长期网站托管。
---

# 发布临时网页

确认运行中的 tmux-web 项目根目录与用户可访问的服务地址，不假定个人绝对路径或内网地址。默认服务端口为 `59999`，也可能通过 `TMUX_WEB_PORT` 或反向代理变更。

## 发布

把一个自包含 HTML 文件写入项目根目录下的 `pages/` 即完成发布，无需 API 或服务重启。目录不存在时创建；写入前确认当前工作目录就是目标项目。

```bash
mkdir -p pages
cat > pages/task-report.html <<'HTML'
<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>任务报告</title>
  <style>
    :root {
      --bg: #0f1117; --panel: #161a23; --border: #262c3a;
      --fg: #d6dae3; --dim: #7a8394; --accent: #4f9cff;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0; padding: 20px; background: var(--bg); color: var(--fg);
      font: 15px/1.6 system-ui, sans-serif;
    }
    main { max-width: 960px; margin: auto; }
    article {
      padding: 20px; background: var(--panel);
      border: 1px solid var(--border); border-radius: 12px;
    }
  </style>
</head>
<body><main><article>
  <h1>任务报告</h1>
  <p>在这里呈现已核实的结论与数据。</p>
</article></main></body>
</html>
HTML
```

根据用户任务替换示例内容。文件名使用 1–64 个小写字母、数字、中划线或下划线，加 `.html` 后缀。页面列表标题来自 `<title>`。覆盖同名文件会更新页面，删除文件会下线页面。

## 页面约束

- 文件最后修改约 24 小时后由服务清理，不用于长期存储。若用户需要保留结果，另存一份到 `pages/` 之外。
- 仪表盘以 `sandbox="allow-scripts"` 的 iframe 展示页面：可运行 JS，但无法访问父页面、Cookie 或 localStorage。不要依赖父页面身份或认证 API。
- CSS、JS、数据全部内联；图形可用内联 SVG 或 canvas，不引用 CDN、外部字体或其他网络资源。不要把密钥、密码或未经授权的私人信息写入 HTML。
- 与仪表盘保持深色主题，适配手机宽度。先展示关键结论，再放证据；需要时增加筛选、排序或折叠，避免无意义动画。
- 发布前检查真实数据、标题和小屏布局。将动态数据插入 HTML 时正确转义，避免数据被解释为脚本。

## 交付

告诉用户页面标题，以及在 tmux-web 左侧 **pages** 面板点击查看的方式，说明约 24 小时后过期。只有确认了用户可访问的服务地址，才提供直接链接；不要把远程机器的 `localhost` 当成用户的浏览器地址。
