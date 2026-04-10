# FastFile（Rust 版）

聊天式文件传输助手，单页前端 + Rust 后端，开箱即用。

## 功能

- 文本消息（代码不设长度上限）
- 文件上传（代码不设大小上限）
- 云端记录（SQLite + 文件系统）
- 直链下载（删除前有效，删除后立即失效）
- 图片缩略图预览、视频在线播放
- 管理模式勾选批量删除
- 单密码访问（默认 `REDACTED_PASSWORD`）
- 全局 no-cache
- 配置文件热加载（每 3 秒）

## 运行（本地）

```bash
cargo run --release
```

默认地址：`http://127.0.0.1:8000`

## 配置文件（热加载）

默认读取：`./fastfile.env`

- 每 3 秒自动重读一次
- 热加载变量：
  - `FASTFILE_PASSWORD`
  - `FASTFILE_SESSION_TTL_SECONDS`
- 启动期变量（建议改完重启）：
  - `FASTFILE_STORAGE`

你现在要求线上密码是 `REDACTED_PASSWORD`，默认配置已是这个值。

## 多架构 Release（GitHub Actions）

已内置工作流：`.github/workflows/release.yml`

触发方式：推送 tag（如 `v1.0.0`）后自动构建并发布附件。

默认产物架构：

- Linux x86_64
- Linux ARM64
- macOS x86_64
- macOS ARM64
- Windows x86_64

## 服务器部署教程（详细）

以下是 Linux 服务器标准部署流程。

### 1) 下载对应架构包

到 GitHub Release 页面下载，例如：

- `fastfile-x86_64-unknown-linux-gnu.tar.gz`
- `fastfile-aarch64-unknown-linux-gnu.tar.gz`

### 2) 解压到服务目录

```bash
mkdir -p /opt/fastfile
tar -xzf fastfile-x86_64-unknown-linux-gnu.tar.gz -C /opt/fastfile
cd /opt/fastfile/fastfile-x86_64-unknown-linux-gnu
```

### 3) 配置文件

编辑 `fastfile.env`，至少确认：

```env
FASTFILE_PASSWORD=REDACTED_PASSWORD
FASTFILE_STORAGE=/data/fastfile
FASTFILE_SESSION_TTL_SECONDS=86400
```

并创建存储目录：

```bash
mkdir -p /data/fastfile
```

### 4) 前台试运行

```bash
./fastfile
```

浏览器访问 `http://服务器IP:8000`，确认可登录、上传、下载、删除。

### 5) 配置 systemd 常驻

创建 `/etc/systemd/system/fastfile.service`：

```ini
[Unit]
Description=FastFile Service
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/fastfile/fastfile-x86_64-unknown-linux-gnu
ExecStart=/opt/fastfile/fastfile-x86_64-unknown-linux-gnu/fastfile
Restart=always
RestartSec=3
User=root

[Install]
WantedBy=multi-user.target
```

启动并开机自启：

```bash
systemctl daemon-reload
systemctl enable --now fastfile
systemctl status fastfile
```

### 6) 反向代理（可选，推荐）

如果你用 Nginx：

```nginx
server {
    listen 80;
    server_name your.domain.com;

    client_max_body_size 0;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

重载：

```bash
nginx -t
systemctl reload nginx
```

### 7) 升级流程

1. 下载新 release 包并解压到新目录
2. 保留原 `fastfile.env`
3. 切换 systemd 的 `WorkingDirectory` 和 `ExecStart`
4. `systemctl daemon-reload && systemctl restart fastfile`

## 许可证

MIT（见 `LICENSE`）
