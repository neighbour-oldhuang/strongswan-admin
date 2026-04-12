# StrongSwan Admin

基于 FastAPI 的 StrongSwan Web 管理控制台。

## 功能

- **实例控制**：启动 / 停止 / 重启 / 重载 strongSwan 服务
- **连接管理**：可视化创建、编辑、删除 IPSec 连接，每个配置项附带说明
- **证书管理**：上传 CA 证书、本端证书、私钥
- **实时监控**：SA 状态、系统日志自动刷新

## 快速开始

```bash
# 需要 root（写入 /etc/swanctl/）
sudo apt install strongswan   # 若未安装

git clone git@github.com:neighbour-oldhuang/strongswan-admin.git
cd strongswan-admin
```

首次运行会自动创建 `.venv` 虚拟环境并安装依赖。

## start.sh 用法

| 命令 | 说明 |
|------|------|
| `sudo bash start.sh` | 前台启动（默认端口 8080） |
| `sudo bash start.sh -d` | 后台启动，日志写入 `strongswan-admin.log` |
| `sudo bash start.sh stop` | 停止后台进程 |

自定义参数（通过环境变量）：

```bash
sudo PORT=9000 bash start.sh          # 自定义端口，前台
sudo PORT=9000 RELOAD=0 bash start.sh -d  # 关闭热重载，后台启动
```

后台运行时 PID 记录在 `strongswan-admin.pid`，日志在 `strongswan-admin.log`：

```bash
tail -f strongswan-admin.log   # 查看日志
sudo bash start.sh stop        # 停止服务
```

## 配置说明

保存连接后会自动生成 `/etc/swanctl/conf.d/admin.conf`，
点击「重载配置」或重启服务生效。

## 目录结构

```
.
├── main.py          # FastAPI 路由
├── ctl.py           # strongSwan 命令封装
├── store.py         # JSON 配置持久化
├── templates/       # Jinja2 页面
├── static/          # CSS / JS
├── data/config.json # 运行时配置存储
└── start.sh         # 启动脚本
```

## 安全提示

- 建议仅在内网或通过 SSH 隧道访问，不要直接暴露到公网
- 生产环境可在前面加 nginx + HTTPS + Basic Auth
