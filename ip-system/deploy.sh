#!/bin/bash
# ============================================================================
# IP地址查询校准系统 - 一键部署脚本
# 目标服务器: 175.178.103.242 (root)
# 使用方法: 在能 SSH 到该服务器的机器上执行
#   bash deploy.sh
# 或从本沙箱下载 ip-system-deploy.tar.gz 后, 上传到目标服务器并执行:
#   tar xzf ip-system-deploy.tar.gz && cd ip-system && bash deploy.sh
# ============================================================================
set -e

APP_DIR="${APP_DIR:-/opt/ip-system}"
PYTHON="${PYTHON:-python3}"
PORT="${PORT:-8000}"

echo "=================================================="
echo "  IP地址查询校准系统 - 部署脚本"
echo "  目标目录: $APP_DIR"
echo "  端口:     $PORT"
echo "=================================================="

# 1. 安装系统依赖
echo ">>> [1/6] 安装系统依赖..."
if command -v apt-get >/dev/null 2>&1; then
    apt-get update -qq
    apt-get install -y -qq python3 python3-pip python3-venv curl >/dev/null
elif command -v yum >/dev/null 2>&1; then
    yum install -y -q python3 python3-pip curl >/dev/null
fi

# 2. 创建应用目录
echo ">>> [2/6] 创建应用目录..."
mkdir -p "$APP_DIR"
cd "$APP_DIR"

# 3. 复制代码（如果当前目录是源码包根目录, 复制到 APP_DIR）
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
if [ "$SCRIPT_DIR" != "$APP_DIR" ] && [ -f "$SCRIPT_DIR/backend/main.py" ]; then
    echo "  从 $SCRIPT_DIR 复制到 $APP_DIR..."
    cp -r "$SCRIPT_DIR/backend" "$APP_DIR/"
    cp -r "$SCRIPT_DIR/frontend" "$APP_DIR/"
    cp -r "$SCRIPT_DIR/run.sh" "$APP_DIR/" 2>/dev/null || true
fi

# 4. 创建虚拟环境并安装 Python 依赖
echo ">>> [3/6] 创建 Python 虚拟环境..."
if [ ! -d "$APP_DIR/venv" ]; then
    $PYTHON -m venv "$APP_DIR/venv"
fi
. "$APP_DIR/venv/bin/activate"

echo ">>> [4/6] 安装 Python 依赖..."
pip install --quiet --upgrade pip
pip install --quiet fastapi uvicorn[standard] openpyxl python-multipart pydantic

# 5. 初始化数据库
echo ">>> [5/6] 初始化数据库..."
cd "$APP_DIR/backend"
$PYTHON -c "from database import init_db; init_db(); print('数据库初始化完成')"

# 6. 配置 systemd 服务实现开机自启
echo ">>> [6/6] 配置 systemd 服务..."
cat > /etc/systemd/system/ip-system.service <<EOF
[Unit]
Description=IP Address Query Calibration System
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$APP_DIR/backend
ExecStart=$APP_DIR/venv/bin/python -m uvicorn main:app --host 0.0.0.0 --port $PORT
Restart=always
RestartSec=5
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable ip-system
systemctl restart ip-system
sleep 3

# 7. 开放防火墙端口
echo ">>> 开放防火墙端口 $PORT..."
if command -v firewall-cmd >/dev/null 2>&1; then
    firewall-cmd --permanent --add-port=$PORT/tcp 2>/dev/null && firewall-cmd --reload 2>/dev/null || true
elif command -v ufw >/dev/null 2>&1; then
    ufw allow $PORT/tcp 2>/dev/null || true
elif command -v iptables >/dev/null 2>&1; then
    iptables -I INPUT -p tcp --dport $PORT -j ACCEPT 2>/dev/null || true
fi

# 8. 验证部署
echo ""
echo "=================================================="
echo "  部署完成！"
echo "=================================================="
systemctl status ip-system --no-pager -l | head -15 || true
echo ""
echo "访问地址: http://$(hostname -I 2>/dev/null | awk '{print $1}' || echo '175.178.103.242'):$PORT"
echo "登录账号: admin / admin123"
echo ""
echo "常用命令:"
echo "  查看状态: systemctl status ip-system"
echo "  查看日志: journalctl -u ip-system -f"
echo "  重启服务: systemctl restart ip-system"
echo "  停止服务: systemctl stop ip-system"
echo ""
echo "如需腾讯云安全组, 请在控制台放行 TCP 端口 $PORT"

# 自检 HTTP
echo ""
echo ">>> 自检 HTTP..."
sleep 2
curl -s -o /dev/null -w "HTTP状态码: %{http_code}\n" http://localhost:$PORT/ || echo "服务尚未就绪, 请稍等几秒后重试"
