# IP地址查询校准系统

安徽移动 IP 主体信息定位平台，基于 FastAPI + Vue3 + SQLite 实现。

## 部署方法

### 方式 1: 一键部署脚本（推荐）

将整个 `ip-system` 目录上传到目标服务器后执行：

```bash
tar xzf ip-system-deploy.tar.gz
cd ip-system
bash deploy.sh
```

脚本会自动完成：
- 安装系统依赖（python3、pip）
- 创建虚拟环境
- 安装 Python 包
- 初始化数据库
- 配置 systemd 开机自启服务
- 开放防火墙端口 8000
- 自检 HTTP 服务

### 方式 2: 手动部署

```bash
# 1. 安装依赖
apt-get install -y python3 python3-pip python3-venv

# 2. 创建虚拟环境
cd /opt/ip-system/backend
python3 -m venv venv
source venv/bin/activate
pip install -r ../requirements.txt

# 3. 初始化数据库
python -c "from database import init_db; init_db()"

# 4. 启动服务
python -m uvicorn main:app --host 0.0.0.0 --port 8000
```

## 访问信息

- 访问地址: http://175.178.103.242:8000
- 登录账号: admin
- 登录密码: admin123

## 腾讯云安全组配置

部署到腾讯云服务器时，需要在控制台 **安全组** 入站规则中放行：

| 协议 | 端口 | 来源 |
|------|------|------|
| TCP  | 8000 | 0.0.0.0/0 |

路径: 腾讯云控制台 → 云服务器 → 实例 → 安全组 → 入站规则

## 服务管理

```bash
systemctl status ip-system     # 查看状态
systemctl restart ip-system    # 重启服务
systemctl stop ip-system       # 停止服务
journalctl -u ip-system -f     # 查看日志
```

## 功能模块

| 模块 | 说明 |
|------|------|
| IP主体定位查询 | IPv4/IPv6 查询、任务详情、路径回放、定位详情 |
| 数据源管理 | 增删改查、权威性分级、告警监控 |
| 主体信息模板 | 模板CRUD、字段管理、加密/敏感标记 |
| 场景与路径管理 | 五类场景、数据源配置（什么数据去什么数据源查询）、发布 |
| 冲突工单管理 | 工单CRUD、生命周期、处理动作 |
| 批量查询与修正 | 模板下载、批量导入、人工修正、敏感信息审批 |
| 日志管理 | 操作日志查询 |
| 安全配置 | 密码策略、登录安全、IP访问授权 |
| 用户管理 | 用户CRUD |
| 导出功能 | 主体信息/工单/日志导出 Excel |
| 仪表盘 | 统计概览 |

## 测试

```bash
bash test_system.sh
```

全部 41 项功能测试通过。
