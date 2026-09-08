# IP地址查询校准系统 — 用户使用文档

## 一、系统概述

本系统是安徽移动IP主体信息定位平台，基于 **FastAPI + Vue3 + Element Plus + SQLite** 技术栈构建。系统提供IP主体定位查询、数据源管理、主体信息模板管理、场景路径编排、冲突工单全生命周期管理、置信度评估、批量查询与人工修正、敏感信息审批、操作日志、安全配置、用户管理及数据导出等完整功能。

### 系统架构

| 层 | 技术 | 说明 |
|---|---|---|
| 前端 | Vue3 + Element Plus | 单页应用，CDN加载无需构建 |
| 后端 | FastAPI (Python) | RESTful API |
| 数据库 | SQLite | 轻量级文件数据库，随系统启动自动初始化 |

### 访问信息

- 访问地址：`http://<服务器IP>:8000`
- 默认账号：`admin`
- 默认密码：`admin123`

---

## 二、启动与部署

### 方式一：快速启动（推荐）

```bash
cd ip-system/backend
pip install fastapi uvicorn[standard] openpyxl python-multipart pydantic
python3 -m uvicorn main:app --host 0.0.0.0 --port 8000
```

服务启动后会自动初始化数据库并导入演示数据（用户、数据源、模板、场景、IP主体样本、评估记录、冲突工单等）。

### 方式二：一键部署脚本

```bash
cd ip-system
bash deploy.sh
```

脚本会自动完成：安装系统依赖 → 创建虚拟环境 → 安装Python包 → 初始化数据库 → 配置systemd开机自启 → 开放防火墙端口 → HTTP自检。

### 方式三：手动部署

```bash
# 1. 安装依赖
apt-get install -y python3 python3-pip python3-venv

# 2. 创建虚拟环境
cd ip-system/backend
python3 -m venv venv
source venv/bin/activate
pip install -r ../requirements.txt

# 3. 初始化数据库
python -c "from database import init_db; init_db()"

# 4. 启动服务
python -m uvicorn main:app --host 0.0.0.0 --port 8000
```

### 运行测试

```bash
cd ip-system
bash test_system.sh
```

测试脚本覆盖14大类共41项功能测试。

---

## 三、功能模块详解

系统左侧导航栏分为四大功能区：

```
系统首页
├── IP主体定位查询
│   ├── IP主体信息查询
│   ├── 任务列表查询
│   └── 批量导入查询
├── 数据与路径管理
│   ├── 数据源管理
│   ├── 主体信息管理
│   └── 场景路径管理
├── 数据校验
│   ├── 冲突工单检测
│   └── 置信度评估
└── 系统管理
    ├── 日志管理
    └── 安全配置
```

### 3.1 系统首页（仪表盘）

登录后首先进入仪表盘页面，展示系统运行概览统计：

| 统计项 | 说明 |
|--------|------|
| 查询任务数 | 历史创建的IP查询任务总数 |
| 数据源数 | 已配置的数据源总数 |
| 冲突工单(未处理) | 状态为open的冲突工单数 |
| 冲突工单(总数) | 所有冲突工单总数 |
| 评估记录数 | 置信度评估台账记录数 |
| IP主体数 | IP主体信息数据条数 |
| 场景数 | 已配置的场景数 |
| 模板数 | 主体信息模板数 |

**API**: `GET /api/dashboard/stats`

---

### 3.2 IP主体定位查询

#### 3.2.1 IP主体信息查询

支持IPv4和IPv6地址查询。输入IP地址、时间范围和场景类型（可选），系统从数据库中检索匹配的IP主体信息，并返回查询任务和执行路径。

**操作步骤**：
1. 在左侧菜单选择「IP主体定位查询 → IP主体信息查询」
2. 填写IP地址（如 `10.0.1.100` 或 `2408:8000:1::100`）
3. 选择开始时间和结束时间
4. 可选：选择场景类型（移网/家宽/专线/IDC/自有业务）
5. 点击「查询」按钮

**返回结果**：查询任务ID、命中记录数、IP主体信息（含脱敏敏感字段）、执行路径节点。

**API**: `POST /api/query/tasks`

**查询结果字段说明**：

| 字段 | 说明 | 示例 |
|------|------|------|
| ip_address | IP地址 | 10.0.1.100 |
| ip_version | IP版本 | IPv4 / IPv6 |
| scene_type | 场景类型 | 移网 |
| user_name | 用户名（脱敏） | 张*三 |
| phone | 电话（脱敏） | 138****8001 |
| address | 地址（脱敏） | 合肥市蜀山区 |
| unit_name | 单位名称 | 安徽移动 |
| data_source | 数据来源 | 移网AAA数据源 |
| location | 定位位置 | 安徽合肥-蜀山 |
| access_node | 接入节点 | SGSN-001 |
| ip_type | IP类型 | 动态/静态 |

#### 3.2.2 任务列表查询

查看历史查询任务列表，支持多维筛选：

- IP地址（模糊匹配）
- IP版本（IPv4/IPv6）
- 场景类型
- 任务名称
- 时间范围
- 状态

**API**: `GET /api/query/tasks?page=1&page_size=10`

点击任务可查看：
- **任务详情**：`GET /api/query/tasks/{task_id}` — 返回任务信息和查询结果
- **路径回放**：`GET /api/query/tasks/{task_id}/path` — 返回任务执行路径节点（开始→场景识别→数据源查询→数据融合→返回结果）
- **定位详情**：`GET /api/query/tasks/{task_id}/detail` — 返回溯源字段、定位值、数据源、位置等详情

#### 3.2.3 批量导入查询

支持通过Excel文件批量导入IP地址进行查询。

**操作步骤**：
1. 点击「下载模板」获取Excel模板
2. 按模板格式填写IP地址（每行一个IP）
3. 上传Excel文件（限5MB以内，仅支持xlsx格式）
4. 系统自动为每个IP创建查询任务并返回结果

**模板字段**：序号、IP地址、IP版本、端口、开始时间、结束时间、场景类型

**API**:
- 下载模板：`GET /api/query/batch/template`
- 批量导入：`POST /api/query/batch/import`（multipart/form-data）

#### 3.2.4 人工修正

当查询结果中字段信息有误时，可提交人工修正。

**操作步骤**：
1. 在查询结果页面点击「人工修正」
2. 选择需修正的字段（user_name/phone/address/unit_name）
3. 填写修正后的值和修正原因
4. 提交后系统自动更新IP主体信息并生成冲突工单（来源为"用户修正"）

**API**: `POST /api/query/manual-fix`

#### 3.2.5 敏感信息审批

查看敏感字段（如身份证号、明文电话等）的明文信息需要经过审批流程。

**操作步骤**：
1. 在查询结果页面点击「申请查看敏感信息」
2. 填写目标IP、目标字段和审批人
3. 系统生成6位验证码（有效期30分钟）
4. 使用验证码验证后获取明文信息

**API**:
- 申请审批：`POST /api/query/approval/request`
- 验证审批：`POST /api/query/approval/verify`

---

### 3.3 数据与路径管理

#### 3.3.1 数据源管理

管理IP主体数据的来源数据源，支持CRUD全流程。同时在数据源管理页面提供 **IP主体数据导入** 功能。

**数据源字段**：

| 字段 | 说明 | 可选值 |
|------|------|--------|
| name | 数据源名称 | 自定义 |
| source_type | 数据源类型 | 移网/家宽/专线/IDC/自有业务/其他 |
| authority_level | 权威性等级 | 高/中/低 |
| owner | 负责人 | 自定义 |
| contact | 联系方式 | 自定义 |
| description | 描述 | 自定义 |
| alarm_enabled | 告警监控 | 开启/关闭 |

**预置数据源**：移网AAA数据源、家宽BRAS数据源、专线资源系统、IDC资产系统、自有业务平台

**API**:
- 列表：`GET /api/datasources?page=1&page_size=10`
- 新增：`POST /api/datasources`
- 修改：`PUT /api/datasources/{id}`
- 删除：`DELETE /api/datasources/{id}`
- 详情：`GET /api/datasources/{id}`

##### IP主体数据导入

由于测试环境无法对接第三方数据源（AAA、BRAS、专线资源系统等），系统支持通过 **Excel文件导入** IP主体数据。导入的数据即查询任务检索的数据源 — 导入什么数据，查询时就返回什么数据。

**操作步骤**：
1. 在左侧菜单选择「数据与路径管理 → 数据源管理」
2. 点击右上角 **「下载导入模板」** 按钮，获取标准Excel模板
3. 按模板格式填写IP主体数据（可参考模板中的示例行）
4. 点击 **「导入IP主体数据」** 按钮，选择填写好的xlsx文件上传
5. 系统自动解析并导入数据，返回成功导入条数和错误明细

**导入模板字段**：

| 列名 | 数据库字段 | 必填 | 说明 |
|------|-----------|------|------|
| IP地址 | ip_address | 是 | IPv4或IPv6地址 |
| IP版本 | ip_version | 否 | 留空自动识别（含`:`为IPv6） |
| 场景类型 | scene_type | 否 | 移网/家宽/专线/IDC/自有业务 |
| 端口 | port | 否 | 端口号 |
| 开始时间 | start_time | 否 | 格式：2026-01-01 00:00:00 |
| 结束时间 | end_time | 否 | 格式：2026-01-01 23:59:59 |
| 用户名 | user_name | 否 | 会自动脱敏存储 |
| 用户ID | user_id | 否 | 用户标识 |
| 电话 | phone | 否 | 会自动脱敏存储 |
| 地址 | address | 否 | 会自动脱敏存储 |
| 单位名称 | unit_name | 否 | 会自动脱敏存储 |
| 身份证号 | id_card | 否 | 前6后4中间脱敏 |
| 带宽 | bandwidth | 否 | 如100M、500M |
| IP类型 | ip_type | 否 | 动态/静态 |
| 数据源 | data_source | 否 | 数据来源名称 |
| 位置 | location | 否 | 如"安徽合肥-蜀山" |
| 接入节点 | access_node | 否 | 如SGSN-001 |
| 开户时间 | create_time | 否 | 格式：2026-01-01 08:00:00 |

**导入规则**：
- 导入模式为 **追加**，不会删除已有数据
- IP地址格式会自动校验，不合法的行会跳过并报告错误
- 敏感字段（用户名、电话、地址、单位名称、身份证号）会自动脱敏后存储，明文保存在对应的 `_plain` 字段中
- 通过敏感信息审批流程可查看明文
- 如需清空旧数据，可调用 `DELETE /api/subjects?confirm=yes`

**API**:
- 下载模板：`GET /api/subjects/import/template`
- 导入数据：`POST /api/subjects/import`（multipart/form-data，字段名file）
- 清空数据：`DELETE /api/subjects?confirm=yes`

#### 3.3.2 主体信息管理（模板管理）

管理不同场景的主体信息字段模板，支持模板CRUD和字段级管理。

**预置模板**：移网用户模板(9字段)、家宽用户模板(8字段)、专线用户模板(8字段)、IDC资产模板(6字段)、自有业务模板(6字段)

**模板字段属性**：

| 属性 | 说明 |
|------|------|
| field_name | 字段名（英文标识） |
| field_label | 字段标签（中文显示名） |
| field_type | 字段类型（text/datetime等） |
| is_required | 是否必填 |
| is_encrypted | 是否加密 |
| is_sensitive | 是否敏感 |
| field_order | 字段排序 |
| description | 描述 |

**API**:
- 模板列表：`GET /api/templates`
- 新增模板：`POST /api/templates`
- 模板详情：`GET /api/templates/{id}`（含字段列表）
- 修改模板：`PUT /api/templates/{id}`
- 删除模板：`DELETE /api/templates/{id}`
- 新增字段：`POST /api/templates/{id}/fields`
- 修改字段：`PUT /api/templates/{id}/fields/{field_id}`
- 删除字段：`DELETE /api/templates/{id}/fields/{field_id}`

#### 3.3.3 场景路径管理

管理五类场景及其查询路径编排，支持拖拽式可视化路径编辑器。

**五类场景**：移网、家宽、专线、IDC、自有业务

**路径编排功能**：
- **开始节点**（蓝色）：流程起点
- **执行节点**（绿色）：数据源查询等执行动作
- **判断节点**（橙色）：条件判断分支
- 节点拖拽定位
- 节点间连线
- 路径保存与发布（draft → published）

**API**:
- 场景列表：`GET /api/scenes`
- 新增场景：`POST /api/scenes`
- 场景状态切换：`PUT /api/scenes/{id}/toggle`
- 路径列表：`GET /api/scenes/{id}/paths`
- 新增路径：`POST /api/scenes/{id}/paths`
- 修改路径：`PUT /api/scenes/{id}/paths/{path_id}`
- 发布路径：`PUT /api/scenes/{id}/paths/{path_id}/publish`
- 删除路径：`DELETE /api/scenes/{id}/paths/{path_id}`

---

### 3.4 数据校验

#### 3.4.1 冲突工单管理

管理IP主体信息字段冲突的工单全生命周期。

**工单状态流转**：`open` → `processing` → `resolved` → `closed`

**工单字段**：

| 字段 | 说明 |
|------|------|
| ticket_no | 工单编号（自动生成） |
| ip_address | 关联IP地址 |
| conflict_source | 冲突来源（数据冲突/用户修正/系统检测/人工录入） |
| conflict_type | 冲突类型（字段冲突/数据不一致/缺失/人工修正） |
| field_name | 冲突字段 |
| source_values | 各数据源值（JSON） |
| suggestion | 处置建议 |
| status | 当前状态 |
| handler | 处理人 |
| lifecycle | 生命周期记录（JSON数组） |

**工单处理动作**：
- `fix`：手动修正，状态变为 processing
- `verify`：治理校验，状态变为 resolved
- `detail`：详情查阅，状态不变

**API**:
- 工单列表：`GET /api/conflicts`
- 新建工单：`POST /api/conflicts`
- 工单详情：`GET /api/conflicts/{id}`
- 工单生命周期：`GET /api/conflicts/{id}/lifecycle`
- 处理工单：`PUT /api/conflicts/{id}/process`

#### 3.4.2 置信度评估

对IP主体信息进行置信度评估，支持加权评分和扣分机制。

**评估维度**（加权计算）：

| 维度 | 权重 | 说明 |
|------|------|------|
| 数据时效性 | 0.30 | 数据更新及时程度 |
| 数据完整性 | 0.30 | 字段完整程度 |
| 数据准确性 | 0.25 | 与权威源一致程度 |
| 数据一致性 | 0.15 | 多源数据一致程度 |

**风险扣分项**：

| 扣分项 | 扣分值 | 风险等级 |
|--------|--------|----------|
| 高风险数据扣分 | 20 | 高风险 |
| 疑似异常IP扣分 | 10 | 可疑 |
| 字段缺失扣分 | 5 | 可疑 |

**风险等级判定**：总分≥90为优秀，≥70为良好，≥50为一般，<50为差。

**API**:
- 维度管理：`GET/POST/PUT/DELETE /api/assessment/dimensions`
- 扣分项管理：`GET/POST/PUT/DELETE /api/assessment/deductions`
- 评估记录：`GET/POST /api/assessment/records`
- 记录详情：`GET /api/assessment/records/{id}`

---

### 3.5 系统管理

#### 3.5.1 日志管理

查询系统操作日志，支持多维筛选。

**筛选条件**：操作类型、操作内容、操作人、时间范围

**记录的操作类型**：登录、查询、下载、批量导入、人工修正、审批申请、敏感信息查看、新增、编辑、删除、导出、工单处理、用户管理、安全配置、IP访问授权、置信度评估等。

**API**: `GET /api/logs?page=1&page_size=10`

#### 3.5.2 安全配置

**密码策略配置**：

| 配置项 | 默认值 | 说明 |
|--------|--------|------|
| password_history_count | 3 | 密码历史留存次数 |
| password_valid_days | 90 | 密码有效天数 |
| password_expire_remind_days | 7 | 密码到期提醒天数 |
| password_min_length | 8 | 密码最小长度 |
| password_complexity_desc | - | 密码复杂度要求说明 |

**登录安全配置**：

| 配置项 | 默认值 | 说明 |
|--------|--------|------|
| login_fail_lock_threshold | 5 | 登录失败锁定次数 |
| account_lock_duration | 30 | 账号锁定时长(分钟) |
| session_idle_timeout | 30 | 会话空闲超时(分钟) |

**IP访问授权规则**：
- 系统默认放开全部IP访问权限
- 可添加IP网段规则并启用/禁用

**API**:
- 安全配置查询：`GET /api/security/config`
- 安全配置更新：`PUT /api/security/config`
- IP访问规则：`GET/POST /api/security/ip-access`
- 规则状态切换：`PUT /api/security/ip-access/{id}/toggle`

#### 3.5.3 用户管理

支持用户的增删改查（当前通过API调用，前端UI未直接暴露此功能页面）。

**API**:
- 用户列表：`GET /api/users`
- 新增用户：`POST /api/users`
- 修改用户：`PUT /api/users/{id}`
- 删除用户：`DELETE /api/users/{id}`

**约束**：admin账户不可删除；用户名不可重复。

---

### 3.6 数据导出

支持将系统数据导出为Excel文件。

| 导出类型 | API | 可选筛选 |
|----------|-----|----------|
| IP主体信息 | `GET /api/export/subjects` | ip_address, scene_type |
| 冲突工单 | `GET /api/export/conflicts` | status, ip_address |
| 操作日志 | `GET /api/export/logs` | start_time, end_time |
| 评估记录 | `GET /api/export/assessment` | ip_address |

导出文件格式为 `.xlsx`，包含表头样式和列宽设置。

---

## 四、API 接口总览

### 认证

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/api/login` | 用户登录 |

### IP主体定位查询

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/api/query/tasks` | 创建IP查询任务 |
| GET | `/api/query/tasks` | 查询任务列表 |
| GET | `/api/query/tasks/{id}` | 查询任务详情 |
| GET | `/api/query/tasks/{id}/path` | 路径回放 |
| GET | `/api/query/tasks/{id}/detail` | 定位详情 |
| GET | `/api/query/batch/template` | 下载批量查询模板 |
| POST | `/api/query/batch/import` | 批量导入查询 |
| POST | `/api/query/manual-fix` | 人工修正 |
| POST | `/api/query/approval/request` | 敏感信息审批申请 |
| POST | `/api/query/approval/verify` | 敏感信息审批验证 |

### 数据与路径管理

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/datasources` | 数据源列表 |
| POST | `/api/datasources` | 新增数据源 |
| PUT | `/api/datasources/{id}` | 修改数据源 |
| DELETE | `/api/datasources/{id}` | 删除数据源 |
| GET | `/api/datasources/{id}` | 数据源详情 |
| GET | `/api/subjects/import/template` | 下载IP主体数据导入模板 |
| POST | `/api/subjects/import` | 导入IP主体数据（Excel上传） |
| DELETE | `/api/subjects?confirm=yes` | 清空所有IP主体数据 |
| GET | `/api/templates` | 模板列表 |
| POST | `/api/templates` | 新增模板 |
| GET | `/api/templates/{id}` | 模板详情 |
| PUT | `/api/templates/{id}` | 修改模板 |
| DELETE | `/api/templates/{id}` | 删除模板 |
| POST | `/api/templates/{id}/fields` | 新增字段 |
| PUT | `/api/templates/{id}/fields/{field_id}` | 修改字段 |
| DELETE | `/api/templates/{id}/fields/{field_id}` | 删除字段 |
| GET | `/api/scenes` | 场景列表 |
| POST | `/api/scenes` | 新增场景 |
| PUT | `/api/scenes/{id}` | 修改场景 |
| DELETE | `/api/scenes/{id}` | 删除场景 |
| PUT | `/api/scenes/{id}/toggle` | 场景状态切换 |
| GET | `/api/scenes/{id}/paths` | 路径列表 |
| POST | `/api/scenes/{id}/paths` | 新增路径 |
| PUT | `/api/scenes/{id}/paths/{path_id}` | 修改路径 |
| DELETE | `/api/scenes/{id}/paths/{path_id}` | 删除路径 |
| PUT | `/api/scenes/{id}/paths/{path_id}/publish` | 发布路径 |

### 数据校验

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/conflicts` | 冲突工单列表 |
| POST | `/api/conflicts` | 新建冲突工单 |
| GET | `/api/conflicts/{id}` | 工单详情 |
| GET | `/api/conflicts/{id}/lifecycle` | 工单生命周期 |
| PUT | `/api/conflicts/{id}/process` | 处理工单 |
| GET | `/api/assessment/dimensions` | 评估维度列表 |
| POST | `/api/assessment/dimensions` | 新增评估维度 |
| PUT | `/api/assessment/dimensions/{id}` | 修改评估维度 |
| DELETE | `/api/assessment/dimensions/{id}` | 删除评估维度 |
| GET | `/api/assessment/deductions` | 扣分项列表 |
| POST | `/api/assessment/deductions` | 新增扣分项 |
| PUT | `/api/assessment/deductions/{id}` | 修改扣分项 |
| DELETE | `/api/assessment/deductions/{id}` | 删除扣分项 |
| GET | `/api/assessment/records` | 评估记录列表 |
| POST | `/api/assessment/records` | 新增评估记录 |
| GET | `/api/assessment/records/{id}` | 评估记录详情 |

### 系统管理

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/logs` | 操作日志列表 |
| GET | `/api/users` | 用户列表 |
| POST | `/api/users` | 新增用户 |
| PUT | `/api/users/{id}` | 修改用户 |
| DELETE | `/api/users/{id}` | 删除用户 |
| GET | `/api/security/config` | 安全配置查询 |
| PUT | `/api/security/config` | 安全配置更新 |
| GET | `/api/security/ip-access` | IP访问规则列表 |
| POST | `/api/security/ip-access` | 新增IP访问规则 |
| PUT | `/api/security/ip-access/{id}/toggle` | IP规则状态切换 |
| DELETE | `/api/security/ip-access/{id}` | 删除IP访问规则 |
| GET | `/api/dashboard/stats` | 仪表盘统计 |

### 导出

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/export/subjects` | 导出IP主体信息 |
| GET | `/api/export/conflicts` | 导出冲突工单 |
| GET | `/api/export/logs` | 导出操作日志 |
| GET | `/api/export/assessment` | 导出评估记录 |

### 前端

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/` | 首页HTML |
| GET | `/static/app.js` | 前端JS |
| GET | `/static/app.css` | 前端CSS |

---

## 五、预置演示数据

系统初始化时自动导入以下演示数据：

### 用户

| 用户名 | 密码 | 角色 | 姓名 |
|--------|------|------|------|
| admin | admin123 | admin | 系统管理员 |

### 数据源

| 名称 | 类型 | 权威性 | 负责人 |
|------|------|--------|--------|
| 移网AAA数据源 | 移网 | 高 | 张三 |
| 家宽BRAS数据源 | 家宽 | 高 | 李四 |
| 专线资源系统 | 专线 | 高 | 王五 |
| IDC资产系统 | IDC | 高 | 赵六 |
| 自有业务平台 | 自有业务 | 中 | 钱七 |

### IP主体样本

| IP地址 | 版本 | 场景 | 数据源 |
|--------|------|------|--------|
| 10.0.1.100 | IPv4 | 移网 | 移网AAA数据源 |
| 10.0.1.101 | IPv4 | 移网 | 移网AAA数据源 |
| 2408:8000:1::100 | IPv6 | 移网 | 移网AAA数据源 |
| 192.168.1.100 | IPv4 | 家宽 | 家宽BRAS数据源 |
| 192.168.1.101 | IPv4 | 家宽 | 家宽BRAS数据源 |
| 172.16.1.100 | IPv4 | 专线 | 专线资源系统 |
| 203.0.113.1 | IPv4 | IDC | IDC资产系统 |
| 111.0.0.1 | IPv4 | 自有业务 | 自有业务平台 |

### 场景

| 场景 | 类型 | IP范围 |
|------|------|--------|
| 移网IP定位场景 | 移网 | 10.0.0.0/8, 100.64.0.0/10 |
| 家宽IP定位场景 | 家宽 | 192.168.0.0/16, 10.1.0.0/16 |
| 专线IP定位场景 | 专线 | 172.16.0.0/12 |
| IDC IP定位场景 | IDC | 203.0.0.0/8 |
| 自有业务IP定位场景 | 自有业务 | 111.0.0.0/8 |

---

## 六、服务管理

```bash
# 查看状态
systemctl status ip-system

# 重启服务
systemctl restart ip-system

# 停止服务
systemctl stop ip-system

# 查看日志
journalctl -u ip-system -f
```

---

## 七、常见问题

### Q: 如何重置数据库？

删除 `ip-system/data/ip_system.db` 文件后重启服务，系统会自动重新初始化并导入演示数据。

### Q: 如何修改管理员密码？

通过API修改：
```bash
curl -X PUT http://localhost:8000/api/users/{admin用户ID} \
  -H "Authorization: {token}" \
  -H "Content-Type: application/json" \
  -d '{"password": "新密码"}'
```

### Q: 如何放行防火墙端口？

```bash
# iptables
iptables -I INPUT -p tcp --dport 8000 -j ACCEPT

# ufw
ufw allow 8000/tcp

# firewall-cmd
firewall-cmd --permanent --add-port=8000/tcp && firewall-cmd --reload
```

### Q: 敏感字段如何脱敏？

系统对用户姓名、电话、地址、身份证号等字段自动进行脱敏处理，脱敏规则：
- 2位以内：首字符 + *
- 3-6位：首字符 + * + 末字符
- 7位以上：前3位 + * + 后3位

查看明文需通过敏感信息审批流程获取验证码。
