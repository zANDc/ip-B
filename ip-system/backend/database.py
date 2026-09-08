"""Database models and initialization for IP Address Query Calibration System."""
import sqlite3
import os
import json
import time
import uuid
import hashlib
from datetime import datetime, timedelta
from contextlib import contextmanager

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "ip_system.db")


def get_db_path():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    return DB_PATH


@contextmanager
def get_conn():
    conn = sqlite3.connect(get_db_path())
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def now_str():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def gen_id(prefix=""):
    return prefix + uuid.uuid4().hex[:12]


def hash_password(pwd):
    return hashlib.sha256(pwd.encode()).hexdigest()


# ---------- Schema DDL ----------
SCHEMA = """
-- 用户表
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    real_name TEXT,
    role TEXT DEFAULT 'admin',
    phone TEXT,
    email TEXT,
    status TEXT DEFAULT 'active',
    created_at TEXT,
    last_login TEXT
);

-- 数据源表
CREATE TABLE IF NOT EXISTS data_sources (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    source_type TEXT,          -- 数据源类型: 移网/家宽/专线/IDC/自有业务/其他
    authority_level TEXT,      -- 数据源权威性: 高/中/低
    owner TEXT,                -- 数据源负责人
    contact TEXT,
    description TEXT,
    alarm_enabled INTEGER DEFAULT 0,  -- 是否开启告警监控
    config_attrs TEXT,         -- 数据源配置属性 JSON
    status TEXT DEFAULT 'active',
    created_at TEXT,
    updated_at TEXT
);

-- 主体信息模板表
CREATE TABLE IF NOT EXISTS subject_templates (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT,
    scene_type TEXT,
    created_at TEXT,
    updated_at TEXT
);

-- 主体信息模板字段表
CREATE TABLE IF NOT EXISTS subject_template_fields (
    id TEXT PRIMARY KEY,
    template_id TEXT NOT NULL,
    field_name TEXT NOT NULL,
    field_label TEXT,
    field_type TEXT,
    is_required INTEGER DEFAULT 0,
    is_encrypted INTEGER DEFAULT 0,  -- 是否加密(敏感)
    is_sensitive INTEGER DEFAULT 0,
    field_order INTEGER DEFAULT 0,
    description TEXT,
    FOREIGN KEY (template_id) REFERENCES subject_templates(id) ON DELETE CASCADE
);

-- 场景表(五类场景)
CREATE TABLE IF NOT EXISTS scenes (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    scene_type TEXT,            -- 移网/家宽/专线/IDC/自有业务
    ip_range TEXT,              -- IP地址范围
    description TEXT,
    status TEXT DEFAULT 'enabled', -- enabled/disabled
    created_at TEXT,
    updated_at TEXT
);

-- 场景查询路径表(配置场景对应的查询数据源)
CREATE TABLE IF NOT EXISTS scene_paths (
    id TEXT PRIMARY KEY,
    scene_id TEXT NOT NULL,
    name TEXT,
    data_source_ids TEXT,       -- JSON数组: 该场景查询时使用的数据源ID列表
    status TEXT DEFAULT 'draft', -- draft/published
    created_at TEXT,
    updated_at TEXT,
    FOREIGN KEY (scene_id) REFERENCES scenes(id) ON DELETE CASCADE
);

-- IP主体数据表(查询结果)
CREATE TABLE IF NOT EXISTS ip_subjects (
    id TEXT PRIMARY KEY,
    ip_address TEXT NOT NULL,
    ip_version TEXT,           -- IPv4/IPv6
    scene_type TEXT,           -- 移网/家宽/专线/IDC/自有业务
    port TEXT,
    start_time TEXT,
    end_time TEXT,
    user_name TEXT,            -- 用户名(可能脱敏)
    user_name_plain TEXT,      -- 明文
    user_id TEXT,
    phone TEXT,
    phone_plain TEXT,
    address TEXT,
    address_plain TEXT,
    unit_name TEXT,
    unit_name_plain TEXT,
    id_card TEXT,
    id_card_plain TEXT,
    bandwidth TEXT,
    ip_type TEXT,             -- 动态/静态
    data_source TEXT,
    data_source_id TEXT,
    location TEXT,
    access_node TEXT,
    create_time TEXT,
    raw_data TEXT,            -- 完整原始数据JSON
    created_at TEXT
);

-- 查询任务表
CREATE TABLE IF NOT EXISTS query_tasks (
    id TEXT PRIMARY KEY,
    task_name TEXT,
    ip_address TEXT,
    ip_version TEXT,
    port TEXT,
    start_time TEXT,
    end_time TEXT,
    scene_type TEXT,
    status TEXT DEFAULT 'completed',  -- pending/running/completed/failed
    result_count INTEGER DEFAULT 0,
    created_by TEXT,
    created_at TEXT,
    completed_at TEXT,
    batch_id TEXT             -- 批量导入批次ID
);

-- 查询任务执行路径
CREATE TABLE IF NOT EXISTS task_paths (
    id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL,
    node_name TEXT,
    node_type TEXT,           -- start/execute/judge
    status TEXT,              -- success/running/failed
    detail TEXT,
    data_source TEXT,
    started_at TEXT,
    completed_at TEXT,
    FOREIGN KEY (task_id) REFERENCES query_tasks(id) ON DELETE CASCADE
);

-- 冲突工单表
CREATE TABLE IF NOT EXISTS conflict_tickets (
    id TEXT PRIMARY KEY,
    ticket_no TEXT UNIQUE,
    ip_address TEXT,
    conflict_source TEXT,      -- 冲突来源: 数据冲突/用户修正/系统检测
    conflict_type TEXT,        -- 冲突类型: 字段冲突/数据不一致/缺失
    conflict_desc TEXT,
    field_name TEXT,            -- 冲突字段
    source_values TEXT,        -- 各数据源值 JSON
    suggestion TEXT,            -- 处置建议
    status TEXT DEFAULT 'open', -- open/processing/resolved/closed
    handler TEXT,
    handle_remark TEXT,
    handle_evidence TEXT,       -- 证据材料
    created_at TEXT,
    processed_at TEXT,
    closed_at TEXT,
    lifecycle TEXT             -- 生命周期JSON
);

-- 审批表(查看敏感信息)
CREATE TABLE IF NOT EXISTS approvals (
    id TEXT PRIMARY KEY,
    applicant TEXT,
    approver TEXT,
    target_ip TEXT,
    target_field TEXT,
    verify_code TEXT,
    status TEXT DEFAULT 'pending',  -- pending/approved/rejected
    created_at TEXT,
    approved_at TEXT,
    expire_at TEXT
);

-- 操作日志表
CREATE TABLE IF NOT EXISTS operation_logs (
    id TEXT PRIMARY KEY,
    operation_time TEXT,
    operation_type TEXT,
    operator TEXT,
    request_url TEXT,
    operation_detail TEXT,
    ip_address TEXT,
    created_at TEXT
);

-- 密码策略配置表
CREATE TABLE IF NOT EXISTS security_config (
    id TEXT PRIMARY KEY,
    config_key TEXT UNIQUE,
    config_value TEXT,
    description TEXT,
    updated_at TEXT
);

-- IP访问权限表
CREATE TABLE IF NOT EXISTS ip_access_rules (
    id TEXT PRIMARY KEY,
    ip_segment TEXT,
    description TEXT,
    enabled INTEGER DEFAULT 1,
    created_at TEXT
);
"""


def init_db():
    """Initialize database and create all tables."""
    with get_conn() as conn:
        conn.executescript(SCHEMA)
        migrate_scene_paths(conn)
    seed_data()


def migrate_scene_paths(conn):
    """Migrate scene_paths table from old nodes/edges schema to data_source_ids."""
    cols = [r[1] for r in conn.execute("PRAGMA table_info(scene_paths)").fetchall()]
    if "data_source_ids" in cols:
        return
    # Old schema without data_source_ids: recreate table
    conn.execute("ALTER TABLE scene_paths RENAME TO scene_paths_old")
    conn.execute("""
        CREATE TABLE scene_paths (
            id TEXT PRIMARY KEY,
            scene_id TEXT NOT NULL,
            name TEXT,
            data_source_ids TEXT,
            status TEXT DEFAULT 'draft',
            created_at TEXT,
            updated_at TEXT,
            FOREIGN KEY (scene_id) REFERENCES scenes(id) ON DELETE CASCADE
        )
    """)
    # Try to migrate old data: extract datasource names from nodes JSON and map to data source IDs
    old_rows = conn.execute("SELECT * FROM scene_paths_old").fetchall()
    for row in old_rows:
        ds_ids = []
        try:
            nodes = json.loads(row["nodes"] or "[]")
            names = [n.get("datasource") or n.get("name") for n in nodes if n.get("datasource") or n.get("name")]
            if names:
                placeholders = ",".join(["?"] * len(names))
                rows = conn.execute(f"SELECT id FROM data_sources WHERE name IN ({placeholders})", names).fetchall()
                ds_ids = [r["id"] for r in rows]
        except Exception:
            pass
        conn.execute(
            "INSERT INTO scene_paths (id, scene_id, name, data_source_ids, status, created_at, updated_at) VALUES (?,?,?,?,?,?,?)",
            (row["id"], row["scene_id"], row["name"], json.dumps(ds_ids, ensure_ascii=False), row["status"], row["created_at"], row["updated_at"]),
        )
    conn.execute("DROP TABLE scene_paths_old")


def log_operation(conn, op_type, operator, url, detail, ip="127.0.0.1"):
    """Record an operation log."""
    conn.execute(
        "INSERT INTO operation_logs (id, operation_time, operation_type, operator, request_url, operation_detail, ip_address, created_at) VALUES (?,?,?,?,?,?,?,?)",
        (gen_id("log_"), now_str(), op_type, operator, url, detail, ip, now_str()),
    )


def seed_data():
    """Insert initial seed data if tables are empty."""
    with get_conn() as conn:
        # Check if already seeded
        count = conn.execute("SELECT COUNT(*) as c FROM users").fetchone()["c"]
        if count > 0:
            return

        # Default user
        conn.execute(
            "INSERT INTO users (id, username, password, real_name, role, phone, email, status, created_at) VALUES (?,?,?,?,?,?,?,?,?)",
            (gen_id("u_"), "admin", hash_password("admin123"), "系统管理员", "admin", "13800138000", "admin@ahmobile.cn", "active", now_str()),
        )

        # Data sources
        ds_list = [
            ("移网AAA数据源", "移网", "高", "张三", "13800000001", "移网用户IP主体数据", 1, '{"source":"AAA系统","protocol":"RADIUS"}'),
            ("家宽BRAS数据源", "家宽", "高", "李四", "13800000002", "家宽用户IP主体数据", 1, '{"source":"BRAS","protocol":"DHCP"}'),
            ("专线资源系统", "专线", "高", "王五", "13800000003", "专线静态IP数据", 0, '{"source":"专线资源管理系统"}'),
            ("IDC资产系统", "IDC", "高", "赵六", "13800000004", "IDC机房IP资产数据", 1, '{"source":"IDC资产管理系统"}'),
            ("自有业务平台", "自有业务", "中", "钱七", "13800000005", "自有业务静态IP数据", 0, '{"source":"自有业务管理平台"}'),
        ]
        # scene_type -> data_source_id mapping for default scene paths
        scene_ds_map = {}
        for ds in ds_list:
            ds_id = gen_id("ds_")
            conn.execute(
                "INSERT INTO data_sources (id, name, source_type, authority_level, owner, contact, description, alarm_enabled, config_attrs, status, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (ds_id, *ds, "active", now_str(), now_str()),
            )
            scene_ds_map.setdefault(ds[1], []).append(ds_id)

        # Subject templates
        tpl_fields = {
            "移网用户模板": [
                ("ip_address", "IP地址", "text", 1, 0, 0, 1, ""),
                ("user_name", "用户姓名", "text", 1, 1, 1, 2, "敏感字段-脱敏展示"),
                ("phone", "手机号码", "text", 1, 1, 1, 3, "敏感字段-脱敏展示"),
                ("id_card", "身份证号", "text", 0, 1, 1, 4, "敏感字段-脱敏展示"),
                ("imsi", "IMSI", "text", 0, 1, 1, 5, ""),
                ("apn", "APN", "text", 0, 0, 0, 6, ""),
                ("access_node", "接入节点", "text", 0, 0, 0, 7, ""),
                ("bandwidth", "带宽", "text", 0, 0, 0, 8, ""),
                ("create_time", "开户时间", "datetime", 0, 0, 0, 9, ""),
            ],
            "家宽用户模板": [
                ("ip_address", "IP地址", "text", 1, 0, 0, 1, ""),
                ("user_name", "用户姓名", "text", 1, 1, 1, 2, "敏感字段-脱敏展示"),
                ("phone", "联系电话", "text", 1, 1, 1, 3, "敏感字段-脱敏展示"),
                ("address", "装机地址", "text", 1, 1, 1, 4, "敏感字段-脱敏展示"),
                ("id_card", "身份证号", "text", 0, 1, 1, 5, "敏感字段-脱敏展示"),
                ("account_id", "账号ID", "text", 0, 0, 0, 6, ""),
                ("bandwidth", "带宽", "text", 0, 0, 0, 7, ""),
                ("create_time", "开户时间", "datetime", 0, 0, 0, 8, ""),
            ],
            "专线用户模板": [
                ("ip_address", "IP地址", "text", 1, 0, 0, 1, ""),
                ("unit_name", "单位名称", "text", 1, 0, 0, 2, ""),
                ("contact_person", "联系人", "text", 0, 1, 1, 3, "敏感字段-脱敏展示"),
                ("contact_phone", "联系电话", "text", 0, 1, 1, 4, "敏感字段-脱敏展示"),
                ("address", "装机地址", "text", 0, 0, 0, 5, ""),
                ("bandwidth", "带宽", "text", 0, 0, 0, 6, ""),
                ("circuit_no", "专线编号", "text", 0, 0, 0, 7, ""),
                ("create_time", "开通时间", "datetime", 0, 0, 0, 8, ""),
            ],
            "IDC资产模板": [
                ("ip_address", "IP地址", "text", 1, 0, 0, 1, ""),
                ("unit_name", "单位名称", "text", 1, 0, 0, 2, ""),
                ("server_id", "服务器ID", "text", 0, 0, 0, 3, ""),
                ("rack_no", "机架号", "text", 0, 0, 0, 4, ""),
                ("location", "机房位置", "text", 0, 0, 0, 5, ""),
                ("create_time", "录入时间", "datetime", 0, 0, 0, 6, ""),
            ],
            "自有业务模板": [
                ("ip_address", "IP地址", "text", 1, 0, 0, 1, ""),
                ("unit_name", "单位名称", "text", 1, 0, 0, 2, ""),
                ("business_name", "业务名称", "text", 0, 0, 0, 3, ""),
                ("contact_person", "联系人", "text", 0, 1, 1, 4, "敏感字段-脱敏展示"),
                ("contact_phone", "联系电话", "text", 0, 1, 1, 5, "敏感字段-脱敏展示"),
                ("create_time", "开通时间", "datetime", 0, 0, 0, 6, ""),
            ],
        }
        for tpl_name, fields in tpl_fields.items():
            tpl_id = gen_id("tpl_")
            scene_map = {"移网用户模板": "移网", "家宽用户模板": "家宽", "专线用户模板": "专线", "IDC资产模板": "IDC", "自有业务模板": "自有业务"}
            conn.execute(
                "INSERT INTO subject_templates (id, name, description, scene_type, created_at, updated_at) VALUES (?,?,?,?,?,?)",
                (tpl_id, tpl_name, f"{tpl_name}字段模板", scene_map.get(tpl_name), now_str(), now_str()),
            )
            for f in fields:
                conn.execute(
                    "INSERT INTO subject_template_fields (id, template_id, field_name, field_label, field_type, is_required, is_encrypted, is_sensitive, field_order, description) VALUES (?,?,?,?,?,?,?,?,?,?)",
                    (gen_id("fld_"), tpl_id, *f),
                )

        # Scenes (five types)
        scenes = [
            ("移网IP定位场景", "移网", "10.0.0.0/8,100.64.0.0/10", "移动网络用户IP主体定位"),
            ("家宽IP定位场景", "家宽", "192.168.0.0/16,10.1.0.0/16", "家庭宽带用户IP主体定位"),
            ("专线IP定位场景", "专线", "172.16.0.0/12", "专线静态IP主体定位"),
            ("IDC IP定位场景", "IDC", "203.0.0.0/8", "IDC机房IP资产定位"),
            ("自有业务IP定位场景", "自有业务", "111.0.0.0/8", "自有业务静态IP定位"),
        ]
        scene_ids = {}
        for s in scenes:
            sid = gen_id("sc_")
            scene_ids[s[1]] = sid
            conn.execute(
                "INSERT INTO scenes (id, name, scene_type, ip_range, description, status, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?)",
                (sid, *s, "enabled", now_str(), now_str()),
            )
            # default path: configure which data sources to query for this scene
            default_ds_ids = scene_ds_map.get(s[1], [])
            conn.execute(
                "INSERT INTO scene_paths (id, scene_id, name, data_source_ids, status, created_at, updated_at) VALUES (?,?,?,?,?,?,?)",
                (gen_id("sp_"), sid, f"{s[0]}查询数据源配置", json.dumps(default_ds_ids, ensure_ascii=False), "published", now_str(), now_str()),
            )

        # IP subject sample data
        samples = [
            # 移网 IPv4
            ("10.0.1.100", "IPv4", "移网", "0", "2026-01-01 08:00:00", "2026-01-01 20:00:00",
             "张*三", "张三", "USER_001", "138****8001", "13800008001", "合肥市蜀山区", "合肥市蜀山区黄山路", "安徽移动", "340100199001011234", "100M", "动态", "移网AAA数据源", "安徽合肥-蜀山", "SGSN-001", "2026-01-01 08:30:00"),
            ("10.0.1.101", "IPv4", "移网", "0", "2026-01-02 08:00:00", "2026-01-02 20:00:00",
             "李*四", "李四", "USER_002", "139****8002", "13900008002", "芜湖市镜湖区", "芜湖市镜湖区北京路", "安徽移动", "340200199002022345", "50M", "动态", "移网AAA数据源", "安徽芜湖-镜湖", "SGSN-002", "2026-01-02 09:00:00"),
            # 移网 IPv6
            ("2408:8000:1::100", "IPv6", "移网", "0", "2026-01-01 08:00:00", "2026-01-01 20:00:00",
             "王*五", "王五", "USER_003", "137****8003", "13700008003", "蚌埠市蚌山区", "蚌埠市蚌山区东海大道", "安徽移动", "340300199003033456", "100M", "动态", "移网AAA数据源", "安徽蚌埠-蚌山", "SGSN-003", "2026-01-01 08:15:00"),
            # 家宽
            ("192.168.1.100", "IPv4", "家宽", "0", "2026-01-01 08:00:00", "2026-01-01 20:00:00",
             "赵*六", "赵六", "USER_004", "136****8004", "13600008004", "合肥市包河区", "合肥市包河区马鞍山路", "安徽移动", "340111199004044567", "300M", "动态", "家宽BRAS数据源", "安徽合肥-包河", "BRAS-001", "2026-01-01 08:20:00"),
            ("192.168.1.101", "IPv4", "家宽", "0", "2026-01-01 08:00:00", "2026-01-01 20:00:00",
             "钱*七", "钱七", "USER_005", "135****8005", "13500008005", "合肥市庐阳区", "合肥市庐阳区长江路", "安徽移动", "340111199005055678", "500M", "动态", "家宽BRAS数据源", "安徽合肥-庐阳", "BRAS-002", "2026-01-01 08:25:00"),
            # 专线
            ("172.16.1.100", "IPv4", "专线", "0", "2026-01-01 00:00:00", "2026-12-31 23:59:59",
             "-", "-", "安徽XX科技有限公司", "0551-12345678", "055163888888", "合肥市高新区", "合肥市高新区创新大道", "安徽XX科技有限公司", "-", "1000M", "静态", "专线资源系统", "安徽合肥-高新", "专线上联-001", "2025-12-01 10:00:00"),
            # IDC
            ("203.0.113.1", "IPv4", "IDC", "0", "2026-01-01 00:00:00", "2026-12-31 23:59:59",
             "-", "-", "安徽移动IDC", "-", "-", "合肥市高新区", "合肥市高新区机房", "安徽移动", "-", "-", "静态", "IDC资产系统", "安徽合肥-高新机房", "IDC-Rack-001", "2025-11-01 10:00:00"),
            # 自有业务
            ("111.0.0.1", "IPv4", "自有业务", "0", "2026-01-01 00:00:00", "2026-12-31 23:59:59",
             "-", "-", "安徽移动", "13800008888", "13800008888", "合肥市", "合肥市黄山路609号", "安徽移动", "-", "-", "静态", "自有业务平台", "安徽合肥", "自有业务-001", "2025-10-01 10:00:00"),
        ]
        for s in samples:
            # mask id_card if not "-"
            id_plain = s[14]
            id_masked = id_plain if id_plain == "-" else (id_plain[:6] + "********" + id_plain[-4:]) if len(id_plain) > 10 else id_plain
            raw = json.dumps({
                "ip": s[0], "version": s[1], "scene": s[2], "port": s[3],
                "user": s[6], "phone": s[9], "unit": s[13], "source": s[17]
            }, ensure_ascii=False)
            conn.execute(
                """INSERT INTO ip_subjects (id, ip_address, ip_version, scene_type, port, start_time, end_time,
                   user_name, user_name_plain, user_id, phone, phone_plain, address, address_plain,
                   unit_name, unit_name_plain, id_card, id_card_plain, bandwidth, ip_type, data_source,
                   data_source_id, location, access_node, create_time, raw_data, created_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (gen_id("ip_"), s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7], s[8], s[9], s[10], s[11], s[12],
                 s[13], s[13], id_masked, id_plain, s[15], s[16], s[17], None, s[18], s[19], s[20], raw, now_str()),
            )

        # Conflict tickets (sample)
        tickets = [
            ("CT20260101001", "10.0.1.100", "数据冲突", "字段冲突", "用户姓名在不同数据源中不一致", "user_name",
             json.dumps([{"source": "移网AAA", "value": "张三"}, {"source": "BRAS", "value": "张森"}]),
             "以AAA系统数据为准", "open", "", "", ""),
            ("CT20260101002", "192.168.1.100", "系统检测", "数据不一致", "手机号格式异常", "phone",
             json.dumps([{"source": "家宽BRAS", "value": "13600008004"}, {"source": "CRM", "value": "1360000800X"}]),
             "核实CRM系统数据", "processing", "李四", "已联系用户核实", ""),
            ("CT20260101003", "172.16.1.100", "数据冲突", "字段冲突", "单位名称不一致", "unit_name",
             json.dumps([{"source": "专线资源", "value": "安徽XX科技有限公司"}, {"source": "工商系统", "value": "安徽XX科技有限责任公司"}]),
             "以工商系统注册名称为准", "resolved", "王五", "已修正为工商注册名", ""),
        ]
        for t in tickets:
            lifecycle = json.dumps([
                {"node": "工单创建", "time": now_str(), "operator": "系统"},
                {"node": "工单分派", "time": now_str(), "operator": "系统"},
                {"node": "处理中", "time": now_str() if t[8] != "open" else "", "operator": t[9]},
            ])
            conn.execute(
                """INSERT INTO conflict_tickets (id, ticket_no, ip_address, conflict_source, conflict_type, conflict_desc,
                   field_name, source_values, suggestion, status, handler, handle_remark, handle_evidence,
                   created_at, processed_at, closed_at, lifecycle)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (gen_id("ct_"), t[0], t[1], t[2], t[3], t[4], t[5], t[6], t[7], t[8], t[9], t[10], t[11],
                 now_str(), now_str() if t[8] != "open" else None, now_str() if t[8] == "resolved" else None, lifecycle),
            )

        # Security config defaults
        sec_configs = [
            ("password_history_count", "3", "密码历史留存规则-不能重复使用最近N次密码"),
            ("password_valid_days", "90", "密码有效天数"),
            ("password_expire_remind_days", "7", "密码到期前置提醒天数"),
            ("password_min_length", "8", "密码最小长度"),
            ("password_complexity_desc", "密码长度不少于8位，需包含大小写字母、数字、特殊字符中至少3种", "密码复杂度说明"),
            ("login_fail_lock_threshold", "5", "登录失败锁定次数阈值"),
            ("account_lock_duration", "30", "账号锁定持续时长(分钟)"),
            ("session_idle_timeout", "30", "会话空闲超时时间(分钟)"),
            ("ip_access_enabled", "0", "是否启用IP访问限制(0默认全部放开)"),
        ]
        for sc in sec_configs:
            conn.execute(
                "INSERT INTO security_config (id, config_key, config_value, description, updated_at) VALUES (?,?,?,?,?)",
                (gen_id("cfg_"), *sc, now_str()),
            )


if __name__ == "__main__":
    init_db()
    print(f"Database initialized at {get_db_path()}")
