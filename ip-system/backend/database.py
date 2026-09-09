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

-- 场景查询路径表(可视化编排: 开始/执行/判断节点及连线分支)
CREATE TABLE IF NOT EXISTS scene_paths (
    id TEXT PRIMARY KEY,
    scene_id TEXT NOT NULL,
    name TEXT,
    nodes TEXT,                  -- 节点JSON: 开始/执行(绑定数据源)/判断(条件分支)节点
    edges TEXT,                  -- 连线JSON: from/to/label(命中/未命中)
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
    created_at TEXT,
    -- 数据源真实字段(四类数据源扩展)
    source_subtype TEXT,       -- 数据源子类型: 家宽/信安/移网/综资
    subscriber_id TEXT,        -- 用户标识: 家宽SUBSCRIBERID/移网用户永久标识
    city_id TEXT,             -- 城市编码(用于数据字典翻译CITY_ID→CITY_NAME)
    ipv4_address TEXT,         -- IPv4地址(数据源原始IPV4ADDRESS)
    ipv6_address TEXT,         -- IPv6地址(数据源原始IPV6ADDRESS)
    nat_begin_port TEXT,      -- NAT起始端口(家宽)
    nat_end_port TEXT,        -- NAT终止端口(家宽)
    isp_license TEXT,         -- IDC/ISP许可证号(信安)
    unit_attr TEXT,           -- 单位属性(信安)
    cert_type TEXT,           -- 证件类型(信安/综资)
    cert_no TEXT,             -- 证件号码(信安/综资)
    postal_code TEXT,         -- 邮政编码(信安)
    register_time TEXT,       -- 注册时间(信安)
    service_open_time TEXT,   -- 服务开通时间(信安/综资变更时间)
    unit_address TEXT,        -- 单位地址(信安)
    security_person_name TEXT,    -- 网络信息安全责任人姓名(信安)
    security_person_cert_type TEXT,
    security_person_cert_no TEXT,
    security_person_phone TEXT,    -- 固定电话(信安)
    security_person_mobile TEXT,  -- 移动电话(信安)
    security_person_email TEXT,   -- 邮箱(信安)
    user_remark TEXT,         -- 用户备注信息(信安)
    machine_room TEXT,       -- 所属机房(信安/综资)
    machine_room_area TEXT,  -- 机房区域名称(信安)
    rack_name TEXT,          -- 机柜名称(信安)
    resource_alloc_time TEXT, -- 资源分配时间(信安)
    ip_type_code TEXT,       -- IP类型编码(信安 0=...)
    public_ip_start TEXT,    -- 外网起始IP(信安)
    public_ip_end TEXT,      -- 外网终止IP(信安)
    network_bandwidth TEXT,  -- 网络带宽(信安)
    region_code TEXT,        -- 所属区域编码(信安)
    app_service_type TEXT,   -- 应用服务类型(信安)
    business_type TEXT,      -- 业务类型(信安/移网/综资)
    link_info TEXT,          -- 用户使用链路信息(信安)
    -- 移网扩展字段
    public_user_id TEXT,     -- 通用公共用户标识(移网)
    permanent_device_id TEXT, -- 永久设备标识(移网)
    user_private_ip TEXT,    -- 用户私网IP地址(移网)
    source_public_ip TEXT,   -- 源公网IP地址(移网)
    private_port TEXT,       -- 私网端口号(移网)
    source_port TEXT,        -- 源端口号(移网)
    dest_ip TEXT,            -- 目的IP地址(移网)
    dest_port TEXT,          -- 目的端口号(移网)
    transport_protocol TEXT, -- 数据传输协议(移网)
    user_url TEXT,           -- 用户访问URL(移网)
    access_location TEXT,    -- 接入位置(移网)
    login_cell_id TEXT,      -- 登录小区号(移网)
    logout_cell_id TEXT,     -- 下线小区号(移网)
    base_station_id TEXT,   -- 基站标识(移网)
    visit_network_id TEXT,  -- 拜访网络标识(移网)
    network_type TEXT,       -- 网络类型(移网)
    roam_flag TEXT,          -- 用户漫游标志(移网)
    slice_id TEXT,           -- 网络切片选择辅助标识(移网)
    visit_duration TEXT,     -- 访问时长(移网)
    send_bytes TEXT,         -- 发送字节数(移网)
    recv_bytes TEXT,         -- 接收字节数(移网)
    send_packets TEXT,       -- 发送包数(移网)
    recv_packets TEXT,       -- 接收包数(移网)
    pdu_session_id TEXT,     -- PDU会话标识(移网)
    nat_device_id TEXT,      -- NAT设备标识(移网)
    operator_id TEXT,        -- 运营商标识(移网)
    access_mode_5g TEXT,     -- 5GSA/NSA接入标识(移网)
    dnn TEXT,                -- DNN(移网)
    collector_left_ip TEXT,  -- 采集点左侧网元IP(移网)
    collector_right_ip TEXT, -- 采集点右侧网元IP(移网)
    protocol_type TEXT,      -- 协议类型(移网)
    http_method TEXT,        -- http请求类型(移网)
    home_id TEXT,            -- 归属地标识(移网)
    link_access_id TEXT,     -- 链接访问标识(移网)
    vpn_id TEXT,             -- VPN标识(移网)
    location_type TEXT,      -- 位置区类型(移网)
    location_id TEXT,       -- 位置区标识(移网)
    ext_field TEXT,          -- 扩展字段(移网)
    -- 综资扩展字段
    is_pro_company TEXT,     -- 是否是专业公司(综资)
    pro_company_name TEXT,   -- 专业公司名称(综资)
    unit_category TEXT,      -- 单位所属分类(综资)
    unit_nature TEXT,        -- 单位性质(综资)
    unit_admin_level TEXT,   -- 单位行政级别(综资)
    unit_industry TEXT,      -- 单位所属行业分类(综资)
    contact_person_client TEXT,    -- 联系人姓名-客户侧(综资)
    contact_phone_client TEXT,     -- 联系人电话-客户侧(综资)
    contact_email_client TEXT,     -- 联系人邮箱-客户侧(综资)
    gateway_location TEXT,   -- 网关物理位置(综资)
    use_mode TEXT,           -- 使用方式(综资)
    gateway_ip TEXT,         -- 网关IP地址(综资)
    device_status TEXT,      -- 使用状态(综资)
    manage_status TEXT,      -- 管理状态(综资)
    device_room TEXT,        -- 设备所属机房(综资)
    loopback_ip TEXT,        -- Loopbak地址(综资)
    resp_dept TEXT,          -- 负责部门-移动侧(综资)
    resp_person_name TEXT,   -- 负责人姓名-移动侧(综资)
    resp_person_phone TEXT,  -- 负责人电话-移动侧(综资)
    resp_person_email TEXT,  -- 负责人邮箱-移动侧(综资)
    unit_cert_type TEXT,     -- 单位证件类型(综资)
    unit_cert_no TEXT,       -- 单位证件号码(综资)
    address_type TEXT,       -- 地址类型(综资)
    product_instance_id TEXT, -- 产品实例标识(综资)
    device_id TEXT,          -- 所属设备(综资)
    change_time TEXT         -- 变更时间(综资)
);

-- 数据字典表(编码→名称映射, 如 CITY_ID → CITY_NAME)
CREATE TABLE IF NOT EXISTS data_dictionary (
    id TEXT PRIMARY KEY,
    dict_type TEXT NOT NULL,        -- 字典类型: CITY/PROVINCE/OPERATOR等
    dict_code TEXT NOT NULL,        -- 编码值(如 CITY_ID=6)
    dict_name TEXT NOT NULL,        -- 名称(如 合肥市)
    description TEXT,              -- 描述说明
    status TEXT DEFAULT 'active',  -- active/inactive
    created_at TEXT,
    updated_at TEXT,
    UNIQUE(dict_type, dict_code)
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
    path_snapshot TEXT,       -- 执行时配置的场景路径快照JSON {name,nodes,edges}
    created_by TEXT,
    created_at TEXT,
    completed_at TEXT,
    batch_id TEXT             -- 批量导入批次ID
);

-- 查询任务执行路径
CREATE TABLE IF NOT EXISTS task_paths (
    id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL,
    node_id TEXT,             -- 对应路径快照中的节点ID
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
        migrate_query_tables(conn)
        migrate_ip_subjects(conn)
    seed_data()
    seed_data_dictionary()
    seed_real_test_data()


def seed_data_dictionary():
    """Seed data dictionary entries (CITY_ID → CITY_NAME, etc.)."""
    with get_conn() as conn:
        existing = conn.execute("SELECT COUNT(*) as c FROM data_dictionary WHERE dict_type='CITY'").fetchone()["c"]
        if existing > 0:
            return
        # Anhui province city code mapping (matches the CITY_ID field in 家宽/移网/综资 data)
        cities = [
            ("1", "合肥市"), ("2", "芜湖市"), ("3", "蚌埠市"), ("4", "淮南市"),
            ("5", "马鞍山市"), ("6", "淮北市"), ("7", "铜陵市"), ("8", "安庆市"),
            ("9", "黄山市"), ("10", "滁州市"), ("11", "阜阳市"), ("12", "宿州市"),
            ("13", "六安市"), ("14", "亳州市"), ("15", "池州市"), ("16", "宣城市"),
        ]
        for code, name in cities:
            conn.execute(
                "INSERT INTO data_dictionary (id, dict_type, dict_code, dict_name, description, status, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?)",
                (gen_id("dd_"), "CITY", code, name, "安徽省地市编码", "active", now_str(), now_str()),
            )
        # 网络类型 (移网)
        network_types = [("3", "5G"), ("2", "4G"), ("1", "3G")]
        for code, name in network_types:
            conn.execute(
                "INSERT INTO data_dictionary (id, dict_type, dict_code, dict_name, description, status, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?)",
                (gen_id("dd_"), "NETWORK_TYPE", code, name, "移网接入网络类型", "active", now_str(), now_str()),
            )
        # 单位属性 (信安)
        unit_attrs = [("4", "增值电信业务经营者")]
        for code, name in unit_attrs:
            conn.execute(
                "INSERT INTO data_dictionary (id, dict_type, dict_code, dict_name, description, status, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?)",
                (gen_id("dd_"), "UNIT_ATTR", code, name, "信安系统单位属性", "active", now_str(), now_str()),
            )
        # 证件类型 (信安/综资)
        cert_types = [("1", "工商营业执照"), ("2", "组织机构代码证"), ("3", "事业单位法人证书")]
        for code, name in cert_types:
            conn.execute(
                "INSERT INTO data_dictionary (id, dict_type, dict_code, dict_name, description, status, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?)",
                (gen_id("dd_"), "CERT_TYPE", code, name, "证件类型", "active", now_str(), now_str()),
            )
        # 应用服务类型 (信安)
        app_service_types = [("999", "其他"), ("3", "IDC业务")]
        for code, name in app_service_types:
            conn.execute(
                "INSERT INTO data_dictionary (id, dict_type, dict_code, dict_name, description, status, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?)",
                (gen_id("dd_"), "APP_SERVICE_TYPE", code, name, "信安系统应用服务类型", "active", now_str(), now_str()),
            )
        # 业务类型 (信安/综资)
        business_types = [("1", "互联网接入"), ("5", "IDC业务")]
        for code, name in business_types:
            conn.execute(
                "INSERT INTO data_dictionary (id, dict_type, dict_code, dict_name, description, status, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?)",
                (gen_id("dd_"), "BUSINESS_TYPE", code, name, "业务类型", "active", now_str(), now_str()),
            )


def seed_real_test_data():
    """Import the four real test datasets (家宽/信安/移网/综资) into ip_subjects."""
    with get_conn() as conn:
        existing = conn.execute("SELECT COUNT(*) as c FROM ip_subjects WHERE source_subtype='家宽'").fetchone()["c"]
        if existing > 0:
            return
        _seed_home_broadband(conn)
        _seed_xinan_system(conn)
        _seed_mobile_network(conn)
        _seed_zongzi(conn)


def _seed_home_broadband(conn):
    """家宽测试集（动态）数据"""
    def _fmt(t):
        # Convert "20260901000016" -> "2026-09-01 00:00:16" for consistent time filtering
        if len(t) == 14 and t.isdigit():
            return f"{t[0:4]}-{t[4:6]}-{t[6:8]} {t[8:10]}:{t[10:12]}:{t[12:14]}"
        return t
    rows = [
        ("13800000001", "20260901000016", "20260902000003", "10.2.0.1",  "2409:8a30:a80e::b087", "1024", "2047", "6"),
        ("13800000002", "20260901000016", "20260902000003", "10.2.0.2",  "2409:8a30:a80e::a231", "1024", "2047", "6"),
        ("13800000003", "20260901000016", "20260902000003", "10.2.0.3",  "2409:8a30:8c09::1306", "1024", "2047", "14"),
        ("13800000004", "20260901000016", "20260902000003", "10.2.0.4",  "2409:8a30:a80e::6f41", "1024", "2047", "6"),
        ("13800000005", "20260901000016", "20260902000003", "10.2.0.5",  "2409:8a30:a80e::6112", "1024", "2047", "6"),
        ("13800000006", "20260901000016", "20260902000003", "10.2.0.6",  "2409:8a30:940b::dc22", "1024", "2047", "14"),
        ("13800000007", "20260901000016", "20260902000003", "10.2.0.7",  "2409:8a30:3c01::aef4", "1024", "2047", "11"),
        ("13800000008", "20260901000016", "20260902000003", "10.2.0.8",  "2409:8a30:0a06::c9dd", "1024", "2047", "1"),
        ("13800000009", "20260901000016", "20260902000003", "10.2.0.9",  "2409:8a31:0c0b::4e42", "1024", "2047", "1"),
        ("13800000010", "20260901000016", "20260902000003", "10.2.0.10", "2409:8a30:5f04::74a1", "1024", "2047", "5"),
        ("13800000011", "20260901000016", "20260902000003", "10.2.0.11", "2409:8a30:2004::f0fd", "1024", "2047", "2"),
        ("13800000012", "20260901000016", "20260902000003", "10.2.0.12", "2409:8a30:020e::3b55", "1024", "2047", "1"),
        ("13800000013", "20260901000016", "20260902000003", "10.2.0.13", "2409:8a30:2e0e::8326", "1024", "2047", "3"),
        ("13800000014", "20260901000016", "20260902000003", "10.2.0.14", "2409:8a30:7e07::2ba9", "1024", "2047", "4"),
        ("13800000015", "20260901000016", "20260902000003", "10.2.0.15", "2409:8a30:9a08::0ea9", "1024", "2047", "14"),
        ("13800000016", "20260901000016", "20260902000003", "10.2.0.16", "2409:8a31:1004::44c9", "1024", "2047", "1"),
    ]
    for r in rows:
        begin_t = _fmt(r[1])
        end_t = _fmt(r[2])
        raw = json.dumps({
            "SUBSCRIBERID": r[0], "BEGINTIME": r[1], "ENDTIME": r[2],
            "IPV4ADDRESS": r[3], "IPV6ADDRESS": r[4],
            "NAT_BEGIN_PORT": r[5], "NAT_END_PORT": r[6], "CITY_ID": r[7],
        }, ensure_ascii=False)
        conn.execute(
            """INSERT INTO ip_subjects (
                id, ip_address, ip_version, scene_type, port, start_time, end_time,
                data_source, ip_type, raw_data, created_at,
                source_subtype, subscriber_id, city_id, ipv4_address, ipv6_address,
                nat_begin_port, nat_end_port
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (gen_id("ip_"), r[3], "IPv4", "家宽", "0", begin_t, end_t,
             "家宽BRAS数据源", "动态", raw, now_str(),
             "家宽", r[0], r[7], r[3], r[4], r[5], r[6]),
        )


def _seed_xinan_system(conn):
    """信安系统测试集（静态）数据 (28 columns matching source data)"""
    # Indices map to source columns:
    # 0=IDC/ISP许可证号, 1=单位名称, 2=单位属性, 3=证件类型, 4=证件号码, 5=邮政编码,
    # 6=注册时间, 7=服务开通时间, 8=单位地址XA, 9=责任人-姓名, 10=责任人-证件类型,
    # 11=责任人-证件号码, 12=责任人-固定电话, 13=责任人-移动电话, 14=责任人-Email,
    # 15=用户备注信息, 16=所属机房, 17=机房区域名称, 18=机柜名称, 19=资源分配时间,
    # 20=IP类型, 21=外网起始IP, 22=外网终止IP, 23=网络带宽, 24=所属区域,
    # 25=应用服务类型, 26=业务类型, 27=用户使用链路信息
    rows = [
        ("", "单位XA0000001", "4", "1", "91000000001", "", "", "2026/8/1", "地址XA0000001",
         "某某XA0000001", "", "", "", "13600000001", "13600000001@136.com", "",
         "马鞍山", "雨山", "", "2020-07-01", "0", "10.1.0.1", "10.1.0.1", "", "340404", "999", "1", ""),
        ("", "单位XA0000002", "4", "1", "91000000002", "", "", "2026/1/20", "地址XA0000002",
         "某某XA0000002", "", "", "", "13600000002", "13600000002@136.com", "",
         "马鞍山", "雨山", "", "2026-02-12", "0", "10.1.0.2", "10.1.0.2", "", "340200", "999", "1", ""),
        ("", "单位XA0000003", "4", "1", "91000000003", "", "", "2026/7/29", "地址XA0000003",
         "某某XA0000003", "", "", "", "13600000003", "13600000003@136.com", "",
         "马鞍山", "雨山", "", "2024-01-09", "0", "10.1.0.3", "10.1.0.3", "", "340202", "999", "1", ""),
        ("", "单位XA0000004", "4", "1", "91000000004", "", "", "2026/1/11", "地址XA0000004",
         "某某XA0000004", "", "", "", "13600000004", "13600000004@136.com", "",
         "马鞍山", "雨山", "", "2024-01-11", "0", "10.1.0.4", "10.1.0.4", "", "341802", "3", "1", ""),
        ("", "单位XA0000005", "4", "1", "91000000005", "", "", "2024/8/22", "地址XA0000005",
         "某某XA0000005", "", "", "", "13600000005", "13600000005@136.com", "",
         "滁州", "天长", "", "2024-01-11", "0", "10.1.0.5", "10.1.0.5", "", "340404", "999", "5", ""),
    ]
    for r in rows:
        raw = json.dumps({
            "IDC/ISP许可证号": r[0], "单位名称": r[1], "单位属性": r[2],
            "证件类型": r[3], "证件号码": r[4], "邮政编码": r[5], "注册时间": r[6],
            "服务开通时间": r[7], "单位地址XA": r[8],
            "网络信息安全责任人-姓名": r[9], "网络信息安全责任人-证件类型": r[10],
            "网络信息安全责任人-证件号码": r[11], "网络信息安全责任人-固定电话": r[12],
            "网络信息安全责任人-移动电话": r[13], "网络信息安全责任人-Email": r[14],
            "用户备注信息": r[15], "所属机房": r[16], "机房区域名称": r[17],
            "机柜名称": r[18], "资源分配时间": r[19], "IP类型": r[20],
            "外网起始IP": r[21], "外网终止IP": r[22], "网络带宽": r[23],
            "所属区域": r[24], "应用服务类型": r[25], "业务类型": r[26], "用户使用链路信息": r[27],
        }, ensure_ascii=False)
        conn.execute(
            """INSERT INTO ip_subjects (
                id, ip_address, ip_version, scene_type, port, start_time, end_time,
                unit_name, unit_name_plain, data_source, ip_type, raw_data, created_at,
                source_subtype, isp_license, unit_attr, cert_type, cert_no, postal_code,
                register_time, service_open_time, unit_address,
                security_person_name, security_person_cert_type, security_person_cert_no,
                security_person_phone, security_person_mobile, security_person_email,
                user_remark, machine_room, machine_room_area, rack_name, resource_alloc_time,
                ip_type_code, public_ip_start, public_ip_end, network_bandwidth, region_code,
                app_service_type, business_type, link_info
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (gen_id("ip_"), r[21], "IPv4", "IDC", "0", r[6], r[19],
             r[1], r[1], "信安系统", "静态", raw, now_str(),
             "信安", r[0], r[2], r[3], r[4], r[5], r[6], r[7], r[8],
             r[9], r[10], r[11], r[12], r[13], r[14], r[15], r[16], r[17], r[18], r[19],
             r[20], r[21], r[22], r[23], r[24], r[25], r[26], r[27]),
        )


def _seed_mobile_network(conn):
    """移网测试集（动态）数据"""
    def _fmt(t):
        # Convert "20260901000000" -> "2026-09-01 00:00:00" for consistent time filtering
        if len(t) == 14 and t.isdigit():
            return f"{t[0:4]}-{t[4:6]}-{t[6:8]} {t[8:10]}:{t[10:12]}:{t[12:14]}"
        return t
    rows = [
        ("13700000001", "10.3.0.1", "2047", "2047", "", "443", "0", "", "4609290",
         "6200000000", "6100000000", "1700000", "551", "3", "0", "",
         "20260901000000", "20260901000059", "59", "1584", "6938", "12", "14", "551"),
        ("13700000002", "10.3.0.2", "2047", "2047", "", "53", "1", "", "4609290",
         "6200000000", "6100000000", "1700000", "551", "3", "0", "",
         "20260901000000", "20260901000059", "59", "87", "442", "1", "1", "551"),
        ("13700000003", "10.3.0.3", "2047", "2047", "", "443", "0", "", "4609290",
         "6200000000", "6100000000", "1700000", "551", "3", "0", "",
         "20260901000000", "20260901000059", "59", "937", "847", "6", "6", "551"),
    ]
    field_names = [
        "用户永久标识", "用户私网IP地址", "私网端口号", "源端口号", "源公网IP地址",
        "目的端口号", "数据传输协议", "用户访问URL", "接入位置", "登录小区号",
        "下线小区号", "基站标识", "拜访网络标识", "网络类型", "用户漫游标志",
        "网络切片选择辅助标识", "访问开始时间", "访问结束时间", "访问时长",
        "发送字节数", "接收字节数", "发送包数", "接收包数", "归属地标识",
    ]
    for r in rows:
        raw_dict = dict(zip(field_names, r))
        raw = json.dumps(raw_dict, ensure_ascii=False)
        begin_t = _fmt(r[16])
        end_t = _fmt(r[17])
        conn.execute(
            """INSERT INTO ip_subjects (
                id, ip_address, ip_version, scene_type, port, start_time, end_time,
                user_id, data_source, ip_type, raw_data, created_at,
                source_subtype, subscriber_id, user_private_ip, private_port, source_port,
                source_public_ip, dest_port, transport_protocol, user_url, access_location,
                login_cell_id, logout_cell_id, base_station_id, visit_network_id, network_type,
                roam_flag, slice_id, visit_duration, send_bytes, recv_bytes, send_packets,
                recv_packets, home_id
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (gen_id("ip_"), r[1], "IPv4", "移网", "0", begin_t, end_t,
             r[0], "移网AAA数据源", "动态", raw, now_str(),
             "移网", r[0], r[1], r[2], r[3], r[4], r[5], r[6], r[7], r[8],
             r[9], r[10], r[11], r[12], r[13], r[14], r[15], r[18], r[19], r[20], r[21], r[22], r[23]),
        )


def _seed_zongzi(conn):
    """综资测试集（静态）数据 (32 columns matching source data)"""
    rows = [
        # IPv4地址名称, 是否专业公司, 专业公司名称, 单位名称, 单位分类, 单位性质, 所属地市, 所属区县,
        # 单位行政级别, 单位行业, 地址, 联系人姓名, 联系人电话, 联系人邮箱, 网关物理位置, 使用方式,
        # 网关IP, 业务类型, 使用状态, 管理状态, 设备所属机房, Loopbak, 负责部门, 负责人姓名,
        # 负责人电话, 负责人邮箱, 单位证件类型, 单位证件号码, 地址类型, 产品实例ID, 所属设备, 变更时间
        ("10.1.0.1", "", "", "单位ZZ0000001", "其他", "企业", "马鞍山", "雨山",
         "无行政级别", "教育", "地址0000001", "某某0000001", "13900000001", "13900000001@139.com",
         "", "静态", "", "互联网专线", "占用", "已启用", "", "", "政企部", "", "", "",
         "统一社会信用代码", "90000000001", "公网", "", "", "2025/12/22 16:30"),
        ("10.1.0.2", "", "", "单位ZZ0000002", "其他", "企业", "马鞍山", "雨山",
         "无行政级别", "教育", "地址0000002", "某某0000002", "13900000002", "13900000002@139.com",
         "", "静态", "", "互联网专线", "占用", "已启用", "", "", "政企部", "", "", "",
         "统一社会信用代码", "90000000002", "公网", "", "", "2025/12/22 16:30"),
        ("10.1.0.3", "", "", "单位ZZ0000003", "其他", "企业", "马鞍山", "雨山",
         "无行政级别", "教育", "地址0000003", "某某0000003", "13900000003", "13900000003@139.com",
         "", "静态", "", "互联网专线", "占用", "已启用", "", "", "政企部", "", "", "",
         "统一社会信用代码", "90000000003", "公网", "", "", "2025/12/22 16:30"),
    ]
    field_names = [
        "IPv4地址名称", "是否是专业公司", "专业公司名称", "单位名称/具体业务信息",
        "单位所属分类", "单位性质", "所属地市", "所属区县", "单位行政级别",
        "单位所属行业分类", "地址详细地址", "联系人姓名(客户侧)", "联系人电话(客户侧)",
        "联系人邮箱(客户侧)", "网关物理位置", "使用方式", "网关IP地址", "业务类型",
        "使用状态", "管理状态", "设备所属机房", "Loopbak地址", "负责部门(移动侧)",
        "负责人姓名(移动侧)", "负责人电话(移动侧)", "负责人邮箱(移动侧)",
        "单位证件类型", "单位证件号码", "地址类型", "产品实例标识", "所属设备", "变更时间",
    ]
    for r in rows:
        raw_dict = dict(zip(field_names, r))
        raw = json.dumps(raw_dict, ensure_ascii=False)
        # r indices: 0=IP, 1=是否专业公司, 2=专业公司名称, 3=单位名称, 4=单位分类, 5=单位性质,
        # 6=所属地市, 7=所属区县, 8=单位行政级别, 9=单位行业, 10=地址, 11=联系人姓名,
        # 12=联系人电话, 13=联系人邮箱, 14=网关物理位置, 15=使用方式, 16=网关IP, 17=业务类型,
        # 18=使用状态, 19=管理状态, 20=设备所属机房, 21=Loopbak, 22=负责部门, 23=负责人姓名,
        # 24=负责人电话, 25=负责人邮箱, 26=单位证件类型, 27=单位证件号码, 28=地址类型,
        # 29=产品实例标识, 30=所属设备, 31=变更时间
        conn.execute(
            """INSERT INTO ip_subjects (
                id, ip_address, ip_version, scene_type, port, start_time, end_time,
                unit_name, unit_name_plain, address, address_plain, data_source, ip_type,
                raw_data, created_at, source_subtype, ipv4_address, is_pro_company,
                pro_company_name, unit_category, unit_nature, unit_admin_level,
                unit_industry, contact_person_client, contact_phone_client,
                contact_email_client, gateway_location, use_mode, gateway_ip,
                business_type, device_status, manage_status, device_room, loopback_ip,
                resp_dept, resp_person_name, resp_person_phone, resp_person_email,
                unit_cert_type, unit_cert_no, address_type, product_instance_id,
                device_id, change_time
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (gen_id("ip_"), r[0], "IPv4", "专线", "0", r[31], r[31],
             r[3], r[3], r[10], r[10], "综资系统", "静态", raw, now_str(),
             "综资", r[0], r[1], r[2], r[4], r[5], r[8], r[9], r[11], r[12],
             r[13], r[14], r[15], r[16], r[17], r[18], r[19], r[20], r[21],
             r[22], r[23], r[24], r[25], r[26], r[27], r[28], r[29], r[30], r[31]),
        )


def migrate_query_tables(conn):
    """Add path_snapshot/node_id columns to existing query_tasks/task_paths tables."""
    task_cols = [r[1] for r in conn.execute("PRAGMA table_info(query_tasks)").fetchall()]
    if task_cols and "path_snapshot" not in task_cols:
        conn.execute("ALTER TABLE query_tasks ADD COLUMN path_snapshot TEXT")
    path_cols = [r[1] for r in conn.execute("PRAGMA table_info(task_paths)").fetchall()]
    if path_cols and "node_id" not in path_cols:
        conn.execute("ALTER TABLE task_paths ADD COLUMN node_id TEXT")


def migrate_ip_subjects(conn):
    """Add new data-source-specific columns to ip_subjects for existing databases."""
    new_cols = [
        "source_subtype", "subscriber_id", "city_id", "ipv4_address", "ipv6_address",
        "nat_begin_port", "nat_end_port", "isp_license", "unit_attr", "cert_type", "cert_no",
        "postal_code", "register_time", "service_open_time", "unit_address",
        "security_person_name", "security_person_cert_type", "security_person_cert_no",
        "security_person_phone", "security_person_mobile", "security_person_email",
        "user_remark", "machine_room", "machine_room_area", "rack_name",
        "resource_alloc_time", "ip_type_code", "public_ip_start", "public_ip_end",
        "network_bandwidth", "region_code", "app_service_type", "business_type", "link_info",
        "public_user_id", "permanent_device_id", "user_private_ip", "source_public_ip",
        "private_port", "source_port", "dest_ip", "dest_port", "transport_protocol",
        "user_url", "access_location", "login_cell_id", "logout_cell_id", "base_station_id",
        "visit_network_id", "network_type", "roam_flag", "slice_id", "visit_duration",
        "send_bytes", "recv_bytes", "send_packets", "recv_packets", "pdu_session_id",
        "nat_device_id", "operator_id", "access_mode_5g", "dnn", "collector_left_ip",
        "collector_right_ip", "protocol_type", "http_method", "home_id", "link_access_id",
        "vpn_id", "location_type", "location_id", "ext_field",
        "is_pro_company", "pro_company_name", "unit_category", "unit_nature",
        "unit_admin_level", "unit_industry", "contact_person_client", "contact_phone_client",
        "contact_email_client", "gateway_location", "use_mode", "gateway_ip", "device_status",
        "manage_status", "device_room", "loopback_ip", "resp_dept", "resp_person_name",
        "resp_person_phone", "resp_person_email", "unit_cert_type", "unit_cert_no",
        "address_type", "product_instance_id", "device_id", "change_time",
    ]
    existing = [r[1] for r in conn.execute("PRAGMA table_info(ip_subjects)").fetchall()]
    for col in new_cols:
        if col not in existing:
            conn.execute(f"ALTER TABLE ip_subjects ADD COLUMN {col} TEXT")


def build_default_path(ds_items):
    """Build default query path: start -> exec(ds1) -> judge(是否命中) --命中/未命中--> ...
    ds_items: [(data_source_id, data_source_name), ...]
    Returns (nodes, edges) lists."""
    nodes = [{"id": "n_start", "type": "start", "name": "开始", "x": 40, "y": 160}]
    edges = []
    prev_id = "n_start"
    for i, (ds_id, ds_name) in enumerate(ds_items):
        eid, jid = f"n_exec{i+1}", f"n_judge{i+1}"
        nodes.append({"id": eid, "type": "execute", "name": f"查询{ds_name}", "x": 260 + i*230, "y": 160, "data_source_id": ds_id, "query_target": f"{ds_name}IP主体信息"})
        nodes.append({"id": jid, "type": "judge", "name": "是否命中", "x": 470 + i*230, "y": 160, "condition": "是否命中"})
        edges.append({"from": prev_id, "to": eid})
        edges.append({"from": eid, "to": jid})
        prev_id = jid
    end_x = 680 + 230*max(len(ds_items)-1, 0)
    nodes.append({"id": "n_end", "type": "execute", "name": "返回结果", "x": end_x, "y": 160})
    if ds_items:
        edges.append({"from": prev_id, "to": "n_end", "label": "命中"})
        edges.append({"from": prev_id, "to": "n_end", "label": "未命中"})
    else:
        edges.append({"from": prev_id, "to": "n_end"})
    return nodes, edges


def migrate_scene_paths(conn):
    """Migrate scene_paths table to the nodes/edges visual path schema."""
    cols = [r[1] for r in conn.execute("PRAGMA table_info(scene_paths)").fetchall()]
    if "nodes" in cols:
        return  # already target schema
    # Old schema (data_source_ids only): rebuild as nodes/edges
    conn.execute("ALTER TABLE scene_paths RENAME TO scene_paths_old")
    conn.execute("""
        CREATE TABLE scene_paths (
            id TEXT PRIMARY KEY,
            scene_id TEXT NOT NULL,
            name TEXT,
            nodes TEXT,
            edges TEXT,
            status TEXT DEFAULT 'draft',
            created_at TEXT,
            updated_at TEXT,
            FOREIGN KEY (scene_id) REFERENCES scenes(id) ON DELETE CASCADE
        )
    """)
    old_rows = conn.execute("SELECT * FROM scene_paths_old").fetchall()
    for row in old_rows:
        try:
            ds_ids = json.loads(row["data_source_ids"] or "[]")
        except Exception:
            ds_ids = []
        ds_items = []
        for did in ds_ids:
            r = conn.execute("SELECT id, name FROM data_sources WHERE id=?", (did,)).fetchone()
            if r:
                ds_items.append((r["id"], r["name"]))
        nodes, edges = build_default_path(ds_items)
        conn.execute(
            "INSERT INTO scene_paths (id, scene_id, name, nodes, edges, status, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?)",
            (row["id"], row["scene_id"], row["name"], json.dumps(nodes, ensure_ascii=False), json.dumps(edges, ensure_ascii=False), row["status"], row["created_at"], row["updated_at"]),
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
            scene_ds_map.setdefault(ds[1], []).append((ds_id, ds[0]))

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
            ("家宽IP定位场景", "家宽", "192.168.0.0/16,10.1.0.0/16,10.2.0.0/16", "家庭宽带用户IP主体定位"),
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
            # default path: visual query path (start -> exec(ds) -> judge -> end)
            ds_items = scene_ds_map.get(s[1], [])
            nodes, edges = build_default_path(ds_items)
            conn.execute(
                "INSERT INTO scene_paths (id, scene_id, name, nodes, edges, status, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?)",
                (gen_id("sp_"), sid, f"{s[0]}查询路径", json.dumps(nodes, ensure_ascii=False), json.dumps(edges, ensure_ascii=False), "published", now_str(), now_str()),
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
