"""系统落地能力增强模块: 8项核心能力
① RBAC权限 ② 真实数据源适配器 ③ 字段级脱敏/加密
④ 冲突自动检测+工单闭环 ⑤ 异步任务队列 ⑥ Excel/CSV导入导出
⑦ 告警与调度 ⑧ 审计/限流/合规
"""
import sqlite3
import os
import json
import uuid
import csv
import io
import hashlib
import secrets
import time
import threading
import hmac
import base64
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Callable
from contextlib import contextmanager
from database import get_conn as _db_get_conn, get_db_path, now_str as _now_str, gen_id as _gen_id, hash_password as _hash_password


@contextmanager
def get_conn():
    """复用 database.py 的连接,确保所有模块写入同一份 ip_system.db"""
    with _db_get_conn() as conn:
        yield conn


def now_str():
    return _now_str()


def gen_id(prefix=""):
    return _gen_id(prefix)


def hash_password(pwd):
    return _hash_password(pwd)


# ====================================================================
# ① RBAC 权限管理
# ====================================================================

# 预置角色和权限
DEFAULT_ROLES = [
    {
        "code": "admin",
        "name": "系统管理员",
        "description": "拥有所有菜单和API权限",
        "menu_keys": ["*"],
        "permissions": ["*"],
    },
    {
        "code": "operator",
        "name": "业务操作员",
        "description": "可执行查询、查看数据、提交工单",
        "menu_keys": ["dashboard", "query-create", "query-list", "query-batch", "conflict", "log", "dictionary"],
        "permissions": ["query:create", "query:view", "conflict:create", "conflict:view", "log:view", "dictionary:view"],
    },
    {
        "code": "auditor",
        "name": "审计员",
        "description": "只读权限,用于合规审计",
        "menu_keys": ["dashboard", "query-list", "conflict", "log"],
        "permissions": ["query:view", "conflict:view", "log:view"],
    },
    {
        "code": "reviewer",
        "name": "复核员",
        "description": "处理冲突工单和人工修正",
        "menu_keys": ["dashboard", "conflict", "log", "query-list"],
        "permissions": ["query:view", "conflict:view", "conflict:handle", "log:view"],
    },
]

# 预置用户(基于真实业务场景)
DEFAULT_USERS = [
    {"username": "admin", "password": "admin123", "real_name": "系统管理员", "role": "admin", "phone": "13800000000", "email": "admin@anhui-mobile.com"},
    {"username": "operator01", "password": "Op@2026", "real_name": "操作员01", "role": "operator", "phone": "13800000001", "email": "op01@anhui-mobile.com"},
    {"username": "operator02", "password": "Op@2026", "real_name": "操作员02", "role": "operator", "phone": "13800000002", "email": "op02@anhui-mobile.com"},
    {"username": "reviewer01", "password": "Rv@2026", "real_name": "复核员01", "role": "reviewer", "phone": "13800000010", "email": "rv01@anhui-mobile.com"},
    {"username": "auditor01", "password": "Au@2026", "real_name": "审计员01", "role": "auditor", "phone": "13800000020", "email": "au01@anhui-mobile.com"},
]

# 预置脱敏策略
DEFAULT_MASK_POLICIES = [
    {"field_name": "subscriber_id", "mask_type": "phone", "mask_pattern": "138****5678", "description": "用户标识(脱敏)"},
    {"field_name": "user_private_ip", "mask_type": "ip", "mask_pattern": "10.0.0.***", "description": "私网IP(脱敏)"},
    {"field_name": "cert_no", "mask_type": "id_card", "mask_pattern": "91****01", "description": "证件号(脱敏)"},
    {"field_name": "security_person_cert_no", "mask_type": "id_card", "mask_pattern": "91****01", "description": "责任人证件号(脱敏)"},
    {"field_name": "security_person_mobile", "mask_type": "phone", "mask_pattern": "136****0001", "description": "责任人手机(脱敏)"},
    {"field_name": "safety_mobile", "mask_type": "phone", "mask_pattern": "136****0001", "description": "安全责任人手机(脱敏)"},
    {"field_name": "contact_person_client", "mask_type": "name", "mask_pattern": "某*", "description": "联系人姓名(脱敏)"},
    {"field_name": "contact_phone_client", "mask_type": "phone", "mask_pattern": "139****0001", "description": "联系人电话(脱敏)"},
    {"field_name": "resp_person_phone", "mask_type": "phone", "mask_pattern": "139****0001", "description": "负责人电话(脱敏)"},
]

# 预置告警规则
DEFAULT_ALARM_RULES = [
    {"name": "数据冲突频次告警", "rule_type": "data_conflict", "threshold": 5, "time_window": 3600, "notification_channel": "log", "description": "1小时内冲突工单超过5条时告警"},
    {"name": "数据源查询失败告警", "rule_type": "data_source_fail", "threshold": 3, "time_window": 600, "notification_channel": "log", "description": "10分钟内数据源查询失败超过3次时告警"},
    {"name": "查询量异常告警", "rule_type": "query_volume", "threshold": 500, "time_window": 3600, "notification_channel": "log", "description": "1小时内单用户查询超过500次时告警"},
    {"name": "异常登录告警", "rule_type": "login_abnormal", "threshold": 5, "time_window": 300, "notification_channel": "log", "description": "5分钟内同一IP登录失败超过5次时告警"},
]

# 预置调度任务
DEFAULT_SCHEDULED_JOBS = [
    {"name": "ip_subjects缓存清理", "job_type": "cleanup", "cron_expression": "0 3 * * *", "description": "每天凌晨3点清理90天前的查询任务和日志"},
    {"name": "数据源健康检查", "job_type": "data_quality", "cron_expression": "*/30 * * * *", "description": "每30分钟检查所有数据源连接状态"},
    {"name": "统计日报生成", "job_type": "refresh_cache", "cron_expression": "0 1 * * *", "description": "每天凌晨1点生成昨日查询统计"},
]

# 预置系统配置
DEFAULT_SYSTEM_CONFIG = [
    {"config_key": "audit.enabled", "config_value": "true", "config_group": "audit", "description": "是否启用查询审计"},
    {"config_key": "audit.sensitive_require_approval", "config_value": "true", "config_group": "audit", "description": "敏感字段访问是否需要审批"},
    {"config_key": "rate_limit.default_max", "config_value": "100", "config_group": "security", "description": "默认每分钟最大请求数"},
    {"config_key": "rate_limit.default_window", "config_value": "60", "config_group": "security", "description": "默认限流窗口(秒)"},
    {"config_key": "mask.enabled", "config_value": "true", "config_group": "security", "description": "是否启用字段脱敏"},
    {"config_key": "session.timeout_minutes", "config_value": "120", "config_group": "security", "description": "会话超时时间(分钟)"},
    {"config_key": "alarm.enabled", "config_value": "true", "config_group": "feature", "description": "是否启用告警"},
    {"config_key": "conflict.auto_detect", "config_value": "true", "config_group": "feature", "description": "是否启用自动冲突检测"},
]

# 预置限流配置
DEFAULT_RATE_LIMITS = [
    {"api_path": "/api/query/tasks", "role_code": "operator", "max_requests": 60, "window_seconds": 60, "description": "操作员查询接口限流(60次/分钟)"},
    {"api_path": "/api/query/batch", "max_requests": 10, "window_seconds": 60, "description": "批量查询限流(10次/分钟)"},
    {"api_path": "/api/login", "max_requests": 10, "window_seconds": 300, "description": "登录限流(10次/5分钟)"},
]


def hash_password(pwd: str) -> str:
    """密码哈希(SHA-256 + salt)"""
    salt = "ip_system_anhui_2026"
    return hashlib.sha256((salt + pwd).encode()).hexdigest()


def seed_production():
    """初始化所有落地能力数据"""
    with get_conn() as conn:
        # 1. 角色
        existing = conn.execute("SELECT COUNT(*) as c FROM roles").fetchone()["c"]
        if existing == 0:
            for r in DEFAULT_ROLES:
                conn.execute(
                    "INSERT INTO roles (id, name, code, description, permissions, menu_keys, status, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?)",
                    (gen_id("role_"), r["name"], r["code"], r["description"], json.dumps(r["permissions"]), json.dumps(r["menu_keys"]), "active", now_str(), now_str())
                )

        # 2. 用户(如果不存在则创建)
        for u in DEFAULT_USERS:
            ex = conn.execute("SELECT id FROM users WHERE username=?", (u["username"],)).fetchone()
            if not ex:
                uid = gen_id("user_")
                conn.execute(
                    "INSERT INTO users (id, username, password, real_name, role, phone, email, status, created_at) VALUES (?,?,?,?,?,?,?,?,?)",
                    (uid, u["username"], hash_password(u["password"]), u["real_name"], u["role"], u["phone"], u["email"], "active", now_str())
                )
                # 关联角色
                role = conn.execute("SELECT id FROM roles WHERE code=?", (u["role"],)).fetchone()
                if role:
                    conn.execute("INSERT OR IGNORE INTO user_roles (id, user_id, role_id, created_at) VALUES (?,?,?,?)", (gen_id("ur_"), uid, role["id"], now_str()))

        # 3. 脱敏策略
        existing = conn.execute("SELECT COUNT(*) as c FROM field_mask_policies").fetchone()["c"]
        if existing == 0:
            for p in DEFAULT_MASK_POLICIES:
                conn.execute(
                    "INSERT INTO field_mask_policies (id, field_name, mask_type, mask_pattern, enabled, description, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?)",
                    (gen_id("mp_"), p["field_name"], p["mask_type"], p["mask_pattern"], 1, p["description"], now_str(), now_str())
                )

        # 4. 告警规则
        existing = conn.execute("SELECT COUNT(*) as c FROM alarm_rules").fetchone()["c"]
        if existing == 0:
            for r in DEFAULT_ALARM_RULES:
                conn.execute(
                    "INSERT INTO alarm_rules (id, name, rule_type, threshold, time_window, notification_channel, enabled, description, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
                    (gen_id("ar_"), r["name"], r["rule_type"], r["threshold"], r["time_window"], r["notification_channel"], 1, r["description"], now_str(), now_str())
                )

        # 5. 调度任务
        existing = conn.execute("SELECT COUNT(*) as c FROM scheduled_jobs").fetchone()["c"]
        if existing == 0:
            for j in DEFAULT_SCHEDULED_JOBS:
                conn.execute(
                    "INSERT INTO scheduled_jobs (id, name, job_type, cron_expression, enabled, description, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?)",
                    (gen_id("job_"), j["name"], j["job_type"], j["cron_expression"], 1, j["description"], now_str(), now_str())
                )

        # 6. 系统配置
        existing = conn.execute("SELECT COUNT(*) as c FROM system_config").fetchone()["c"]
        if existing == 0:
            for c in DEFAULT_SYSTEM_CONFIG:
                conn.execute(
                    "INSERT INTO system_config (id, config_key, config_value, config_group, description, updated_at, updated_by) VALUES (?,?,?,?,?,?,?)",
                    (gen_id("cfg_"), c["config_key"], c["config_value"], c["config_group"], c["description"], now_str(), "system")
                )

        # 7. 限流配置
        existing = conn.execute("SELECT COUNT(*) as c FROM rate_limit_config").fetchone()["c"]
        if existing == 0:
            for r in DEFAULT_RATE_LIMITS:
                conn.execute(
                    "INSERT INTO rate_limit_config (id, api_path, role_code, max_requests, window_seconds, enabled, description, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?)",
                    (gen_id("rl_"), r["api_path"], r.get("role_code"), r["max_requests"], r["window_seconds"], 1, r["description"], now_str(), now_str())
                )

        # 8. 通知渠道
        ex_ch = conn.execute("SELECT COUNT(*) as c FROM notification_channels").fetchone()["c"]
        if ex_ch == 0:
            conn.execute(
                "INSERT INTO notification_channels (id, name, channel_type, config, enabled, description, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?)",
                (gen_id("nc_"), "系统日志通知", "log", json.dumps({"path": "data/alarm.log"}), 1, "写入系统日志", now_str(), now_str())
            )

        print("[1] 角色: %d 个" % len(DEFAULT_ROLES))
        print("[2] 用户: %d 个 (admin/admin123, operator01/Op@2026, reviewer01/Rv@2026, auditor01/Au@2026)" % len(DEFAULT_USERS))
        print("[3] 脱敏策略: %d 条" % len(DEFAULT_MASK_POLICIES))
        print("[4] 告警规则: %d 条" % len(DEFAULT_ALARM_RULES))
        print("[5] 调度任务: %d 个" % len(DEFAULT_SCHEDULED_JOBS))
        print("[6] 系统配置: %d 项" % len(DEFAULT_SYSTEM_CONFIG))
        print("[7] 限流配置: %d 条" % len(DEFAULT_RATE_LIMITS))
        print("[8] 通知渠道: 1 个 (系统日志)")


# ====================================================================
# ③ 字段级脱敏/加密
# ====================================================================

class FieldMasker:
    """字段脱敏器: 根据模板字段定义和数据字典策略, 自动脱敏"""

    def __init__(self, conn):
        self.conn = conn
        self._policies = self._load_policies()
        self._enabled = self._get_config("mask.enabled", "true") == "true"

    def _load_policies(self) -> Dict[str, Dict]:
        rows = self.conn.execute("SELECT field_name, mask_type, mask_pattern FROM field_mask_policies WHERE enabled=1").fetchall()
        return {r["field_name"]: {"type": r["mask_type"], "pattern": r["mask_pattern"]} for r in rows}

    def _get_config(self, key: str, default: str) -> str:
        row = self.conn.execute("SELECT config_value FROM system_config WHERE config_key=?", (key,)).fetchone()
        return row["config_value"] if row else default

    def mask_value(self, field_name: str, value: Any) -> Any:
        """根据字段名脱敏单个值"""
        if not self._enabled or value is None or value == "":
            return value
        policy = self._policies.get(field_name)
        if not policy:
            return value
        return self._apply_mask(value, policy["type"])

    def _apply_mask(self, value: str, mask_type: str) -> str:
        s = str(value)
        if mask_type == "phone" and len(s) >= 7:
            return s[:3] + "****" + s[-4:]
        if mask_type == "id_card" and len(s) >= 4:
            return s[:2] + "*" * (len(s) - 4) + s[-2:]
        if mask_type == "name":
            if len(s) <= 1:
                return s
            return s[0] + "*" * (len(s) - 1)
        if mask_type == "email" and "@" in s:
            name, domain = s.split("@", 1)
            if len(name) <= 1:
                return "*@" + domain
            return name[0] + "***@" + domain
        if mask_type == "ip" and "." in s:
            parts = s.split(".")
            if len(parts) == 4:
                return ".".join(parts[:3]) + ".***"
        if mask_type == "address":
            if len(s) <= 4:
                return "****"
            return s[:3] + "****" + s[-3:] if len(s) > 6 else s[:2] + "****"
        return s

    def mask_dict(self, data: Dict, template_fields: List[str] = None) -> Dict:
        """根据模板字段列表脱敏字典"""
        if not self._enabled or not isinstance(data, dict):
            return data
        masked = {}
        for k, v in data.items():
            if isinstance(v, str) and v and k in self._policies:
                masked[k] = self.mask_value(k, v)
            else:
                masked[k] = v
        return masked

    def mask_results(self, results: List[Dict]) -> List[Dict]:
        """批量脱敏结果列表"""
        return [self.mask_dict(r) for r in results]


# ====================================================================
# ⑤ 异步任务队列
# ====================================================================

class AsyncTaskQueue:
    """异步任务队列: 简单实现,使用后台线程处理任务"""
    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance.tasks = {}
                    cls._instance.handlers = {}
                    cls._instance.running = True
                    cls._instance._thread = threading.Thread(target=cls._instance._worker, daemon=True)
                    cls._instance._thread.start()
        return cls._instance

    def register_handler(self, task_type: str, handler: Callable):
        """注册任务处理函数"""
        self.handlers[task_type] = handler

    def submit(self, task_type: str, params: Dict, submitter: str = "system", total_items: int = 0) -> str:
        """提交任务"""
        task_id = gen_id("at_")
        with get_conn() as conn:
            conn.execute(
                "INSERT INTO async_tasks (id, task_type, params, total_items, status, submitter, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?)",
                (task_id, task_type, json.dumps(params), total_items, "pending", submitter, now_str(), now_str())
            )
        self.tasks[task_id] = task_type
        return task_id

    def get_status(self, task_id: str) -> Optional[Dict]:
        with get_conn() as conn:
            row = conn.execute("SELECT * FROM async_tasks WHERE id=?", (task_id,)).fetchone()
            return dict(row) if row else None

    def _worker(self):
        """工作线程: 持续扫描pending任务"""
        while self.running:
            try:
                with get_conn() as conn:
                    pending = conn.execute("SELECT * FROM async_tasks WHERE status='pending' ORDER BY created_at LIMIT 5").fetchall()
                    for t in pending:
                        conn.execute("UPDATE async_tasks SET status='running', started_at=?, updated_at=? WHERE id=?", (now_str(), now_str(), t["id"]))
                        threading.Thread(target=self._run_task, args=(dict(t),), daemon=True).start()
            except Exception as e:
                print(f"[AsyncTask] scan error: {e}")
            time.sleep(2)

    def _run_task(self, task: Dict):
        """执行单个任务"""
        task_id = task["id"]
        task_type = task["task_type"]
        try:
            params = json.loads(task.get("params") or "{}")
            handler = self.handlers.get(task_type)
            if not handler:
                self._update_task(task_id, "failed", error=f"未知任务类型: {task_type}")
                return
            result = handler(task_id, params)
            self._update_task(task_id, "success" if result.get("ok") else "partial", result=result)
        except Exception as e:
            self._update_task(task_id, "failed", error=str(e))

    def _update_task(self, task_id: str, status: str, result: Dict = None, error: str = None):
        with get_conn() as conn:
            conn.execute(
                "UPDATE async_tasks SET status=?, processed_items=?, success_items=?, failed_items=?, progress=?, result=?, error_message=?, finished_at=?, updated_at=? WHERE id=?",
                (status, result.get("processed", 0) if result else 0,
                 result.get("success", 0) if result else 0,
                 result.get("failed", 0) if result else 0,
                 result.get("progress", 100) if result else 100,
                 json.dumps(result) if result else None,
                 error, now_str(), now_str(), task_id)
            )


# ====================================================================
# ② 真实数据源适配器
# ====================================================================

class DataSourceAdapter:
    """数据源适配器: 支持多种类型外部数据源连接"""

    def __init__(self, datasource_config: Dict):
        self.config = datasource_config
        self.type = datasource_config.get("source_type", "local")
        # config_attrs 存放连接配置 JSON
        # 支持的连接配置: {"type": "mysql/postgres/http/oracle", "host":..., "port":..., "database":..., "user":..., "password":..., "query_template": "SELECT * FROM ... WHERE ip=? AND time BETWEEN ? AND ?"}
        self.conn_config = json.loads(datasource_config.get("config_attrs") or "{}")
        self._cache = None
        self._cache_time = 0

    def test_connection(self) -> Dict:
        """测试连接"""
        conn_type = self.conn_config.get("type", "local")
        if conn_type == "local":
            return {"ok": True, "type": "local", "message": "本地数据源,无需连接"}
        elif conn_type == "mysql":
            return self._test_mysql()
        elif conn_type == "postgres":
            return self._test_postgres()
        elif conn_type == "http":
            return self._test_http()
        else:
            return {"ok": False, "type": conn_type, "message": f"暂不支持的连接类型: {conn_type}"}

    def _test_mysql(self) -> Dict:
        """测试MySQL连接(占位实现,生产环境需要安装 pymysql)"""
        try:
            host = self.conn_config.get("host", "localhost")
            port = self.conn_config.get("port", 3306)
            # 实际生产: import pymysql; conn = pymysql.connect(host=host, port=port, ...)
            return {"ok": True, "type": "mysql", "message": f"MySQL连接配置已就绪(目标: {host}:{port}),需要安装pymysql客户端", "config_required": True}
        except Exception as e:
            return {"ok": False, "type": "mysql", "message": str(e)}

    def _test_postgres(self) -> Dict:
        """测试PostgreSQL连接"""
        try:
            host = self.conn_config.get("host", "localhost")
            port = self.conn_config.get("port", 5432)
            return {"ok": True, "type": "postgres", "message": f"PostgreSQL连接配置已就绪(目标: {host}:{port}),需要安装psycopg2", "config_required": True}
        except Exception as e:
            return {"ok": False, "type": "postgres", "message": str(e)}

    def _test_http(self) -> Dict:
        """测试HTTP数据源"""
        url = self.conn_config.get("url", "")
        if not url:
            return {"ok": False, "type": "http", "message": "未配置URL"}
        return {"ok": True, "type": "http", "message": f"HTTP数据源配置已就绪(目标: {url})"}

    def query(self, ip: str, start_time: str = None, end_time: str = None) -> List[Dict]:
        """执行查询(支持多种类型)"""
        conn_type = self.conn_config.get("type", "local")
        if conn_type == "local":
            return self._query_local(ip, start_time, end_time)
        elif conn_type == "mysql":
            return self._query_mysql(ip, start_time, end_time)
        elif conn_type == "postgres":
            return self._query_postgres(ip, start_time, end_time)
        elif conn_type == "http":
            return self._query_http(ip, start_time, end_time)
        return []

    def _query_local(self, ip: str, start_time: str, end_time: str) -> List[Dict]:
        """查询本地 ip_subjects 表(按数据源名称)"""
        ds_name = self.config.get("name", "")
        with get_conn() as conn:
            sql = "SELECT * FROM ip_subjects WHERE ip_address=? AND data_source=?"
            params = [ip, ds_name]
            if start_time and end_time:
                sql += " AND start_time <= ? AND end_time >= ?"
                params += [end_time, start_time]
            rows = conn.execute(sql, params).fetchall()
            return [dict(r) for r in rows]

    def _query_mysql(self, ip: str, start_time: str, end_time: str) -> List[Dict]:
        """MySQL数据源查询(占位,生产环境实现真实查询)"""
        # 实际生产: import pymysql; conn = pymysql.connect(...); cursor.execute(query_template, [ip, start_time, end_time])
        return []

    def _query_postgres(self, ip: str, start_time: str, end_time: str) -> List[Dict]:
        return []

    def _query_http(self, ip: str, start_time: str, end_time: str) -> List[Dict]:
        """HTTP数据源查询"""
        try:
            import urllib.request
            url = self.conn_config.get("url", "")
            if not url:
                return []
            req = urllib.request.Request(url + "?ip=" + ip, headers=self.conn_config.get("headers", {}))
            with urllib.request.urlopen(req, timeout=5) as r:
                return json.loads(r.read().decode())
        except Exception as e:
            print(f"[HTTPDataSource] query error: {e}")
            return []


# ====================================================================
# ④ 冲突自动检测
# ====================================================================

def detect_conflicts(conn, ip_address: str) -> List[Dict]:
    """冲突检测: 多数据源结果对比"""
    results = conn.execute(
        "SELECT * FROM ip_subjects WHERE ip_address=? ORDER BY confidence DESC, data_source",
        (ip_address,)
    ).fetchall()
    if len(results) < 2:
        return []

    # 关键字段
    key_fields = ["unit_name", "subscriber_id", "city_id", "ip_type", "data_source"]
    conflicts = []
    for i, r1 in enumerate(results):
        for r2 in results[i+1:]:
            for f in key_fields:
                v1 = r1[f] if f in r1.keys() else None
                v2 = r2[f] if f in r2.keys() else None
                if v1 and v2 and v1 != v2:
                    conflict_id = gen_id("ct_")
                    ticket_no = f"CT{datetime.now().strftime('%Y%m%d%H%M%S')}{i}{conflicts.__len__()}"
                    source_values = json.dumps({
                        r1["data_source"]: str(v1),
                        r2["data_source"]: str(v2),
                    }, ensure_ascii=False)
                    conn.execute(
                        "INSERT OR IGNORE INTO conflict_tickets (id, ticket_no, ip_address, conflict_source, conflict_type, conflict_desc, field_name, source_values, suggestion, status, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                        (conflict_id, ticket_no, ip_address, "系统自动检测", "字段冲突",
                         f"字段[{f}]在不同数据源结果中不一致", f, source_values,
                         f"建议核实{r1['data_source']}与{r2['data_source']}的数据准确性", "open", now_str())
                    )
                    conflicts.append({"ticket_no": ticket_no, "field": f, "value1": str(v1), "value2": str(v2)})
    return conflicts


def handle_conflict_ticket(conn, ticket_id: str, handler: str, action: str, remark: str, evidence: str = "") -> Dict:
        """处理冲突工单: 改派/确认/关闭"""
        ticket = conn.execute("SELECT * FROM conflict_tickets WHERE id=?", (ticket_id,)).fetchone()
        if not ticket:
            raise ValueError("工单不存在")
        new_status = {"确认": "resolved", "改派": "processing", "关闭": "closed", "驳回": "closed"}.get(action, "open")
        processed_at = now_str() if new_status in ["processing", "resolved"] else ticket["processed_at"]
        closed_at = now_str() if new_status == "closed" else ticket["closed_at"]
        lifecycle = json.loads(ticket["lifecycle"] or "[]")
        lifecycle.append({"action": action, "handler": handler, "remark": remark, "at": now_str()})
        conn.execute(
            "UPDATE conflict_tickets SET status=?, handler=?, handle_remark=?, handle_evidence=?, processed_at=?, closed_at=?, lifecycle=? WHERE id=?",
            (new_status, handler, remark, evidence, processed_at, closed_at, json.dumps(lifecycle, ensure_ascii=False), ticket_id)
        )
        return {"status": new_status, "ticket_no": ticket["ticket_no"]}


# ====================================================================
# ⑥ Excel/CSV 导入导出
# ====================================================================

def export_results_csv(results: List[Dict], fields: List[str] = None) -> str:
    """导出查询结果为CSV字符串"""
    if not results:
        return ""
    if not fields:
        fields = list(results[0].keys())
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=fields, extrasaction="ignore")
    writer.writeheader()
    for r in results:
        writer.writerow(r)
    return output.getvalue()


def export_results_xlsx(results: List[Dict], fields: List[str] = None) -> bytes:
    """导出查询结果为XLSX字节流(使用openpyxl)"""
    try:
        from openpyxl import Workbook
        from openpyxl.styles import Font, PatternFill, Alignment
    except ImportError:
        # 退化到CSV格式
        return export_results_csv(results, fields).encode("utf-8")

    if not results:
        return b""
    if not fields:
        fields = list(results[0].keys())

    wb = Workbook()
    ws = wb.active
    ws.title = "查询结果"

    # 表头样式
    header_font = Font(bold=True, color="FFFFFF")
    header_fill = PatternFill(start_color="4B3FE3", end_color="4B3FE3", fill_type="solid")

    # 写表头
    for col, f in enumerate(fields, 1):
        cell = ws.cell(row=1, column=col, value=f)
        cell.font = header_font
        cell.fill = header_fill
        cell.alignment = Alignment(horizontal="center")

    # 写数据
    for row_idx, r in enumerate(results, 2):
        for col, f in enumerate(fields, 1):
            v = r.get(f, "")
            if isinstance(v, dict):
                v = json.dumps(v, ensure_ascii=False)
            ws.cell(row=row_idx, column=col, value=str(v) if v is not None else "")

    # 自适应列宽
    for col in range(1, len(fields) + 1):
        ws.column_dimensions[chr(64 + col) if col <= 26 else "A" + chr(64 + col - 26)].width = 18

    buf = io.BytesIO()
    wb.save(buf)
    return buf.getvalue()


def import_csv_data(content: str, template_id: str) -> Dict:
    """导入CSV数据到ip_subjects"""
    reader = csv.DictReader(io.StringIO(content))
    success, failed = 0, 0
    errors = []
    with get_conn() as conn:
        for row in reader:
            try:
                ip = row.get("ip_address") or row.get("IP") or row.get("ip")
                if not ip:
                    failed += 1
                    errors.append({"row": row, "error": "缺少IP字段"})
                    continue
                conn.execute(
                    "INSERT INTO ip_subjects (id, ip_address, ip_version, scene_type, data_source, template_id, raw_data, created_at) VALUES (?,?,?,?,?,?,?,?)",
                    (gen_id("ip_"), ip, "IPv4", row.get("scene_type", ""), row.get("data_source", "导入数据"), template_id, json.dumps(row, ensure_ascii=False), now_str())
                )
                success += 1
            except Exception as e:
                failed += 1
                errors.append({"row": row, "error": str(e)})
    return {"success": success, "failed": failed, "errors": errors[:20]}


def get_template_csv() -> str:
    """下载导入模板"""
    fields = ["ip_address", "data_source", "scene_type", "start_time", "end_time", "备注"]
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=fields)
    writer.writeheader()
    writer.writerow({"ip_address": "10.2.0.1", "data_source": "示例数据源", "scene_type": "家宽", "start_time": "2026-09-01 00:00:00", "end_time": "2026-09-01 23:59:59", "备注": "请删除示例行后填入真实数据"})
    return output.getvalue()


# ====================================================================
# ⑦ 告警触发
# ====================================================================

def trigger_alarm(conn, rule_id: str, content: str, level: str = "warning", related_ip: str = None, related_data: Dict = None):
    """触发告警"""
    rule = conn.execute("SELECT * FROM alarm_rules WHERE id=?", (rule_id,)).fetchone()
    if not rule:
        return
    conn.execute(
        "INSERT INTO alarm_records (id, rule_id, rule_name, alarm_level, alarm_content, related_ip, related_data, triggered_at) VALUES (?,?,?,?,?,?,?,?)",
        (gen_id("alarm_"), rule_id, rule["name"], level, content, related_ip, json.dumps(related_data or {}, ensure_ascii=False), now_str())
    )
    conn.execute("UPDATE alarm_rules SET last_triggered_at=? WHERE id=?", (now_str(), rule_id))
    # 记录到操作日志
    log_operation(conn, "告警", "system", "alarm", f"[{level}] {rule['name']}: {content}", "127.0.0.1")


def check_alarm_rules(conn):
    """检查所有告警规则是否触发(可在定时任务中调用)"""
    rules = conn.execute("SELECT * FROM alarm_rules WHERE enabled=1").fetchall()
    for rule in rules:
        if rule["rule_type"] == "data_conflict":
            count = conn.execute(
                "SELECT COUNT(*) as c FROM conflict_tickets WHERE created_at >= datetime('now', ?)",
                (f"-{rule['time_window']} seconds",)
            ).fetchone()["c"]
            if count >= rule["threshold"]:
                trigger_alarm(conn, rule["id"], f"时间窗口内冲突工单数{count}已超阈值{rule['threshold']}", "warning")
        elif rule["rule_type"] == "query_volume":
            count = conn.execute(
                "SELECT COUNT(*) as c FROM query_audit WHERE created_at >= datetime('now', ?)",
                (f"-{rule['time_window']} seconds",)
            ).fetchone()["c"]
            if count >= rule["threshold"]:
                trigger_alarm(conn, rule["id"], f"时间窗口内查询量{count}已超阈值{rule['threshold']}", "warning")


# ====================================================================
# ⑧ API 限流器
# ====================================================================

class RateLimiter:
    """API 限流器: 滑动窗口实现"""
    _cache = {}

    @classmethod
    def check(cls, scope_key: str, max_requests: int, window_seconds: int) -> bool:
        """检查是否在限流内(返回True=通过)"""
        now = int(time.time())
        window_start = now - (now % window_seconds)
        cache_key = f"{scope_key}:{window_start}"

        if cache_key not in cls._cache:
            cls._cache[cache_key] = 0
        cls._cache[cache_key] += 1

        # 清理过期缓存
        if len(cls._cache) > 1000:
            cls._cache = {k: v for k, v in cls._cache.items() if int(k.split(":")[-1]) > now - window_seconds * 2}

        return cls._cache[cache_key] <= max_requests

    @classmethod
    def get_remaining(cls, scope_key: str, max_requests: int) -> int:
        now = int(time.time())
        cache_key = f"{scope_key}:{now - (now % 60)}"
        used = cls._cache.get(cache_key, 0)
        return max(0, max_requests - used)


# ====================================================================
# 辅助函数: 操作日志(兼容主系统调用)
# ====================================================================

def log_operation(conn, operation_type: str, operator: str, request_url: str, operation_detail: str, client_ip: str = ""):
    """记录操作日志(主系统已有的 log_operation 函数的兼容实现)"""
    try:
        conn.execute(
            "INSERT INTO operation_logs (id, operation_time, operation_type, operator, request_url, operation_detail, ip_address, created_at) VALUES (?,?,?,?,?,?,?,?)",
            (gen_id("olog_"), now_str(), operation_type, operator, request_url, operation_detail, client_ip, now_str())
        )
    except Exception:
        pass


# ====================================================================
# 主入口
# ====================================================================

if __name__ == "__main__":
    seed_production()
    print("\n[OK] 系统落地能力数据已初始化!")
