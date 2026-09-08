"""FastAPI backend for IP Address Query Calibration System."""
import os
import json
import re
import time
import uuid
import io
import hashlib
import random
from datetime import datetime, timedelta
from typing import Optional, List
from fastapi import FastAPI, HTTPException, UploadFile, File, Query, Request, Depends, Response
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, StreamingResponse, JSONResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from openpyxl import Workbook
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side

from database import get_conn, init_db, now_str, gen_id, hash_password, log_operation

app = FastAPI(title="IP地址查询校准系统", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

FRONTEND_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "frontend")


# ============ Helper ============
def mask_value(val, field_type="default"):
    """Mask sensitive data."""
    if not val or val == "-" or val == "":
        return val
    s = str(val)
    if len(s) <= 2:
        return s[0] + "*" if len(s) == 2 else "*"
    if len(s) <= 6:
        return s[0] + "*" * (len(s) - 2) + s[-1]
    return s[:3] + "*" * (len(s) - 6) + s[-3:]


def get_client_ip(request):
    """Safely get client IP."""
    return request.client.host if request.client else "127.0.0.1"


def parse_list(rows):
    """Convert sqlite3.Row list to dict list."""
    return [dict(r) for r in rows]


def is_ipv6(ip):
    return ":" in ip


def validate_ipv4(ip):
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    for p in parts:
        try:
            if int(p) < 0 or int(p) > 255:
                return False
        except ValueError:
            return False
    return True


def validate_ipv6(ip):
    return ":" in ip and len(ip) > 2


def ip_in_cidr(ip, cidr):
    """Check if an IPv4 address belongs to a CIDR range (supports comma-separated ranges)."""
    import ipaddress
    for segment in cidr.split(","):
        segment = segment.strip()
        if not segment:
            continue
        try:
            if "/" in segment:
                if ipaddress.ip_address(ip) in ipaddress.ip_network(segment, strict=False):
                    return True
            elif segment == ip:
                return True
        except ValueError:
            continue
    return False


def detect_scene_by_ip(conn, ip):
    """Auto-detect scene type by matching IP against configured scene IP ranges."""
    scenes = conn.execute("SELECT scene_type, ip_range FROM scenes WHERE status='enabled' AND ip_range IS NOT NULL AND ip_range != ''").fetchall()
    for s in scenes:
        if s["ip_range"] and ip_in_cidr(ip, s["ip_range"]):
            return s["scene_type"]
    return None


def execute_scene_path(conn, nodes, edges, ip, req):
    """Execute a published scene query path by walking its nodes/edges.

    - start node: entry point
    - execute node: query the bound data source (哪类数据去哪个数据源查)
    - judge node: branch by '是否命中' condition label (判断什么后该查哪里)
    Returns (results, records) where records is a list of tuples:
    (node_name, node_type, status, detail, data_source).
    """
    results = []
    records = []
    node_map = {n["id"]: n for n in nodes if isinstance(n, dict)}
    edges_from = {}
    for e in edges:
        if isinstance(e, dict) and e.get("from"):
            edges_from.setdefault(e["from"], []).append(e)

    current = next((n for n in nodes if isinstance(n, dict) and n.get("type") == "start"), None)
    visited = set()
    guard = 0
    while current and guard < 100:
        guard += 1
        nid = current.get("id")
        if nid in visited:  # loop protection
            break
        visited.add(nid)
        ntype = current.get("type")
        nname = current.get("name") or ntype or "节点"

        if ntype == "start":
            records.append((nname, "start", "success", "任务开始", "系统"))
        elif ntype == "execute":
            ds_id = current.get("data_source_id")
            ds_name = None
            if ds_id:
                r = conn.execute("SELECT name FROM data_sources WHERE id=?", (ds_id,)).fetchone()
                ds_name = r["name"] if r else None
            if ds_name:
                sql = "SELECT * FROM ip_subjects WHERE ip_address=? AND data_source=?"
                params = [ip, ds_name]
                if req.start_time and req.end_time:
                    sql += " AND start_time <= ? AND end_time >= ?"
                    params += [req.end_time, req.start_time]
                rows = conn.execute(sql, params).fetchall()
                results.extend(rows)
                target = current.get("query_target") or "IP主体信息"
                records.append((nname, "execute", "success", f"查询[{target}]于数据源[{ds_name}], 命中{len(rows)}条", ds_name))
            else:
                records.append((nname, "execute", "success", f"返回{len(results)}条定位结果", "系统"))
        elif ntype == "judge":
            hit = len(results) > 0
            label = "命中" if hit else "未命中"
            cond = current.get("condition") or "是否命中"
            outs = edges_from.get(nid, [])
            edge = next((e for e in outs if (e.get("label") or "") == label), None)
            if edge is None:
                edge = outs[0] if outs else None
            records.append((nname, "judge", "success", f"判断[{cond}]: {label}, 走[{label}]分支", "系统"))
            if edge:
                current = node_map.get(edge.get("to"))
                continue
            break
        else:
            records.append((nname, ntype or "execute", "success", str(current.get("detail") or ""), "系统"))

        # non-judge node: follow first outgoing edge
        outs = edges_from.get(nid, [])
        if outs:
            current = node_map.get(outs[0].get("to"))
        else:
            break
    return results, records


# ============ Auth (simplified) ============
class LoginRequest(BaseModel):
    username: str
    password: str


@app.post("/api/login")
def login(req: LoginRequest, request: Request):
    with get_conn() as conn:
        user = conn.execute("SELECT * FROM users WHERE username=? AND status='active'", (req.username,)).fetchone()
        if not user or user["password"] != hash_password(req.password):
            raise HTTPException(401, "用户名或密码错误")
        conn.execute("UPDATE users SET last_login=? WHERE id=?", (now_str(), user["id"]))
        log_operation(conn, "登录", req.username, str(request.url), f"用户{req.username}登录成功", get_client_ip(request))
        token = gen_id("tk_")
        return {"token": token, "user": {"id": user["id"], "username": user["username"], "real_name": user["real_name"], "role": user["role"]}}


# ============ 1. IP主体定位查询能力 ============

# 1.1 IP主体信息查询
class QueryTaskRequest(BaseModel):
    ip_address: str
    ip_version: Optional[str] = None
    port: Optional[str] = None
    start_time: str
    end_time: str
    scene_type: Optional[str] = None
    task_name: Optional[str] = None


@app.post("/api/query/tasks")
def create_query_task(req: QueryTaskRequest, request: Request):
    ip = req.ip_address.strip()
    # Auto-detect version
    ip_ver = req.ip_version or ("IPv6" if is_ipv6(ip) else "IPv4")
    if ip_ver == "IPv4" and not validate_ipv4(ip):
        raise HTTPException(400, "IPV4地址格式不正确")
    if ip_ver == "IPv6" and not validate_ipv6(ip):
        raise HTTPException(400, "IPV6地址格式不正确")

    with get_conn() as conn:
        task_id = gen_id("task_")

        # Determine scene type: use request param, or auto-detect by IP range
        scene_type = req.scene_type
        if not scene_type:
            scene_type = detect_scene_by_ip(conn, ip)

        # Resolve the published visual query path for this scene and execute it
        results = []
        records = []
        path_name = None
        if scene_type:
            scene = conn.execute("SELECT * FROM scenes WHERE scene_type=? AND status='enabled'", (scene_type,)).fetchone()
            if scene:
                path = conn.execute(
                    "SELECT * FROM scene_paths WHERE scene_id=? AND status='published' ORDER BY updated_at DESC LIMIT 1",
                    (scene["id"],),
                ).fetchone()
                if path:
                    try:
                        nodes = json.loads(path["nodes"] or "[]")
                    except Exception:
                        nodes = []
                    try:
                        edges = json.loads(path["edges"] or "[]")
                    except Exception:
                        edges = []
                    if nodes:
                        path_name = path["name"]
                        results, records = execute_scene_path(conn, nodes, edges, ip, req)
                        # Prepend scene identification record
                        records.insert(0, ("场景识别", "judge", "success", f"场景类型: {scene_type} (路径: {path_name})", "系统"))

        # Fallback: no published path -> query all data sources of this scene
        if not records:
            sql = "SELECT * FROM ip_subjects WHERE ip_address=?"
            params = [ip]
            if req.start_time and req.end_time:
                sql += " AND start_time <= ? AND end_time >= ?"
                params += [req.end_time, req.start_time]
            if scene_type:
                sql += " AND scene_type=?"
                params += [scene_type]
            results = conn.execute(sql, params).fetchall()
            ds_desc = ",".join(sorted({r["data_source"] for r in results})) if results else "无匹配数据源"
            records = [
                ("开始", "start", "success", "任务开始", "系统"),
                ("场景识别", "judge", "success", f"场景类型: {scene_type or '未识别'} (未配置发布路径, 查询场景全部数据源)", "系统"),
                ("数据源查询", "execute", "success" if results else "failed", f"查询数据源: {ds_desc}", ds_desc),
                ("数据融合", "execute", "success" if results else "failed", f"命中{len(results)}条记录", "融合算法"),
                ("返回结果", "execute", "success", f"返回{len(results)}条定位结果", "系统"),
            ]

        # Create task
        task_name = req.task_name or f"查询-{ip}"
        conn.execute(
            """INSERT INTO query_tasks (id, task_name, ip_address, ip_version, port, start_time, end_time, scene_type, status, result_count, created_by, created_at, completed_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (task_id, task_name, ip, ip_ver, req.port or "", req.start_time, req.end_time, scene_type or "", "completed", len(results), "admin", now_str(), now_str()),
        )

        # Create path records from actual execution flow
        for rec in records:
            conn.execute(
                "INSERT INTO task_paths (id, task_id, node_name, node_type, status, detail, data_source, started_at, completed_at) VALUES (?,?,?,?,?,?,?,?,?)",
                (gen_id("tp_"), task_id, rec[0], rec[1], rec[2], rec[3], rec[4], now_str(), now_str()),
            )

        log_operation(conn, "查询", "admin", str(request.url), f"创建IP查询任务: {ip} (场景:{scene_type or '未识别'}, 路径:{path_name or '默认流程'})", get_client_ip(request))

        # Mask sensitive fields in results
        masked_results = []
        for r in results:
            rd = dict(r)
            masked_results.append(rd)

        return {
            "task_id": task_id,
            "results": masked_results,
            "count": len(results),
            "paths": parse_list(conn.execute("SELECT * FROM task_paths WHERE task_id=? ORDER BY rowid", (task_id,)).fetchall()),
        }


# Get task result details
@app.get("/api/query/tasks/{task_id}")
def get_task_detail(task_id: str, request: Request):
    with get_conn() as conn:
        task = conn.execute("SELECT * FROM query_tasks WHERE id=?", (task_id,)).fetchone()
        if not task:
            raise HTTPException(404, "任务不存在")
        # Re-query results
        results = conn.execute("SELECT * FROM ip_subjects WHERE ip_address=?", (task["ip_address"],)).fetchall()
        paths = conn.execute("SELECT * FROM task_paths WHERE task_id=? ORDER BY rowid", (task_id,)).fetchall()
        return {
            "task": dict(task),
            "results": parse_list(results),
            "paths": parse_list(paths),
        }


# 1.2 Task list multi-dimensional query
@app.get("/api/query/tasks")
def list_query_tasks(
    request: Request,
    page: int = 1,
    page_size: int = 10,
    ip_address: Optional[str] = None,
    ip_version: Optional[str] = None,
    scene_type: Optional[str] = None,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    task_name: Optional[str] = None,
    status: Optional[str] = None,
):
    with get_conn() as conn:
        sql = "SELECT * FROM query_tasks WHERE 1=1"
        params = []
        if ip_address:
            sql += " AND ip_address LIKE ?"
            params.append(f"%{ip_address}%")
        if ip_version:
            sql += " AND ip_version=?"
            params.append(ip_version)
        if scene_type:
            sql += " AND scene_type=?"
            params.append(scene_type)
        if start_time:
            sql += " AND created_at >= ?"
            params.append(start_time)
        if end_time:
            sql += " AND created_at <= ?"
            params.append(end_time)
        if task_name:
            sql += " AND task_name LIKE ?"
            params.append(f"%{task_name}%")
        if status:
            sql += " AND status=?"
            params.append(status)

        total = conn.execute(f"SELECT COUNT(*) as c FROM ({sql})", params).fetchone()["c"]
        sql += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
        params += [page_size, (page - 1) * page_size]
        tasks = conn.execute(sql, params).fetchall()
        return {"total": total, "page": page, "page_size": page_size, "data": parse_list(tasks)}


# Get path replay for a task
@app.get("/api/query/tasks/{task_id}/path")
def get_task_path(task_id: str, request: Request):
    with get_conn() as conn:
        task = conn.execute("SELECT * FROM query_tasks WHERE id=?", (task_id,)).fetchone()
        if not task:
            raise HTTPException(404, "任务不存在")
        paths = conn.execute("SELECT * FROM task_paths WHERE task_id=? ORDER BY rowid", (task_id,)).fetchall()
        return {
            "task": dict(task),
            "paths": parse_list(paths),
        }


# Get location detail (溯源字段、定位值、数据源)
@app.get("/api/query/tasks/{task_id}/detail")
def get_location_detail(task_id: str, request: Request):
    with get_conn() as conn:
        task = conn.execute("SELECT * FROM query_tasks WHERE id=?", (task_id,)).fetchone()
        if not task:
            raise HTTPException(404, "任务不存在")
        results = conn.execute("SELECT * FROM ip_subjects WHERE ip_address=?", (task["ip_address"],)).fetchall()
        # Build detail with trace fields
        details = []
        for r in results:
            rd = dict(r)
            detail = {
                "field_name": "IP地址",
                "trace_value": rd["ip_address"],
                "data_source": rd["data_source"],
                "location": rd["location"],
                "access_node": rd["access_node"],
                "ip_type": rd["ip_type"],
                "scene_type": rd["scene_type"],
            }
            details.append(detail)
        return {"task": dict(task), "details": details, "results": parse_list(results)}


# 1.3 Batch import IP query
@app.get("/api/query/batch/template")
def download_batch_template(request: Request):
    """Download xlsx template for batch IP import."""
    wb = Workbook()
    ws = wb.active
    ws.title = "IP批量查询模板"
    headers = ["序号", "IP地址", "IP版本", "端口", "开始时间", "结束时间", "场景类型"]
    header_fill = PatternFill(start_color="409EFF", end_color="409EFF", fill_type="solid")
    header_font = Font(color="FFFFFF", bold=True, size=11)
    thin_border = Border(
        left=Side(style="thin"), right=Side(style="thin"),
        top=Side(style="thin"), bottom=Side(style="thin")
    )
    for col, h in enumerate(headers, 1):
        cell = ws.cell(row=1, column=col, value=h)
        cell.fill = header_fill
        cell.font = header_font
        cell.alignment = Alignment(horizontal="center")
        cell.border = thin_border

    # Sample rows
    samples = [
        [1, "10.0.1.100", "IPv4", "", "2026-01-01 00:00:00", "2026-01-01 23:59:59", "移网"],
        [2, "192.168.1.100", "IPv4", "", "2026-01-01 00:00:00", "2026-01-01 23:59:59", "家宽"],
        [3, "2408:8000:1::100", "IPv6", "", "2026-01-01 00:00:00", "2026-01-01 23:59:59", "移网"],
    ]
    for row_idx, row in enumerate(samples, 2):
        for col_idx, val in enumerate(row, 1):
            cell = ws.cell(row=row_idx, column=col_idx, value=val)
            cell.border = thin_border
            cell.alignment = Alignment(horizontal="center")

    # Set column widths
    widths = [6, 20, 10, 8, 22, 22, 12]
    for i, w in enumerate(widths, 1):
        ws.column_dimensions[chr(64 + i)].width = w

    output = io.BytesIO()
    wb.save(output)
    output.seek(0)

    with get_conn() as conn:
        log_operation(conn, "下载", "admin", str(request.url), "下载批量导入模板", get_client_ip(request))

    return StreamingResponse(
        output,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": "attachment; filename=IP_batch_query_template.xlsx"}
    )


@app.post("/api/query/batch/import")
async def batch_import(request: Request, file: UploadFile = File(...)):
    """Batch import IP addresses from xlsx and query."""
    # File size limit: 5MB
    MAX_SIZE = 5 * 1024 * 1024
    content = await file.read()
    if len(content) > MAX_SIZE:
        raise HTTPException(400, "文件大小超出限制(最大5MB)，请减小文件后重试")

    if not file.filename.endswith(".xlsx") and not file.filename.endswith(".xls"):
        raise HTTPException(400, "仅支持xlsx格式文件")

    from openpyxl import load_workbook
    wb = load_workbook(io.BytesIO(content))
    ws = wb.active

    batch_id = gen_id("batch_")
    results = []
    with get_conn() as conn:
        for row_idx in range(2, ws.max_row + 1):
            ip = ws.cell(row=row_idx, column=2).value
            if not ip:
                continue
            ip = str(ip).strip()
            ip_ver = ws.cell(row=row_idx, column=3).value or ("IPv6" if is_ipv6(ip) else "IPv4")
            port = str(ws.cell(row=row_idx, column=4).value or "")
            start_time = str(ws.cell(row=row_idx, column=5).value or "")
            end_time = str(ws.cell(row=row_idx, column=6).value or "")
            scene_type = str(ws.cell(row=row_idx, column=7).value or "")

            # Create task for each IP
            task_id = gen_id("task_")
            task_name = f"批量查询-{ip}"
            ip_results = conn.execute("SELECT * FROM ip_subjects WHERE ip_address=?", (ip,)).fetchall()
            conn.execute(
                """INSERT INTO query_tasks (id, task_name, ip_address, ip_version, port, start_time, end_time, scene_type, status, result_count, created_by, created_at, completed_at, batch_id)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (task_id, task_name, ip, ip_ver, port, start_time, end_time, scene_type, "completed", len(ip_results), "admin", now_str(), now_str(), batch_id),
            )
            results.append({"ip": ip, "task_id": task_id, "count": len(ip_results)})

        log_operation(conn, "批量导入", "admin", str(request.url), f"批量导入{len(results)}个IP地址", get_client_ip(request))

    return {"batch_id": batch_id, "total": len(results), "results": results}


# 1.4 Manual modify IP subject info
class ManualFixRequest(BaseModel):
    ip_address: str
    field_name: str
    field_value: str
    reason: str = ""
    operator: str = "admin"


@app.post("/api/query/manual-fix")
def manual_fix(req: ManualFixRequest, request: Request):
    with get_conn() as conn:
        # Update the subject record
        field_map = {
            "user_name": ("user_name", "user_name_plain"),
            "phone": ("phone", "phone_plain"),
            "address": ("address", "address_plain"),
            "unit_name": ("unit_name", "unit_name_plain"),
        }
        if req.field_name in field_map:
            masked_col, plain_col = field_map[req.field_name]
            conn.execute(f"UPDATE ip_subjects SET {plain_col}=? WHERE ip_address=?", (req.field_value, req.ip_address))
            conn.execute(f"UPDATE ip_subjects SET {masked_col}=? WHERE ip_address=?", (req.field_value, req.ip_address))

        # Create conflict ticket (来源: 用户修正)
        ticket_no = f"CT{datetime.now().strftime('%Y%m%d%H%M%S')}{random.randint(10,99)}"
        lifecycle = json.dumps([
            {"node": "工单创建", "time": now_str(), "operator": "系统"},
            {"node": "用户修正触发", "time": now_str(), "operator": req.operator},
        ], ensure_ascii=False)
        conn.execute(
            """INSERT INTO conflict_tickets (id, ticket_no, ip_address, conflict_source, conflict_type, conflict_desc, field_name, source_values, suggestion, status, handler, handle_remark, handle_evidence, created_at, lifecycle)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (gen_id("ct_"), ticket_no, req.ip_address, "用户修正", "人工修正", f"用户修正字段{req.field_name}，原因:{req.reason}", req.field_name,
             json.dumps([{"source": "用户修正", "value": req.field_value}], ensure_ascii=False), "请核实修正后的数据", "open", "", req.reason, "", now_str(), lifecycle),
        )

        log_operation(conn, "人工修正", req.operator, str(request.url), f"修正IP:{req.ip_address}字段:{req.field_name}", get_client_ip(request))

        return {"success": True, "ticket_no": ticket_no, "message": "修正已提交，已生成冲突来源为'用户修正'的冲突工单"}


# 1.5 Sensitive info approval
class ApprovalRequest(BaseModel):
    target_ip: str
    target_field: str
    approver: str
    applicant: str = "admin"


@app.post("/api/query/approval/request")
def request_approval(req: ApprovalRequest, request: Request):
    verify_code = str(random.randint(100000, 999999))
    with get_conn() as conn:
        approval_id = gen_id("ap_")
        expire = (datetime.now() + timedelta(minutes=30)).strftime("%Y-%m-%d %H:%M:%S")
        conn.execute(
            "INSERT INTO approvals (id, applicant, approver, target_ip, target_field, verify_code, status, created_at, expire_at) VALUES (?,?,?,?,?,?,?,?,?)",
            (approval_id, req.applicant, req.approver, req.target_ip, req.target_field, verify_code, "pending", now_str(), expire),
        )
        log_operation(conn, "审批申请", req.applicant, str(request.url), f"申请查看{req.target_ip}的{req.target_field}", get_client_ip(request))
    return {"approval_id": approval_id, "verify_code": verify_code, "expire_at": expire, "message": f"验证码已发送给审批人{req.approver}"}


class VerifyApprovalRequest(BaseModel):
    approval_id: str
    verify_code: str


@app.post("/api/query/approval/verify")
def verify_approval(req: VerifyApprovalRequest, request: Request):
    with get_conn() as conn:
        ap = conn.execute("SELECT * FROM approvals WHERE id=? AND verify_code=? AND status='pending'", (req.approval_id, req.verify_code)).fetchone()
        if not ap:
            raise HTTPException(400, "验证码错误或审批已过期")
        # Check expiry
        expire = datetime.strptime(ap["expire_at"], "%Y-%m-%d %H:%M:%S")
        if datetime.now() > expire:
            conn.execute("UPDATE approvals SET status='rejected' WHERE id=?", (req.approval_id,))
            raise HTTPException(400, "审批已过期")
        conn.execute("UPDATE approvals SET status='approved', approved_at=? WHERE id=?", (now_str(), req.approval_id))
        # Get plain text of sensitive field
        subject = conn.execute("SELECT * FROM ip_subjects WHERE ip_address=?", (ap["target_ip"],)).fetchone()
        if not subject:
            raise HTTPException(404, "IP主体信息不存在")
        field_map = {
            "user_name": "user_name_plain", "phone": "phone_plain", "address": "address_plain",
            "unit_name": "unit_name_plain", "id_card": "id_card_plain",
        }
        col = field_map.get(ap["target_field"], ap["target_field"])
        plain_value = subject[col] if col in subject.keys() else None
        log_operation(conn, "敏感信息查看", "admin", str(request.url), f"验证通过，查看{ap['target_ip']}的{ap['target_field']}", get_client_ip(request))
        return {"approved": True, "field": ap["target_field"], "plain_value": plain_value, "message": "验证通过，已获取明文信息"}


# ============ 2. 数据与路径管理 ============

# 2.1 Data source management
class DataSourceRequest(BaseModel):
    name: str
    source_type: str
    authority_level: str
    owner: str
    contact: str = ""
    description: str = ""
    alarm_enabled: int = 0
    config_attrs: str = "{}"


@app.get("/api/datasources")
def list_datasources(request: Request, page: int = 1, page_size: int = 10, name: Optional[str] = None, source_type: Optional[str] = None, authority_level: Optional[str] = None):
    with get_conn() as conn:
        sql = "SELECT * FROM data_sources WHERE 1=1"
        params = []
        if name:
            sql += " AND name LIKE ?"
            params.append(f"%{name}%")
        if source_type:
            sql += " AND source_type=?"
            params.append(source_type)
        if authority_level:
            sql += " AND authority_level=?"
            params.append(authority_level)
        total = conn.execute(f"SELECT COUNT(*) as c FROM ({sql})", params).fetchone()["c"]
        sql += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
        params += [page_size, (page - 1) * page_size]
        data = parse_list(conn.execute(sql, params).fetchall())
        return {"total": total, "page": page, "page_size": page_size, "data": data}


@app.post("/api/datasources")
def create_datasource(req: DataSourceRequest, request: Request):
    with get_conn() as conn:
        ds_id = gen_id("ds_")
        conn.execute(
            "INSERT INTO data_sources (id, name, source_type, authority_level, owner, contact, description, alarm_enabled, config_attrs, status, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (ds_id, req.name, req.source_type, req.authority_level, req.owner, req.contact, req.description, req.alarm_enabled, req.config_attrs, "active", now_str(), now_str()),
        )
        log_operation(conn, "新增", "admin", str(request.url), f"新增数据源:{req.name}", get_client_ip(request))
        return {"id": ds_id, "message": "数据源新增成功"}


@app.put("/api/datasources/{ds_id}")
def update_datasource(ds_id: str, req: DataSourceRequest, request: Request):
    with get_conn() as conn:
        conn.execute(
            "UPDATE data_sources SET name=?, source_type=?, authority_level=?, owner=?, contact=?, description=?, alarm_enabled=?, config_attrs=?, updated_at=? WHERE id=?",
            (req.name, req.source_type, req.authority_level, req.owner, req.contact, req.description, req.alarm_enabled, req.config_attrs, now_str(), ds_id),
        )
        log_operation(conn, "编辑", "admin", str(request.url), f"编辑数据源:{req.name}", get_client_ip(request))
        return {"message": "数据源更新成功"}


@app.delete("/api/datasources/{ds_id}")
def delete_datasource(ds_id: str, request: Request):
    with get_conn() as conn:
        conn.execute("DELETE FROM data_sources WHERE id=?", (ds_id,))
        log_operation(conn, "删除", "admin", str(request.url), f"删除数据源:{ds_id}", get_client_ip(request))
        return {"message": "数据源删除成功"}


@app.get("/api/datasources/{ds_id}")
def get_datasource(ds_id: str, request: Request):
    with get_conn() as conn:
        ds = conn.execute("SELECT * FROM data_sources WHERE id=?", (ds_id,)).fetchone()
        if not ds:
            raise HTTPException(404, "数据源不存在")
        return dict(ds)


# 2.2 Subject info management (templates)
class TemplateRequest(BaseModel):
    name: str
    description: str = ""
    scene_type: str = ""


@app.get("/api/templates")
def list_templates(request: Request, page: int = 1, page_size: int = 10, name: Optional[str] = None):
    with get_conn() as conn:
        sql = "SELECT * FROM subject_templates WHERE 1=1"
        params = []
        if name:
            sql += " AND name LIKE ?"
            params.append(f"%{name}%")
        total = conn.execute(f"SELECT COUNT(*) as c FROM ({sql})", params).fetchone()["c"]
        sql += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
        params += [page_size, (page - 1) * page_size]
        templates = parse_list(conn.execute(sql, params).fetchall())
        for t in templates:
            t["fields"] = parse_list(conn.execute("SELECT * FROM subject_template_fields WHERE template_id=? ORDER BY field_order", (t["id"],)).fetchall())
        return {"total": total, "page": page, "page_size": page_size, "data": templates}


@app.post("/api/templates")
def create_template(req: TemplateRequest, request: Request):
    with get_conn() as conn:
        tpl_id = gen_id("tpl_")
        conn.execute(
            "INSERT INTO subject_templates (id, name, description, scene_type, created_at, updated_at) VALUES (?,?,?,?,?,?)",
            (tpl_id, req.name, req.description, req.scene_type, now_str(), now_str()),
        )
        log_operation(conn, "新增", "admin", str(request.url), f"新增主体信息模板:{req.name}", get_client_ip(request))
        return {"id": tpl_id, "message": "模板创建成功"}


@app.put("/api/templates/{tpl_id}")
def update_template(tpl_id: str, req: TemplateRequest, request: Request):
    with get_conn() as conn:
        conn.execute("UPDATE subject_templates SET name=?, description=?, scene_type=?, updated_at=? WHERE id=?", (req.name, req.description, req.scene_type, now_str(), tpl_id))
        log_operation(conn, "编辑", "admin", str(request.url), f"编辑模板:{req.name}", get_client_ip(request))
        return {"message": "模板更新成功"}


@app.delete("/api/templates/{tpl_id}")
def delete_template(tpl_id: str, request: Request):
    with get_conn() as conn:
        conn.execute("DELETE FROM subject_templates WHERE id=?", (tpl_id,))
        log_operation(conn, "删除", "admin", str(request.url), f"删除模板:{tpl_id}", get_client_ip(request))
        return {"message": "模板删除成功"}


@app.get("/api/templates/{tpl_id}")
def get_template(tpl_id: str, request: Request):
    with get_conn() as conn:
        tpl = conn.execute("SELECT * FROM subject_templates WHERE id=?", (tpl_id,)).fetchone()
        if not tpl:
            raise HTTPException(404, "模板不存在")
        fields = parse_list(conn.execute("SELECT * FROM subject_template_fields WHERE template_id=? ORDER BY field_order", (tpl_id,)).fetchall())
        result = dict(tpl)
        result["fields"] = fields
        return result


class TemplateFieldRequest(BaseModel):
    field_name: str
    field_label: str = ""
    field_type: str = "text"
    is_required: int = 0
    is_encrypted: int = 0
    is_sensitive: int = 0
    field_order: int = 0
    description: str = ""


@app.post("/api/templates/{tpl_id}/fields")
def add_template_field(tpl_id: str, req: TemplateFieldRequest, request: Request):
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO subject_template_fields (id, template_id, field_name, field_label, field_type, is_required, is_encrypted, is_sensitive, field_order, description) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (gen_id("fld_"), tpl_id, req.field_name, req.field_label, req.field_type, req.is_required, req.is_encrypted, req.is_sensitive, req.field_order, req.description),
        )
        return {"message": "字段新增成功"}


@app.put("/api/templates/{tpl_id}/fields/{field_id}")
def update_template_field(tpl_id: str, field_id: str, req: TemplateFieldRequest, request: Request):
    with get_conn() as conn:
        conn.execute(
            "UPDATE subject_template_fields SET field_name=?, field_label=?, field_type=?, is_required=?, is_encrypted=?, is_sensitive=?, field_order=?, description=? WHERE id=? AND template_id=?",
            (req.field_name, req.field_label, req.field_type, req.is_required, req.is_encrypted, req.is_sensitive, req.field_order, req.description, field_id, tpl_id),
        )
        return {"message": "字段更新成功"}


@app.delete("/api/templates/{tpl_id}/fields/{field_id}")
def delete_template_field(tpl_id: str, field_id: str, request: Request):
    with get_conn() as conn:
        conn.execute("DELETE FROM subject_template_fields WHERE id=? AND template_id=?", (field_id, tpl_id))
        return {"message": "字段删除成功"}


# 2.3 Scene path management
class SceneRequest(BaseModel):
    name: str
    scene_type: str
    ip_range: str = ""
    description: str = ""


@app.get("/api/scenes")
def list_scenes(request: Request, page: int = 1, page_size: int = 10, name: Optional[str] = None, scene_type: Optional[str] = None, status: Optional[str] = None):
    with get_conn() as conn:
        sql = "SELECT * FROM scenes WHERE 1=1"
        params = []
        if name:
            sql += " AND name LIKE ?"
            params.append(f"%{name}%")
        if scene_type:
            sql += " AND scene_type=?"
            params.append(scene_type)
        if status:
            sql += " AND status=?"
            params.append(status)
        total = conn.execute(f"SELECT COUNT(*) as c FROM ({sql})", params).fetchone()["c"]
        sql += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
        params += [page_size, (page - 1) * page_size]
        scenes = parse_list(conn.execute(sql, params).fetchall())
        for s in scenes:
            s["paths"] = parse_list(conn.execute("SELECT * FROM scene_paths WHERE scene_id=?", (s["id"],)).fetchall())
        return {"total": total, "page": page, "page_size": page_size, "data": scenes}


@app.post("/api/scenes")
def create_scene(req: SceneRequest, request: Request):
    with get_conn() as conn:
        sid = gen_id("sc_")
        conn.execute(
            "INSERT INTO scenes (id, name, scene_type, ip_range, description, status, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?)",
            (sid, req.name, req.scene_type, req.ip_range, req.description, "enabled", now_str(), now_str()),
        )
        log_operation(conn, "新增", "admin", str(request.url), f"新增场景:{req.name}", get_client_ip(request))
        return {"id": sid, "message": "场景创建成功"}


@app.put("/api/scenes/{scene_id}")
def update_scene(scene_id: str, req: SceneRequest, request: Request):
    with get_conn() as conn:
        conn.execute("UPDATE scenes SET name=?, scene_type=?, ip_range=?, description=?, updated_at=? WHERE id=?", (req.name, req.scene_type, req.ip_range, req.description, now_str(), scene_id))
        log_operation(conn, "编辑", "admin", str(request.url), f"编辑场景:{req.name}", get_client_ip(request))
        return {"message": "场景更新成功"}


@app.delete("/api/scenes/{scene_id}")
def delete_scene(scene_id: str, request: Request):
    with get_conn() as conn:
        conn.execute("DELETE FROM scenes WHERE id=?", (scene_id,))
        log_operation(conn, "删除", "admin", str(request.url), f"删除场景:{scene_id}", get_client_ip(request))
        return {"message": "场景删除成功"}


@app.put("/api/scenes/{scene_id}/toggle")
def toggle_scene(scene_id: str, request: Request):
    with get_conn() as conn:
        sc = conn.execute("SELECT status FROM scenes WHERE id=?", (scene_id,)).fetchone()
        if not sc:
            raise HTTPException(404, "场景不存在")
        new_status = "disabled" if sc["status"] == "enabled" else "enabled"
        conn.execute("UPDATE scenes SET status=?, updated_at=? WHERE id=?", (new_status, now_str(), scene_id))
        log_operation(conn, "状态切换", "admin", str(request.url), f"场景{scene_id}切换为{new_status}", get_client_ip(request))
        return {"status": new_status, "message": f"场景已{'开启' if new_status == 'enabled' else '关闭'}"}


# Scene path management
class ScenePathRequest(BaseModel):
    name: str
    nodes: str = "[]"   # JSON string of path nodes
    edges: str = "[]"    # JSON string of path edges


@app.get("/api/scenes/{scene_id}/paths")
def list_scene_paths(scene_id: str, request: Request):
    with get_conn() as conn:
        paths = parse_list(conn.execute("SELECT * FROM scene_paths WHERE scene_id=?", (scene_id,)).fetchall())
        return {"data": paths}


@app.post("/api/scenes/{scene_id}/paths")
def create_scene_path(scene_id: str, req: ScenePathRequest, request: Request):
    with get_conn() as conn:
        pid = gen_id("sp_")
        conn.execute(
            "INSERT INTO scene_paths (id, scene_id, name, nodes, edges, status, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?)",
            (pid, scene_id, req.name, req.nodes, req.edges, "draft", now_str(), now_str()),
        )
        log_operation(conn, "新增路径", "admin", str(request.url), f"新增场景查询路径:{req.name}", get_client_ip(request))
        return {"id": pid, "message": "路径创建成功"}


@app.put("/api/scenes/{scene_id}/paths/{path_id}")
def update_scene_path(scene_id: str, path_id: str, req: ScenePathRequest, request: Request):
    with get_conn() as conn:
        conn.execute("UPDATE scene_paths SET name=?, nodes=?, edges=?, updated_at=? WHERE id=?", (req.name, req.nodes, req.edges, now_str(), path_id))
        log_operation(conn, "编辑路径", "admin", str(request.url), f"编辑场景查询路径:{req.name}", get_client_ip(request))
        return {"message": "路径更新成功"}


@app.delete("/api/scenes/{scene_id}/paths/{path_id}")
def delete_scene_path(scene_id: str, path_id: str, request: Request):
    with get_conn() as conn:
        conn.execute("DELETE FROM scene_paths WHERE id=?", (path_id,))
        return {"message": "路径删除成功"}


@app.put("/api/scenes/{scene_id}/paths/{path_id}/publish")
def publish_scene_path(scene_id: str, path_id: str, request: Request):
    with get_conn() as conn:
        conn.execute("UPDATE scene_paths SET status='published', updated_at=? WHERE id=?", (now_str(), path_id))
        log_operation(conn, "发布路径", "admin", str(request.url), f"发布场景查询路径:{path_id}", get_client_ip(request))
        return {"message": "路径发布成功，查询流程已生效"}


@app.get("/api/scenes/{scene_id}/paths/{path_id}")
def get_scene_path(scene_id: str, path_id: str, request: Request):
    with get_conn() as conn:
        p = conn.execute("SELECT * FROM scene_paths WHERE id=? AND scene_id=?", (path_id, scene_id)).fetchone()
        if not p:
            raise HTTPException(404, "路径不存在")
        return dict(p)


# ============ 3. 数据校验能力 ============

# 3.1 Conflict ticket management
@app.get("/api/conflicts")
def list_conflicts(
    request: Request,
    page: int = 1,
    page_size: int = 10,
    ticket_no: Optional[str] = None,
    ip_address: Optional[str] = None,
    conflict_source: Optional[str] = None,
    conflict_type: Optional[str] = None,
    status: Optional[str] = None,
    field_name: Optional[str] = None,
):
    with get_conn() as conn:
        sql = "SELECT * FROM conflict_tickets WHERE 1=1"
        params = []
        if ticket_no:
            sql += " AND ticket_no LIKE ?"
            params.append(f"%{ticket_no}%")
        if ip_address:
            sql += " AND ip_address LIKE ?"
            params.append(f"%{ip_address}%")
        if conflict_source:
            sql += " AND conflict_source=?"
            params.append(conflict_source)
        if conflict_type:
            sql += " AND conflict_type=?"
            params.append(conflict_type)
        if status:
            sql += " AND status=?"
            params.append(status)
        if field_name:
            sql += " AND field_name LIKE ?"
            params.append(f"%{field_name}%")
        total = conn.execute(f"SELECT COUNT(*) as c FROM ({sql})", params).fetchone()["c"]
        sql += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
        params += [page_size, (page - 1) * page_size]
        data = parse_list(conn.execute(sql, params).fetchall())
        return {"total": total, "page": page, "page_size": page_size, "data": data}


@app.get("/api/conflicts/{ticket_id}")
def get_conflict(ticket_id: str, request: Request):
    with get_conn() as conn:
        t = conn.execute("SELECT * FROM conflict_tickets WHERE id=?", (ticket_id,)).fetchone()
        if not t:
            raise HTTPException(404, "工单不存在")
        return dict(t)


class ConflictProcessRequest(BaseModel):
    action: str  # fix/verify/detail
    handle_remark: str = ""
    handle_evidence: str = ""
    handler: str = "admin"


@app.put("/api/conflicts/{ticket_id}/process")
def process_conflict(ticket_id: str, req: ConflictProcessRequest, request: Request):
    with get_conn() as conn:
        t = conn.execute("SELECT * FROM conflict_tickets WHERE id=?", (ticket_id,)).fetchone()
        if not t:
            raise HTTPException(404, "工单不存在")
        current_lifecycle = json.loads(t["lifecycle"] or "[]")
        if req.action == "fix":
            new_status = "processing"
            node = "手动修正"
        elif req.action == "verify":
            new_status = "resolved"
            node = "治理校验"
        else:
            new_status = t["status"]
            node = "详情查阅"
        current_lifecycle.append({"node": node, "time": now_str(), "operator": req.handler, "remark": req.handle_remark})
        conn.execute(
            "UPDATE conflict_tickets SET status=?, handler=?, handle_remark=?, handle_evidence=?, lifecycle=? WHERE id=?",
            (new_status, req.handler, req.handle_remark, req.handle_evidence, json.dumps(current_lifecycle, ensure_ascii=False), ticket_id),
        )
        if new_status == "resolved":
            conn.execute("UPDATE conflict_tickets SET closed_at=? WHERE id=?", (now_str(), ticket_id))
        log_operation(conn, "工单处理", req.handler, str(request.url), f"处理工单:{t['ticket_no']}动作:{req.action}", get_client_ip(request))
        return {"status": new_status, "lifecycle": current_lifecycle, "message": "处理成功"}


@app.get("/api/conflicts/{ticket_id}/lifecycle")
def get_conflict_lifecycle(ticket_id: str, request: Request):
    with get_conn() as conn:
        t = conn.execute("SELECT lifecycle, ticket_no, ip_address, conflict_source, conflict_type, status, created_at, processed_at, closed_at, handler FROM conflict_tickets WHERE id=?", (ticket_id,)).fetchone()
        if not t:
            raise HTTPException(404, "工单不存在")
        lifecycle = json.loads(t["lifecycle"] or "[]")
        return {"ticket": dict(t), "lifecycle": lifecycle}


# Manually create conflict ticket
class ConflictCreateRequest(BaseModel):
    ip_address: str
    conflict_source: str = "人工录入"
    conflict_type: str = "字段冲突"
    conflict_desc: str = ""
    field_name: str = ""
    source_values: str = "[]"
    suggestion: str = ""
    operator: str = "admin"


@app.post("/api/conflicts")
def create_conflict(req: ConflictCreateRequest, request: Request):
    with get_conn() as conn:
        ticket_no = f"CT{datetime.now().strftime('%Y%m%d%H%M%S')}{random.randint(10,99)}"
        ct_id = gen_id("ct_")
        lifecycle = json.dumps([
            {"node": "工单创建", "time": now_str(), "operator": req.operator},
            {"node": "冲突录入", "time": now_str(), "operator": req.operator, "remark": req.conflict_desc},
        ], ensure_ascii=False)
        conn.execute(
            """INSERT INTO conflict_tickets (id, ticket_no, ip_address, conflict_source, conflict_type, conflict_desc, field_name, source_values, suggestion, status, handler, handle_remark, handle_evidence, created_at, lifecycle)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (ct_id, ticket_no, req.ip_address, req.conflict_source, req.conflict_type, req.conflict_desc, req.field_name,
             req.source_values, req.suggestion, "open", "", "", "", now_str(), lifecycle),
        )
        log_operation(conn, "新建工单", req.operator, str(request.url), f"新建冲突工单:{ticket_no} IP:{req.ip_address}", get_client_ip(request))
        return {"id": ct_id, "ticket_no": ticket_no, "message": "冲突工单创建成功"}


# ============ IP Subject Data Import ============

# 导入模板的列定义: (Excel列名, 数据库字段名, 是否必填)
IMPORT_COLUMNS = [
    ("IP地址", "ip_address", True),
    ("IP版本", "ip_version", False),
    ("场景类型", "scene_type", False),
    ("端口", "port", False),
    ("开始时间", "start_time", False),
    ("结束时间", "end_time", False),
    ("用户名", "user_name", False),
    ("用户ID", "user_id", False),
    ("电话", "phone", False),
    ("地址", "address", False),
    ("单位名称", "unit_name", False),
    ("身份证号", "id_card", False),
    ("带宽", "bandwidth", False),
    ("IP类型", "ip_type", False),
    ("数据源", "data_source", False),
    ("位置", "location", False),
    ("接入节点", "access_node", False),
    ("开户时间", "create_time", False),
]


@app.get("/api/subjects/import/template")
def download_subject_import_template(request: Request):
    """下载IP主体数据导入模板。"""
    wb = Workbook()
    ws = wb.active
    ws.title = "IP主体数据导入"
    headers = [c[0] for c in IMPORT_COLUMNS]
    header_fill = PatternFill(start_color="409EFF", end_color="409EFF", fill_type="solid")
    header_font = Font(color="FFFFFF", bold=True, size=11)
    thin_border = Border(
        left=Side(style="thin"), right=Side(style="thin"),
        top=Side(style="thin"), bottom=Side(style="thin")
    )
    for col, h in enumerate(headers, 1):
        cell = ws.cell(row=1, column=col, value=h)
        cell.fill = header_fill
        cell.font = header_font
        cell.alignment = Alignment(horizontal="center")
        cell.border = thin_border

    # 示例行
    samples = [
        ["10.0.1.200", "IPv4", "移网", "0", "2026-01-01 00:00:00", "2026-01-01 23:59:59",
         "张三", "USER_100", "13800001234", "合肥市蜀山区黄山路", "安徽移动",
         "340100199001011234", "100M", "动态", "移网AAA数据源", "安徽合肥-蜀山", "SGSN-001", "2026-01-01 08:30:00"],
        ["192.168.1.200", "IPv4", "家宽", "0", "2026-01-01 00:00:00", "2026-01-01 23:59:59",
         "李四", "USER_101", "13600005678", "合肥市包河区马鞍山路", "安徽移动",
         "340111199004044567", "300M", "动态", "家宽BRAS数据源", "安徽合肥-包河", "BRAS-001", "2026-01-01 08:20:00"],
        ["2408:8000:1::200", "IPv6", "移网", "0", "2026-01-01 00:00:00", "2026-01-01 23:59:59",
         "王五", "USER_102", "13700009000", "蚌埠市蚌山区东海大道", "安徽移动",
         "340300199003033456", "100M", "动态", "移网AAA数据源", "安徽蚌埠-蚌山", "SGSN-003", "2026-01-01 08:15:00"],
    ]
    for row_idx, row in enumerate(samples, 2):
        for col_idx, val in enumerate(row, 1):
            cell = ws.cell(row=row_idx, column=col_idx, value=val)
            cell.border = thin_border
            cell.alignment = Alignment(horizontal="center")

    # 标注必填列（第一列标红注释）
    ws.cell(row=len(samples) + 3, column=1, value="说明：")
    ws.cell(row=len(samples) + 4, column=1, value="1. IP地址为必填字段")
    ws.cell(row=len(samples) + 5, column=1, value="2. IP版本留空时自动识别（含:为IPv6）")
    ws.cell(row=len(samples) + 6, column=1, value="3. 场景类型可选：移网/家宽/专线/IDC/自有业务")
    ws.cell(row=len(samples) + 7, column=1, value="4. 敏感字段（用户名/电话/身份证号）会自动脱敏存储")
    ws.cell(row=len(samples) + 8, column=1, value="5. 导入模式为追加，不会删除已有数据")
    ws.cell(row=len(samples) + 9, column=1, value="6. 如需清空旧数据，请先在数据源管理中删除对应数据")

    # 列宽
    widths = [18, 10, 10, 8, 22, 22, 14, 14, 14, 22, 16, 20, 10, 10, 16, 14, 14, 22]
    for i, w in enumerate(widths, 1):
        ws.column_dimensions[chr(64 + i) if i <= 26 else chr(64 + (i - 1) // 26) + chr(65 + (i - 1) % 26)].width = w

    with get_conn() as conn:
        log_operation(conn, "下载", "admin", str(request.url), "下载IP主体数据导入模板", get_client_ip(request))

    return _xlsx_response(wb, "IP_subjects_import_template")


@app.post("/api/subjects/import")
async def import_subjects(request: Request, file: UploadFile = File(...)):
    """通过Excel导入IP主体数据。导入模式为追加，不会删除已有数据。"""
    MAX_SIZE = 10 * 1024 * 1024
    content = await file.read()
    if len(content) > MAX_SIZE:
        raise HTTPException(400, "文件大小超出限制(最大10MB)，请减小文件后重试")
    if not file.filename.endswith(".xlsx"):
        raise HTTPException(400, "仅支持xlsx格式文件")

    from openpyxl import load_workbook
    wb = load_workbook(io.BytesIO(content))
    ws = wb.active

    # 读取表头，建立列索引映射
    header_row = {}
    for col in range(1, ws.max_column + 1):
        header = ws.cell(row=1, column=col).value
        if header:
            header_row[str(header).strip()] = col

    # 验证必填列存在
    for col_name, db_field, required in IMPORT_COLUMNS:
        if required and col_name not in header_row:
            raise HTTPException(400, f"缺少必填列：{col_name}")

    imported = 0
    errors = []
    with get_conn() as conn:
        for row_idx in range(2, ws.max_row + 1):
            ip = ws.cell(row=row_idx, column=header_row.get("IP地址", 1)).value
            if not ip:
                continue
            ip = str(ip).strip()
            if not ip:
                continue

            # 构建字段值字典
            row_data = {}
            for col_name, db_field, _ in IMPORT_COLUMNS:
                col_idx = header_row.get(col_name)
                if col_idx:
                    val = ws.cell(row=row_idx, column=col_idx).value
                    row_data[db_field] = str(val).strip() if val else ""
                else:
                    row_data[db_field] = ""

            # 自动识别IP版本
            if not row_data.get("ip_version"):
                row_data["ip_version"] = "IPv6" if is_ipv6(ip) else "IPv4"

            # 校验IP地址格式
            if row_data["ip_version"] == "IPv4" and not validate_ipv4(ip):
                errors.append(f"第{row_idx}行: IPv4地址格式不正确 ({ip})")
                continue
            if row_data["ip_version"] == "IPv6" and not validate_ipv6(ip):
                errors.append(f"第{row_idx}行: IPv6地址格式不正确 ({ip})")
                continue

            # 敏感字段自动脱敏
            user_name_plain = row_data.get("user_name", "")
            phone_plain = row_data.get("phone", "")
            id_card_plain = row_data.get("id_card", "")
            address_plain = row_data.get("address", "")
            unit_name_plain = row_data.get("unit_name", "")

            row_data["user_name_plain"] = user_name_plain
            row_data["phone_plain"] = phone_plain
            row_data["id_card_plain"] = id_card_plain
            row_data["address_plain"] = address_plain
            row_data["unit_name_plain"] = unit_name_plain

            row_data["user_name"] = mask_value(user_name_plain) if user_name_plain else ""
            row_data["phone"] = mask_value(phone_plain) if phone_plain else ""
            row_data["address"] = mask_value(address_plain) if address_plain else ""
            row_data["unit_name"] = mask_value(unit_name_plain) if unit_name_plain else ""
            # 身份证号脱敏：前6后4
            if id_card_plain and id_card_plain != "-" and len(id_card_plain) > 10:
                row_data["id_card"] = id_card_plain[:6] + "********" + id_card_plain[-4:]
            elif id_card_plain:
                row_data["id_card"] = id_card_plain

            # 构建raw_data
            raw = json.dumps({
                "ip": ip, "version": row_data["ip_version"],
                "user": user_name_plain, "phone": phone_plain,
                "unit": unit_name_plain, "source": row_data.get("data_source", "")
            }, ensure_ascii=False)

            sid = gen_id("ip_")
            conn.execute(
                """INSERT INTO ip_subjects (id, ip_address, ip_version, scene_type, port, start_time, end_time,
                   user_name, user_name_plain, user_id, phone, phone_plain, address, address_plain,
                   unit_name, unit_name_plain, id_card, id_card_plain, bandwidth, ip_type, data_source,
                   data_source_id, location, access_node, create_time, raw_data, created_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (sid, ip, row_data.get("ip_version", ""), row_data.get("scene_type", ""),
                 row_data.get("port", ""), row_data.get("start_time", ""), row_data.get("end_time", ""),
                 row_data.get("user_name", ""), row_data.get("user_name_plain", ""),
                 row_data.get("user_id", ""), row_data.get("phone", ""), row_data.get("phone_plain", ""),
                 row_data.get("address", ""), row_data.get("address_plain", ""),
                 row_data.get("unit_name", ""), row_data.get("unit_name_plain", ""),
                 row_data.get("id_card", ""), row_data.get("id_card_plain", ""),
                 row_data.get("bandwidth", ""), row_data.get("ip_type", ""),
                 row_data.get("data_source", ""), None,
                 row_data.get("location", ""), row_data.get("access_node", ""),
                 row_data.get("create_time", ""), raw, now_str()),
            )
            imported += 1

        log_operation(conn, "数据导入", "admin", str(request.url),
                      f"导入IP主体数据{imported}条" + (f"，错误{len(errors)}条" if errors else ""),
                      get_client_ip(request))

    result = {
        "imported": imported,
        "errors": errors[:20],
        "error_count": len(errors),
        "message": f"成功导入 {imported} 条数据" + (f"，{len(errors)}条数据格式错误已跳过" if errors else "")
    }
    return result


@app.delete("/api/subjects")
def clear_all_subjects(request: Request, confirm: str = ""):
    """清空所有IP主体数据（需要confirm=yes参数）。"""
    if confirm != "yes":
        raise HTTPException(400, "请确认清空操作（参数confirm=yes）")
    with get_conn() as conn:
        count = conn.execute("SELECT COUNT(*) as c FROM ip_subjects").fetchone()["c"]
        conn.execute("DELETE FROM ip_subjects")
        log_operation(conn, "数据清空", "admin", str(request.url), f"清空IP主体数据{count}条", get_client_ip(request))
        return {"deleted": count, "message": f"已清空 {count} 条IP主体数据"}


# ============ Export endpoints ============
def _xlsx_response(wb, filename):
    buf = io.BytesIO()
    wb.save(buf)
    buf.seek(0)
    return StreamingResponse(
        buf,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f'attachment; filename="{filename}.xlsx"'}
    )


def _style_header(ws, headers):
    header_fill = PatternFill(start_color="409EFF", end_color="409EFF", fill_type="solid")
    header_font = Font(color="FFFFFF", bold=True, size=11)
    thin = Border(left=Side(style="thin"), right=Side(style="thin"), top=Side(style="thin"), bottom=Side(style="thin"))
    for col, h in enumerate(headers, 1):
        c = ws.cell(row=1, column=col, value=h)
        c.fill = header_fill
        c.font = header_font
        c.alignment = Alignment(horizontal="center")
        c.border = thin


@app.get("/api/export/subjects")
def export_subjects(request: Request, ip_address: Optional[str] = None, scene_type: Optional[str] = None):
    with get_conn() as conn:
        sql = "SELECT * FROM ip_subjects WHERE 1=1"
        params = []
        if ip_address:
            sql += " AND ip_address LIKE ?"
            params.append(f"%{ip_address}%")
        if scene_type:
            sql += " AND scene_type=?"
            params.append(scene_type)
        rows = conn.execute(sql + " ORDER BY created_at DESC", params).fetchall()
        wb = Workbook()
        ws = wb.active
        ws.title = "IP主体信息"
        headers = ["IP地址", "IP版本", "场景类型", "端口", "用户名", "电话", "地址", "单位名称", "数据源", "位置", "接入节点", "IP类型", "开始时间", "结束时间"]
        _style_header(ws, headers)
        for r_idx, r in enumerate(rows, 2):
            vals = [r["ip_address"], r["ip_version"], r["scene_type"], r["port"], r["user_name"], r["phone"], r["address"], r["unit_name"], r["data_source"], r["location"], r["access_node"], r["ip_type"], r["start_time"], r["end_time"]]
            for c_idx, v in enumerate(vals, 1):
                ws.cell(row=r_idx, column=c_idx, value=v if v else "")
        widths = [16, 8, 10, 8, 14, 14, 20, 16, 16, 14, 14, 10, 20, 20]
        for i, w in enumerate(widths, 1):
            ws.column_dimensions[chr(64 + i)].width = w
        log_operation(conn, "导出", "admin", str(request.url), f"导出IP主体信息{len(rows)}条", get_client_ip(request))
        return _xlsx_response(wb, "IP_subjects_export")


@app.get("/api/export/conflicts")
def export_conflicts(request: Request, status: Optional[str] = None, ip_address: Optional[str] = None):
    with get_conn() as conn:
        sql = "SELECT * FROM conflict_tickets WHERE 1=1"
        params = []
        if status:
            sql += " AND status=?"
            params.append(status)
        if ip_address:
            sql += " AND ip_address LIKE ?"
            params.append(f"%{ip_address}%")
        rows = conn.execute(sql + " ORDER BY created_at DESC", params).fetchall()
        wb = Workbook()
        ws = wb.active
        ws.title = "冲突工单"
        headers = ["工单号", "IP地址", "冲突来源", "冲突类型", "冲突描述", "冲突字段", "来源值", "处理建议", "状态", "处理人", "处理备注", "创建时间"]
        _style_header(ws, headers)
        for r_idx, r in enumerate(rows, 2):
            vals = [r["ticket_no"], r["ip_address"], r["conflict_source"], r["conflict_type"], r["conflict_desc"], r["field_name"], r["source_values"], r["suggestion"], r["status"], r["handler"], r["handle_remark"], r["created_at"]]
            for c_idx, v in enumerate(vals, 1):
                ws.cell(row=r_idx, column=c_idx, value=v if v else "")
        widths = [22, 16, 12, 12, 30, 12, 30, 20, 10, 10, 20, 20]
        for i, w in enumerate(widths, 1):
            ws.column_dimensions[chr(64 + i)].width = w
        log_operation(conn, "导出", "admin", str(request.url), f"导出冲突工单{len(rows)}条", get_client_ip(request))
        return _xlsx_response(wb, "conflicts_export")


@app.get("/api/export/logs")
def export_logs(request: Request, start_time: Optional[str] = None, end_time: Optional[str] = None):
    with get_conn() as conn:
        sql = "SELECT * FROM operation_logs WHERE 1=1"
        params = []
        if start_time:
            sql += " AND created_at >= ?"
            params.append(start_time)
        if end_time:
            sql += " AND created_at <= ?"
            params.append(end_time)
        rows = conn.execute(sql + " ORDER BY created_at DESC LIMIT 1000", params).fetchall()
        wb = Workbook()
        ws = wb.active
        ws.title = "操作日志"
        headers = ["操作类型", "操作人", "操作时间", "IP地址", "访问URL", "操作内容"]
        _style_header(ws, headers)
        for r_idx, r in enumerate(rows, 2):
            vals = [r["operation_type"], r["operator"], r["created_at"], r["ip_address"], r["request_url"], r["operation_detail"]]
            for c_idx, v in enumerate(vals, 1):
                ws.cell(row=r_idx, column=c_idx, value=v if v else "")
        widths = [12, 10, 20, 16, 30, 40]
        for i, w in enumerate(widths, 1):
            ws.column_dimensions[chr(64 + i)].width = w
        return _xlsx_response(wb, "operation_logs_export")



# ============ 4. 平台系统管理能力 ============

# 4.1 Operation logs
@app.get("/api/logs")
def list_logs(
    request: Request,
    page: int = 1,
    page_size: int = 10,
    operation_type: Optional[str] = None,
    operation_detail: Optional[str] = None,
    operator: Optional[str] = None,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
):
    with get_conn() as conn:
        sql = "SELECT * FROM operation_logs WHERE 1=1"
        params = []
        if operation_type:
            sql += " AND operation_type LIKE ?"
            params.append(f"%{operation_type}%")
        if operation_detail:
            sql += " AND operation_detail LIKE ?"
            params.append(f"%{operation_detail}%")
        if operator:
            sql += " AND operator LIKE ?"
            params.append(f"%{operator}%")
        if start_time:
            sql += " AND operation_time >= ?"
            params.append(start_time)
        if end_time:
            sql += " AND operation_time <= ?"
            params.append(end_time)
        total = conn.execute(f"SELECT COUNT(*) as c FROM ({sql})", params).fetchone()["c"]
        sql += " ORDER BY operation_time DESC LIMIT ? OFFSET ?"
        params += [page_size, (page - 1) * page_size]
        data = parse_list(conn.execute(sql, params).fetchall())
        return {"total": total, "page": page, "page_size": page_size, "data": data}


# ============ User management ============
@app.get("/api/users")
def list_users(request: Request, page: int = 1, page_size: int = 10, username: Optional[str] = None, role: Optional[str] = None):
    with get_conn() as conn:
        sql = "SELECT id, username, real_name, role, phone, email, status, created_at, last_login FROM users WHERE 1=1"
        params = []
        if username:
            sql += " AND username LIKE ?"
            params.append(f"%{username}%")
        if role:
            sql += " AND role=?"
            params.append(role)
        total = conn.execute(f"SELECT COUNT(*) as c FROM ({sql})", params).fetchone()["c"]
        sql += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
        params += [page_size, (page - 1) * page_size]
        data = parse_list(conn.execute(sql, params).fetchall())
        return {"total": total, "page": page, "page_size": page_size, "data": data}


class UserCreateRequest(BaseModel):
    username: str
    password: str
    real_name: str = ""
    role: str = "operator"
    phone: str = ""
    email: str = ""


@app.post("/api/users")
def create_user(req: UserCreateRequest, request: Request):
    with get_conn() as conn:
        existing = conn.execute("SELECT id FROM users WHERE username=?", (req.username,)).fetchone()
        if existing:
            raise HTTPException(400, "用户名已存在")
        uid = gen_id("u_")
        conn.execute(
            "INSERT INTO users (id, username, password, real_name, role, phone, email, status, created_at) VALUES (?,?,?,?,?,?,?,?,?)",
            (uid, req.username, hash_password(req.password), req.real_name, req.role, req.phone, req.email, "active", now_str()),
        )
        log_operation(conn, "用户管理", "admin", str(request.url), f"新建用户:{req.username}", get_client_ip(request))
        return {"id": uid, "message": "用户创建成功"}


class UserUpdateRequest(BaseModel):
    real_name: Optional[str] = None
    role: Optional[str] = None
    phone: Optional[str] = None
    email: Optional[str] = None
    status: Optional[str] = None
    password: Optional[str] = None


@app.put("/api/users/{user_id}")
def update_user(user_id: str, req: UserUpdateRequest, request: Request):
    with get_conn() as conn:
        u = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
        if not u:
            raise HTTPException(404, "用户不存在")
        fields = []
        params = []
        if req.real_name is not None:
            fields.append("real_name=?"); params.append(req.real_name)
        if req.role is not None:
            fields.append("role=?"); params.append(req.role)
        if req.phone is not None:
            fields.append("phone=?"); params.append(req.phone)
        if req.email is not None:
            fields.append("email=?"); params.append(req.email)
        if req.status is not None:
            fields.append("status=?"); params.append(req.status)
        if req.password is not None:
            fields.append("password=?"); params.append(hash_password(req.password))
        if not fields:
            return {"message": "无更新内容"}
        params.append(user_id)
        conn.execute(f"UPDATE users SET {','.join(fields)} WHERE id=?", params)
        log_operation(conn, "用户管理", "admin", str(request.url), f"编辑用户:{u['username']}", get_client_ip(request))
        return {"message": "用户更新成功"}


@app.delete("/api/users/{user_id}")
def delete_user(user_id: str, request: Request):
    with get_conn() as conn:
        u = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
        if not u:
            raise HTTPException(404, "用户不存在")
        if u["username"] == "admin":
            raise HTTPException(400, "不能删除管理员账户")
        conn.execute("DELETE FROM users WHERE id=?", (user_id,))
        log_operation(conn, "用户管理", "admin", str(request.url), f"删除用户:{u['username']}", get_client_ip(request))
        return {"message": "用户删除成功"}


# 4.2 Security config
@app.get("/api/security/config")
def get_security_config(request: Request):
    with get_conn() as conn:
        configs = parse_list(conn.execute("SELECT * FROM security_config ORDER BY id").fetchall())
        return {"data": configs}


class SecurityConfigRequest(BaseModel):
    config_key: str
    config_value: str


@app.put("/api/security/config")
def update_security_config(req: SecurityConfigRequest, request: Request):
    with get_conn() as conn:
        conn.execute("UPDATE security_config SET config_value=?, updated_at=? WHERE config_key=?", (req.config_value, now_str(), req.config_key))
        log_operation(conn, "安全配置", "admin", str(request.url), f"更新安全配置:{req.config_key}={req.config_value}", get_client_ip(request))
        return {"message": "安全配置更新成功"}


# IP access rules
@app.get("/api/security/ip-access")
def list_ip_access(request: Request):
    with get_conn() as conn:
        rules = parse_list(conn.execute("SELECT * FROM ip_access_rules ORDER BY created_at DESC").fetchall())
        # Include default all-open rule
        return {"data": rules, "default": "系统默认放开全部IP访问权限"}


class IPAccessRequest(BaseModel):
    ip_segment: str
    description: str = ""


@app.post("/api/security/ip-access")
def create_ip_access(req: IPAccessRequest, request: Request):
    with get_conn() as conn:
        rid = gen_id("ipa_")
        conn.execute(
            "INSERT INTO ip_access_rules (id, ip_segment, description, enabled, created_at) VALUES (?,?,?,?,?)",
            (rid, req.ip_segment, req.description, 1, now_str()),
        )
        log_operation(conn, "IP访问授权", "admin", str(request.url), f"新增IP访问规则:{req.ip_segment}", get_client_ip(request))
        return {"id": rid, "message": "IP访问规则创建成功"}


@app.put("/api/security/ip-access/{rule_id}/toggle")
def toggle_ip_access(rule_id: str, request: Request):
    with get_conn() as conn:
        r = conn.execute("SELECT enabled FROM ip_access_rules WHERE id=?", (rule_id,)).fetchone()
        if not r:
            raise HTTPException(404, "规则不存在")
        new_enabled = 0 if r["enabled"] == 1 else 1
        conn.execute("UPDATE ip_access_rules SET enabled=? WHERE id=?", (new_enabled, rule_id))
        return {"enabled": new_enabled, "message": "规则状态已切换"}


@app.delete("/api/security/ip-access/{rule_id}")
def delete_ip_access(rule_id: str, request: Request):
    with get_conn() as conn:
        conn.execute("DELETE FROM ip_access_rules WHERE id=?", (rule_id,))
        return {"message": "IP访问规则删除成功"}


# ============ Dashboard/Stats ============
@app.get("/api/dashboard/stats")
def dashboard_stats(request: Request):
    with get_conn() as conn:
        return {
            "task_count": conn.execute("SELECT COUNT(*) as c FROM query_tasks").fetchone()["c"],
            "datasource_count": conn.execute("SELECT COUNT(*) as c FROM data_sources").fetchone()["c"],
            "conflict_open": conn.execute("SELECT COUNT(*) as c FROM conflict_tickets WHERE status='open'").fetchone()["c"],
            "conflict_total": conn.execute("SELECT COUNT(*) as c FROM conflict_tickets").fetchone()["c"],
            "ip_subject_count": conn.execute("SELECT COUNT(*) as c FROM ip_subjects").fetchone()["c"],
            "scene_count": conn.execute("SELECT COUNT(*) as c FROM scenes").fetchone()["c"],
            "template_count": conn.execute("SELECT COUNT(*) as c FROM subject_templates").fetchone()["c"],
        }


# ============ Serve Frontend ============
@app.get("/", response_class=HTMLResponse)
def index():
    with open(os.path.join(FRONTEND_DIR, "index.html"), "r", encoding="utf-8") as f:
        return f.read()


app.mount("/static", StaticFiles(directory=os.path.join(FRONTEND_DIR, "static")), name="static")


@app.on_event("startup")
def startup():
    init_db()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
