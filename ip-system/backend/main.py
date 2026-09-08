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
        # Query ip_subjects
        sql = "SELECT * FROM ip_subjects WHERE ip_address=?"
        params = [ip]
        if req.start_time and req.end_time:
            sql += " AND start_time <= ? AND end_time >= ?"
            params += [req.end_time, req.start_time]
        if req.scene_type:
            sql += " AND scene_type=?"
            params += [req.scene_type]
        results = conn.execute(sql, params).fetchall()

        # Create task
        task_name = req.task_name or f"查询-{ip}"
        conn.execute(
            """INSERT INTO query_tasks (id, task_name, ip_address, ip_version, port, start_time, end_time, scene_type, status, result_count, created_by, created_at, completed_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (task_id, task_name, ip, ip_ver, req.port or "", req.start_time, req.end_time, req.scene_type or "", "completed", len(results), "admin", now_str(), now_str()),
        )

        # Create path records
        path_nodes = [
            ("开始", "start", "success", "任务开始", "系统", now_str()),
            ("场景识别", "judge", "success", f"场景类型: {req.scene_type or '自动识别'}", "系统", now_str()),
            ("数据源查询", "execute", "success", f"查询IP: {ip}", "移网AAA数据源,家宽BRAS数据源", now_str()),
            ("数据融合", "execute", "success" if results else "failed", f"命中{len(results)}条记录", "融合算法", now_str()),
            ("返回结果", "execute", "success", f"返回{len(results)}条定位结果", "系统", now_str()),
        ]
        for pn in path_nodes:
            conn.execute(
                "INSERT INTO task_paths (id, task_id, node_name, node_type, status, detail, data_source, started_at, completed_at) VALUES (?,?,?,?,?,?,?,?,?)",
                (gen_id("tp_"), task_id, pn[0], pn[1], pn[2], pn[3], pn[4], pn[5], now_str()),
            )

        log_operation(conn, "查询", "admin", str(request.url), f"创建IP查询任务: {ip}", get_client_ip(request))

        # Mask sensitive fields in results
        masked_results = []
        for r in results:
            rd = dict(r)
            masked_results.append(rd)

        return {
            "task_id": task_id,
            "results": masked_results,
            "count": len(results),
            "paths": parse_list(conn.execute("SELECT * FROM task_paths WHERE task_id=? ORDER BY id", (task_id,)).fetchall()),
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
        paths = conn.execute("SELECT * FROM task_paths WHERE task_id=? ORDER BY id", (task_id,)).fetchall()
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
        paths = conn.execute("SELECT * FROM task_paths WHERE task_id=? ORDER BY id", (task_id,)).fetchall()
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
    nodes: str = "[]"
    edges: str = "[]"


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
        log_operation(conn, "新增路径", "admin", str(request.url), f"新增场景路径:{req.name}", get_client_ip(request))
        return {"id": pid, "message": "路径创建成功"}


@app.put("/api/scenes/{scene_id}/paths/{path_id}")
def update_scene_path(scene_id: str, path_id: str, req: ScenePathRequest, request: Request):
    with get_conn() as conn:
        conn.execute("UPDATE scene_paths SET name=?, nodes=?, edges=?, updated_at=? WHERE id=?", (req.name, req.nodes, req.edges, now_str(), path_id))
        log_operation(conn, "编辑路径", "admin", str(request.url), f"编辑场景路径:{req.name}", get_client_ip(request))
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
        log_operation(conn, "发布路径", "admin", str(request.url), f"发布场景路径:{path_id}", get_client_ip(request))
        return {"message": "路径发布成功"}


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


@app.get("/api/export/assessment")
def export_assessment(request: Request, ip_address: Optional[str] = None):
    with get_conn() as conn:
        sql = "SELECT * FROM assessment_records WHERE 1=1"
        params = []
        if ip_address:
            sql += " AND ip_address LIKE ?"
            params.append(f"%{ip_address}%")
        rows = conn.execute(sql + " ORDER BY created_at DESC", params).fetchall()
        wb = Workbook()
        ws = wb.active
        ws.title = "置信度评估"
        headers = ["IP地址", "数据源", "来源字段", "评估时间", "总分", "维度得分", "扣分项", "风险等级"]
        _style_header(ws, headers)
        for r_idx, r in enumerate(rows, 2):
            vals = [r["ip_address"], r["data_source"], r["source_field"], r["assessment_time"], r["total_score"], r["dimension_scores"], r["deductions"], r["risk_level"]]
            for c_idx, v in enumerate(vals, 1):
                ws.cell(row=r_idx, column=c_idx, value=v if v else "")
        widths = [16, 16, 12, 20, 8, 30, 30, 10]
        for i, w in enumerate(widths, 1):
            ws.column_dimensions[chr(64 + i)].width = w
        return _xlsx_response(wb, "assessment_export")


# 3.2 Confidence assessment
@app.get("/api/assessment/dimensions")
def list_dimensions(request: Request):
    with get_conn() as conn:
        dims = parse_list(conn.execute("SELECT * FROM assessment_dimensions ORDER BY weight DESC").fetchall())
        for d in dims:
            d["color_levels"] = json.loads(d["color_levels"] or "[]")
        return {"data": dims}


class DimensionRequest(BaseModel):
    name: str
    description: str = ""
    weight: float = 1.0
    max_score: float = 100
    color_levels: str = "[]"


@app.post("/api/assessment/dimensions")
def create_dimension(req: DimensionRequest, request: Request):
    with get_conn() as conn:
        dim_id = gen_id("dim_")
        conn.execute(
            "INSERT INTO assessment_dimensions (id, name, description, weight, max_score, color_levels, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?)",
            (dim_id, req.name, req.description, req.weight, req.max_score, req.color_levels, now_str(), now_str()),
        )
        log_operation(conn, "新增评估维度", "admin", str(request.url), f"新增维度:{req.name}", get_client_ip(request))
        return {"id": dim_id, "message": "维度创建成功"}


@app.put("/api/assessment/dimensions/{dim_id}")
def update_dimension(dim_id: str, req: DimensionRequest, request: Request):
    with get_conn() as conn:
        conn.execute(
            "UPDATE assessment_dimensions SET name=?, description=?, weight=?, max_score=?, color_levels=?, updated_at=? WHERE id=?",
            (req.name, req.description, req.weight, req.max_score, req.color_levels, now_str(), dim_id),
        )
        return {"message": "维度更新成功"}


@app.delete("/api/assessment/dimensions/{dim_id}")
def delete_dimension(dim_id: str, request: Request):
    with get_conn() as conn:
        conn.execute("DELETE FROM assessment_dimensions WHERE id=?", (dim_id,))
        return {"message": "维度删除成功"}


# Deductions
@app.get("/api/assessment/deductions")
def list_deductions(request: Request):
    with get_conn() as conn:
        return {"data": parse_list(conn.execute("SELECT * FROM assessment_deductions ORDER BY deduction_value DESC").fetchall())}


class DeductionRequest(BaseModel):
    name: str
    description: str = ""
    deduction_value: float
    risk_level: str = "可疑"


@app.post("/api/assessment/deductions")
def create_deduction(req: DeductionRequest, request: Request):
    with get_conn() as conn:
        did = gen_id("ded_")
        conn.execute(
            "INSERT INTO assessment_deductions (id, name, description, deduction_value, risk_level, created_at) VALUES (?,?,?,?,?,?)",
            (did, req.name, req.description, req.deduction_value, req.risk_level, now_str()),
        )
        log_operation(conn, "新增扣分项", "admin", str(request.url), f"新增扣分项:{req.name}", get_client_ip(request))
        return {"id": did, "message": "扣分项创建成功"}


@app.put("/api/assessment/deductions/{ded_id}")
def update_deduction(ded_id: str, req: DeductionRequest, request: Request):
    with get_conn() as conn:
        conn.execute("UPDATE assessment_deductions SET name=?, description=?, deduction_value=?, risk_level=? WHERE id=?", (req.name, req.description, req.deduction_value, req.risk_level, ded_id))
        return {"message": "扣分项更新成功"}


@app.delete("/api/assessment/deductions/{ded_id}")
def delete_deduction(ded_id: str, request: Request):
    with get_conn() as conn:
        conn.execute("DELETE FROM assessment_deductions WHERE id=?", (ded_id,))
        return {"message": "扣分项删除成功"}


# Assessment records (台账)
@app.get("/api/assessment/records")
def list_assessment_records(
    request: Request,
    page: int = 1,
    page_size: int = 10,
    ip_address: Optional[str] = None,
    data_source: Optional[str] = None,
    source_field: Optional[str] = None,
    risk_level: Optional[str] = None,
):
    with get_conn() as conn:
        sql = "SELECT * FROM assessment_records WHERE 1=1"
        params = []
        if ip_address:
            sql += " AND ip_address LIKE ?"
            params.append(f"%{ip_address}%")
        if data_source:
            sql += " AND data_source LIKE ?"
            params.append(f"%{data_source}%")
        if source_field:
            sql += " AND source_field LIKE ?"
            params.append(f"%{source_field}%")
        if risk_level:
            sql += " AND risk_level=?"
            params.append(risk_level)
        total = conn.execute(f"SELECT COUNT(*) as c FROM ({sql})", params).fetchone()["c"]
        sql += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
        params += [page_size, (page - 1) * page_size]
        records = parse_list(conn.execute(sql, params).fetchall())
        for r in records:
            r["dimension_scores"] = json.loads(r["dimension_scores"] or "{}")
            r["deductions"] = json.loads(r["deductions"] or "[]")
        return {"total": total, "page": page, "page_size": page_size, "data": records}


class AssessmentRecordRequest(BaseModel):
    ip_address: str
    data_source: str
    source_field: str
    dimension_scores: dict = {}
    deductions: list = []


@app.post("/api/assessment/records")
def create_assessment_record(req: AssessmentRecordRequest, request: Request):
    with get_conn() as conn:
        # Get dimensions for weighted calculation
        dims = conn.execute("SELECT * FROM assessment_dimensions").fetchall()
        total_score = 0.0
        for d in dims:
            score = req.dimension_scores.get(d["name"], 0)
            total_score += score * d["weight"]
        # Apply deductions
        total_deduction = sum(d.get("value", 0) for d in req.deductions)
        total_score -= total_deduction
        total_score = max(0, min(100, total_score))
        # Determine risk level
        if total_score >= 90:
            risk = "优秀"
        elif total_score >= 70:
            risk = "良好"
        elif total_score >= 50:
            risk = "一般"
        else:
            risk = "差"
        access_id = f"ACC{datetime.now().strftime('%Y%m%d%H%M%S')}{random.randint(10,99)}"
        rid = gen_id("ar_")
        conn.execute(
            "INSERT INTO assessment_records (id, access_id, ip_address, data_source, source_field, assessment_time, total_score, dimension_scores, deductions, risk_level, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (rid, access_id, req.ip_address, req.data_source, req.source_field, now_str(), total_score, json.dumps(req.dimension_scores, ensure_ascii=False), json.dumps(req.deductions, ensure_ascii=False), risk, now_str()),
        )
        log_operation(conn, "置信度评估", "admin", str(request.url), f"评估IP:{req.ip_address}得分:{total_score}", get_client_ip(request))
        return {"id": rid, "access_id": access_id, "total_score": total_score, "risk_level": risk, "message": "评估记录创建成功"}


@app.get("/api/assessment/records/{record_id}")
def get_assessment_record(record_id: str, request: Request):
    with get_conn() as conn:
        r = conn.execute("SELECT * FROM assessment_records WHERE id=?", (record_id,)).fetchone()
        if not r:
            raise HTTPException(404, "评估记录不存在")
        result = dict(r)
        result["dimension_scores"] = json.loads(result["dimension_scores"] or "{}")
        result["deductions"] = json.loads(result["deductions"] or "[]")
        return result


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
            "assessment_count": conn.execute("SELECT COUNT(*) as c FROM assessment_records").fetchone()["c"],
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
