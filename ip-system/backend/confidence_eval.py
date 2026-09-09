"""置信度评估引擎:基于 confidence_dimensions 配置,对IP主体做多维度加权评估并落台账。"""
import json
import sqlite3
from datetime import datetime, timedelta
from contextlib import contextmanager
from database import get_conn, now_str, gen_id


@contextmanager
def open_conn():
    with get_conn() as conn:
        yield conn


def _load_dimensions(conn, only_main=True):
    """加载启用的维度(默认只主维度, 不含风险扣分项)"""
    flag = " AND is_risk=0" if only_main else ""
    rows = conn.execute(
        f"SELECT * FROM confidence_dimensions WHERE enabled=1{flag} ORDER BY display_order, dim_code"
    ).fetchall()
    return [dict(r) for r in rows]


def _load_risk_rules(conn):
    rows = conn.execute(
        "SELECT * FROM confidence_dimensions WHERE enabled=1 AND is_risk=1 ORDER BY dim_code"
    ).fetchall()
    return [dict(r) for r in rows]


def _score_authority(datasource):
    """权威性维度:数据源等级 → 分数"""
    if not datasource:
        return 60, "数据源未关联"
    level = datasource.get("authority_level") or "中"
    return {"高": 95, "中": 75, "低": 55}.get(level, 60), f"权威性等级={level}"


def _score_completeness(conn, subject, template):
    """完整度维度:基于模板字段定义计算非空比例"""
    if template:
        fields = conn.execute(
            "SELECT field_name FROM subject_template_fields WHERE template_id=?",
            (template["id"],),
        ).fetchall()
        names = [f["field_name"] for f in fields]
    else:
        names = ["ip_address", "scene_type", "data_source", "start_time", "end_time", "city_id"]
    if not names:
        return 50, "模板无字段"
    filled = sum(1 for n in names if subject.get(n) not in (None, ""))
    pct = int(filled / len(names) * 100)
    return pct, f"{filled}/{len(names)}字段非空"


def _score_freshness(subject):
    """新鲜度维度:基于 start_time 与当前间隔"""
    start = subject.get("start_time") or subject.get("query_time")
    if not start:
        return 50, "无时间字段"
    try:
        s = str(start)
        if len(s) == 14 and s.isdigit():
            dt = datetime.strptime(s, "%Y%m%d%H%M%S")
        else:
            dt = datetime.strptime(s[:19], "%Y-%m-%d %H:%M:%S")
    except Exception:
        return 50, "时间解析失败"
    days = max((datetime.now() - dt).days, 0)
    if days <= 1:
        score, note = 100, f"1天内"
    elif days <= 7:
        score, note = 90, f"{days}天"
    elif days <= 30:
        score, note = 75, f"{days}天"
    elif days <= 90:
        score, note = 55, f"{days}天"
    elif days <= 180:
        score, note = 40, f"{days}天"
    else:
        score, note = 20, f"{days}天(严重过期)"
    return score, note


def _score_consistency(conn, subject):
    """多源一致性维度:该IP在多少源中出现过, 越一致越高分"""
    ip = subject.get("ip_address")
    if not ip:
        return 50, "无IP"
    sources = conn.execute(
        "SELECT DISTINCT data_source FROM ip_subjects WHERE ip_address=?",
        (ip,),
    ).fetchall()
    cnt = len(sources)
    if cnt >= 3:
        return 95, f"在{cnt}个数据源中均有"
    if cnt == 2:
        return 80, "在2个数据源中出现"
    if cnt == 1:
        return 60, "仅在1个数据源中出现"
    return 50, "无数据源"


def _trigger_risks(subject, dimension_scores):
    """根据 subject 状态触发风险扣分项,返回触发的扣分项明细 + 总扣分"""
    risks = []
    total_deduct = 0
    start = subject.get("start_time")
    days = 0
    if start:
        try:
            s = str(start)
            if len(s) == 14 and s.isdigit():
                dt = datetime.strptime(s, "%Y%m%d%H%M%S")
            else:
                dt = datetime.strptime(s[:19], "%Y-%m-%d %H:%M:%S")
            days = max((datetime.now() - dt).days, 0)
        except Exception:
            days = 0
    if days > 180:
        risks.append({"code": "risk_outdated", "name": "严重过期", "deduct": 15, "reason": f"已过期{days}天"})
        total_deduct += 15
    # 数据源有可疑标识
    ds = subject.get("data_source") or ""
    if "匿名" in ds or "黑名单" in ds:
        risks.append({"code": "risk_anonymous", "name": "匿名访问", "deduct": 5, "reason": f"数据源={ds}"})
        total_deduct += 5
    # 命中可疑IP(示例:203.0.113.0/24 段作为可疑示例)
    ip = subject.get("ip_address") or ""
    if ip.startswith("203.0.113."):
        risks.append({"code": "risk_suspicious", "name": "可疑数据", "deduct": 10, "reason": f"IP {ip} 命中可疑网段"})
        total_deduct += 10
    # 多源冲突(consistency 维度分<60即冲突)
    consistency = next((d for d in dimension_scores if d["code"] == "consistency"), None)
    if consistency and consistency["score"] < 60:
        risks.append({"code": "risk_conflict", "name": "多源冲突", "deduct": 8, "reason": "字段值在多源间不一致"})
        total_deduct += 8
    return risks, total_deduct


def _level_for(score):
    if score >= 85:
        return "高"
    if score >= 60:
        return "中"
    return "低"


def evaluate_subject(conn, subject):
    """对一条 ip_subjects 评估,返回 {total_score, level, dim_scores[], risks[], risk_deduct}"""
    sub = dict(subject)
    ds_id = sub.get("data_source_id") or sub.get("source_id")
    datasource = conn.execute("SELECT * FROM data_sources WHERE id=?", (ds_id,)).fetchone() if ds_id else None
    template = conn.execute("SELECT * FROM subject_templates WHERE id=?", (sub.get("template_id"),)).fetchone()

    dims = _load_dimensions(conn, only_main=True)
    # 计算每个维度的原始分数
    raw = {}
    raw["authority"] = _score_authority(dict(datasource) if datasource else None)
    raw["completeness"] = _score_completeness(conn, sub, dict(template) if template else None)
    raw["freshness"] = _score_freshness(sub)
    raw["consistency"] = _score_consistency(conn, sub)

    # 用 confidence_dimensions.weight 加权
    weight_total = sum((d["weight"] or 0) for d in dims) or 100
    dim_scores = []
    weighted = 0.0
    for d in dims:
        code = d["dim_code"]
        sc, note = raw.get(code, (60, "未计算"))
        w = d["weight"] or 0
        weighted += sc * (w / weight_total)
        dim_scores.append({
            "id": d["id"],
            "code": code,
            "name": d["dim_name"],
            "weight": w,
            "score": sc,
            "note": note,
            "description": d["description"],
        })
    base = round(weighted, 1)
    risks, deduct = _trigger_risks(sub, dim_scores)
    total = max(round(base - deduct, 1), 0)
    return {
        "total_score": total,
        "base_score": base,
        "level": _level_for(total),
        "dim_scores": dim_scores,
        "risks": risks,
        "risk_deduct": deduct,
    }


def evaluate_all_pending(batch_size=200):
    """扫描 ip_subjects 中 eval_status='pending' 的记录做评估, 写入台账"""
    evaluated = 0
    with open_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM ip_subjects WHERE source_subtype IS NOT NULL AND (eval_status IS NULL OR eval_status='pending') LIMIT ?",
            (batch_size,),
        ).fetchall()
        for r in rows:
            sub = dict(r)
            res = evaluate_subject(conn, sub)
            eid = gen_id("ce_")
            conn.execute(
                """INSERT INTO confidence_evaluations
                (id, access_key, ip_address, source_id, source_name, field_name, eval_time, total_score, level,
                 risk_deductions, dimension_scores, subject_snapshot, created_at)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    eid,
                    sub.get("id"),
                    sub.get("ip_address"),
                    sub.get("data_source_id"),
                    sub.get("data_source"),
                    None,
                    now_str(),
                    res["total_score"],
                    res["level"],
                    json.dumps(res["risks"], ensure_ascii=False),
                    json.dumps(res["dim_scores"], ensure_ascii=False),
                    json.dumps({k: sub.get(k) for k in ["ip_address", "scene_type", "data_source", "start_time", "end_time"]}, ensure_ascii=False),
                    now_str(),
                ),
            )
            conn.execute(
                "UPDATE ip_subjects SET eval_status='evaluated', last_eval_time=? WHERE id=?",
                (now_str(), sub["id"]),
            )
            evaluated += 1
    return evaluated


def evaluate_one(ip_address, source_name=None):
    """对单条IP触发评估(可按数据源过滤)"""
    with open_conn() as conn:
        if source_name:
            rows = conn.execute(
                "SELECT * FROM ip_subjects WHERE ip_address=? AND data_source=? LIMIT 1",
                (ip_address, source_name),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM ip_subjects WHERE ip_address=? ORDER BY id DESC LIMIT 1",
                (ip_address,),
            ).fetchall()
        results = []
        for r in rows:
            sub = dict(r)
            res = evaluate_subject(conn, sub)
            eid = gen_id("ce_")
            conn.execute(
                """INSERT INTO confidence_evaluations
                (id, access_key, ip_address, source_id, source_name, field_name, eval_time, total_score, level,
                 risk_deductions, dimension_scores, subject_snapshot, created_at)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    eid, sub.get("id"), sub.get("ip_address"),
                    sub.get("data_source_id"), sub.get("data_source"),
                    None, now_str(), res["total_score"], res["level"],
                    json.dumps(res["risks"], ensure_ascii=False),
                    json.dumps(res["dim_scores"], ensure_ascii=False),
                    json.dumps({k: sub.get(k) for k in ["ip_address", "scene_type", "data_source", "start_time"]}, ensure_ascii=False),
                    now_str(),
                ),
            )
            conn.execute(
                "UPDATE ip_subjects SET eval_status='evaluated', last_eval_time=? WHERE id=?",
                (now_str(), sub["id"]),
            )
            results.append({"eval_id": eid, "result": res, "ip": ip_address, "source": sub.get("data_source")})
        return results


def list_dimensions():
    """列出所有维度(含风险扣分项)"""
    with open_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM confidence_dimensions ORDER BY is_risk, display_order, dim_code"
        ).fetchall()
        return [dict(r) for r in rows]


def update_dimension(dim_id, updates):
    """更新维度配置(权重/说明/扣分值/启用等)"""
    allowed = {"dim_name", "description", "weight", "config", "enabled", "risk_value", "display_order"}
    sets, vals = [], []
    for k, v in updates.items():
        if k in allowed:
            sets.append(f"{k}=?")
            vals.append(v)
    if not sets:
        return 0
    sets.append("updated_at=?")
    vals.append(now_str())
    vals.append(dim_id)
    with open_conn() as conn:
        return conn.execute(f"UPDATE confidence_dimensions SET {','.join(sets)} WHERE id=?", vals).rowcount


def create_dimension(payload):
    """新增自定义维度"""
    with open_conn() as conn:
        dim_id = gen_id("dim_")
        conn.execute(
            """INSERT INTO confidence_dimensions
            (id, dim_code, dim_name, description, weight, score_mode, config, is_required, is_risk, risk_value, display_order, enabled, created_at, updated_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                dim_id,
                payload["dim_code"],
                payload["dim_name"],
                payload.get("description", ""),
                int(payload.get("weight", 0)),
                payload.get("score_mode", "score"),
                json.dumps(payload.get("config") or {}, ensure_ascii=False),
                1 if payload.get("is_required") else 0,
                1 if payload.get("is_risk") else 0,
                int(payload.get("risk_value", 0)),
                int(payload.get("display_order", 0)),
                1 if payload.get("enabled", True) else 0,
                now_str(),
                now_str(),
            ),
        )
        return dim_id


def delete_dimension(dim_id):
    with open_conn() as conn:
        return conn.execute("DELETE FROM confidence_dimensions WHERE id=?", (dim_id,)).rowcount


def query_evaluations(filters=None, page=1, page_size=20):
    """查询评估台账:多条件+分页"""
    f = filters or {}
    where, vals = [], []
    if f.get("ip_address"):
        where.append("ip_address LIKE ?")
        vals.append(f"%{f['ip_address']}%")
    if f.get("source_name"):
        where.append("source_name LIKE ?")
        vals.append(f"%{f['source_name']}%")
    if f.get("field_name"):
        where.append("field_name LIKE ?")
        vals.append(f"%{f['field_name']}%")
    if f.get("level"):
        where.append("level=?")
        vals.append(f["level"])
    if f.get("start_time"):
        where.append("eval_time>=?")
        vals.append(f["start_time"])
    if f.get("end_time"):
        where.append("eval_time<=?")
        vals.append(f["end_time"])
    where.append("1=1")
    sql = "SELECT * FROM confidence_evaluations WHERE " + " AND ".join(where)
    sql += " ORDER BY eval_time DESC LIMIT ? OFFSET ?"
    count_sql = "SELECT COUNT(*) c FROM confidence_evaluations WHERE " + " AND ".join(where)
    with open_conn() as conn:
        total = conn.execute(count_sql, vals).fetchone()["c"]
        rows = conn.execute(sql, vals + [page_size, (page - 1) * page_size]).fetchall()
        items = []
        for r in rows:
            d = dict(r)
            d["risk_deductions"] = json.loads(d["risk_deductions"] or "[]")
            d["dimension_scores"] = json.loads(d["dimension_scores"] or "[]")
            items.append(d)
        return {"total": total, "page": page, "page_size": page_size, "items": items}


def get_evaluation(eval_id):
    with open_conn() as conn:
        row = conn.execute("SELECT * FROM confidence_evaluations WHERE id=?", (eval_id,)).fetchone()
        if not row:
            return None
        d = dict(row)
        d["risk_deductions"] = json.loads(d["risk_deductions"] or "[]")
        d["dimension_scores"] = json.loads(d["dimension_scores"] or "[]")
        d["subject_snapshot"] = json.loads(d["subject_snapshot"] or "{}")
        return d


def get_distribution():
    """等级分布统计(可视化标尺数据)"""
    with open_conn() as conn:
        rows = conn.execute(
            "SELECT level, COUNT(*) c FROM confidence_evaluations GROUP BY level"
        ).fetchall()
        return {r["level"]: r["c"] for r in rows}


def list_evaluations_by_ip(ip_address):
    """按IP查所有评估记录(供冲突工单详情嵌入)"""
    with open_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM confidence_evaluations WHERE ip_address=? ORDER BY eval_time DESC",
            (ip_address,),
        ).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["risk_deductions"] = json.loads(d["risk_deductions"] or "[]")
            d["dimension_scores"] = json.loads(d["dimension_scores"] or "[]")
            out.append(d)
        return out
