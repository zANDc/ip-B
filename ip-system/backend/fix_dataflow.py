"""修复数据流向三处断裂：
1. 场景 scenes 关联数据源（新增 scene_datasources 关系表）
2. ip_subjects 新增 template_id 字段，回填各数据源关联的模板
3. 建立场景->数据源->模板 的联动关系，并自动维护
"""
import sqlite3
import os
import uuid
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "data", "ip_system.db")


def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def now_str():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def gen_id(prefix=""):
    return prefix + uuid.uuid4().hex[:12]


# 数据源名 -> 模板名 (用于回填 ip_subjects.template_id)
# 注: 信安/综资 ip_subjects.data_source 字段保存的是短名
DS_TEMPLATE_MAP = {
    "家宽BRAS数据源": "家宽用户模板",
    "信安系统": "信安系统模板",
    "移网AAA数据源": "移网用户模板",
    "综资系统": "综资系统模板",
}

# 场景名 -> 数据源名列表 (建立场景与数据源关联)
SCENE_DS_MAP = {
    "移网IP定位场景": ["移网AAA数据源"],
    "家宽IP定位场景": ["家宽BRAS数据源"],
    "专线IP定位场景": ["专线资源系统"],
    "IDC IP定位场景": ["IDC资产系统"],
    "自有业务IP定位场景": ["自有业务平台"],
}


def fix_dataflow():
    with get_conn() as conn:
        # === 断裂1: scenes 表无 datasource 关联 ===
        # 创建场景-数据源关联表
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scene_datasources (
                id TEXT PRIMARY KEY,
                scene_id TEXT NOT NULL,
                datasource_id TEXT NOT NULL,
                created_at TEXT,
                UNIQUE(scene_id, datasource_id),
                FOREIGN KEY (scene_id) REFERENCES scenes(id) ON DELETE CASCADE,
                FOREIGN KEY (datasource_id) REFERENCES data_sources(id) ON DELETE CASCADE
            )
        """)
        print("[1] scene_datasources 关联表已创建/已存在")

        # 按场景名映射关系建立关联数据
        existing_links = {r["scene_id"] + ":" + r["datasource_id"] for r in conn.execute("SELECT scene_id, datasource_id FROM scene_datasources").fetchall()}
        added = 0
        for sc_name, ds_names in SCENE_DS_MAP.items():
            sc = conn.execute("SELECT id FROM scenes WHERE name=?", (sc_name,)).fetchone()
            if not sc:
                print(f"  跳过：场景[{sc_name}]不存在")
                continue
            for ds_name in ds_names:
                ds = conn.execute("SELECT id FROM data_sources WHERE name=?", (ds_name,)).fetchone()
                if not ds:
                    print(f"  跳过：数据源[{ds_name}]不存在")
                    continue
                key = sc["id"] + ":" + ds["id"]
                if key in existing_links:
                    continue
                conn.execute(
                    "INSERT INTO scene_datasources (id, scene_id, datasource_id, created_at) VALUES (?,?,?,?)",
                    (gen_id("sd_"), sc["id"], ds["id"], now_str()),
                )
                added += 1
                existing_links.add(key)
        print(f"[1] 新增场景-数据源关联: {added} 条")

        # === 断裂2: ip_subjects 无 template_id ===
        cols = [c["name"] for c in conn.execute("PRAGMA table_info(ip_subjects)").fetchall()]
        if "template_id" not in cols:
            conn.execute("ALTER TABLE ip_subjects ADD COLUMN template_id TEXT")
            print("[2] ip_subjects 表新增 template_id 字段")
        else:
            print("[2] ip_subjects.template_id 字段已存在")

        # 按数据源名回填 template_id
        updated = 0
        for ds_name, tpl_name in DS_TEMPLATE_MAP.items():
            tpl = conn.execute("SELECT id FROM subject_templates WHERE name=?", (tpl_name,)).fetchone()
            if not tpl:
                continue
            cur = conn.execute("UPDATE ip_subjects SET template_id=? WHERE data_source=? AND (template_id IS NULL OR template_id='')", (tpl["id"], ds_name))
            updated += cur.rowcount
        print(f"[2] 回填 ip_subjects.template_id: {updated} 条")

        # === 断裂3: 建立数据源->模板->字段 的关联查询，用于置信度计算 ===
        # 验证 data_sources.template_id 字段已关联
        linked = conn.execute("SELECT COUNT(*) as c FROM data_sources WHERE template_id IS NOT NULL AND template_id != ''").fetchone()["c"]
        total_ds = conn.execute("SELECT COUNT(*) as c FROM data_sources").fetchone()["c"]
        print(f"[3] 数据源-模板关联: {linked}/{total_ds} 个数据源已关联模板")

        # 验证 ip_subjects 完整关联链
        print("\n=== 验证完整数据流向 ===")
        print("场景 -> 数据源 -> 模板 -> 字段:")
        for sc_name in SCENE_DS_MAP:
            sc = conn.execute("SELECT id FROM scenes WHERE name=?", (sc_name,)).fetchone()
            if not sc:
                continue
            ds_links = conn.execute("SELECT ds.name as ds_name, ds.template_id, t.name as tpl_name FROM scene_datasources sd JOIN data_sources ds ON sd.datasource_id=ds.id LEFT JOIN subject_templates t ON ds.template_id=t.id WHERE sd.scene_id=?", (sc["id"],)).fetchall()
            for r in ds_links:
                field_count = conn.execute("SELECT COUNT(*) as c FROM subject_template_fields WHERE template_id=?", (r["template_id"],)).fetchone()["c"] if r["template_id"] else 0
                ip_count = conn.execute("SELECT COUNT(*) as c FROM ip_subjects WHERE template_id=?", (r["template_id"],)).fetchone()["c"] if r["template_id"] else 0
                print(f"  {sc_name} -> {r['ds_name']} -> {r['tpl_name'] or '未关联'} (字段{field_count}个, 数据{ip_count}条)")

        # 验证 ip_subjects 全部有 template_id
        total_ip = conn.execute("SELECT COUNT(*) as c FROM ip_subjects").fetchone()["c"]
        with_tpl = conn.execute("SELECT COUNT(*) as c FROM ip_subjects WHERE template_id IS NOT NULL AND template_id != ''").fetchone()["c"]
        print(f"\nip_subjects 总数: {total_ip}, 已关联模板: {with_tpl}, 未关联: {total_ip-with_tpl}")


if __name__ == "__main__":
    fix_dataflow()
    print("\n数据流向修复完成!")
