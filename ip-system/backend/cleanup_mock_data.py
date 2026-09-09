"""清理模拟数据 + 重建基于真实数据源的主体模板字段 + 数据源关联模板."""
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


# 基于真实数据源字段的主体模板定义
REAL_TEMPLATES = {
    "移网用户模板": {
        "scene_type": "移网",
        "description": "移网测试集(动态)字段模板 - 用户永久标识/GPSI/PEIMEI/IP/端口/基站/会话等40字段",
        "fields": [
            ("subscriber_id", "用户永久标识", "text", 1, 1, 1, 1, "用户永久标识(15位数字)"),
            ("public_user_id", "通用公共用户标识", "text", 0, 0, 0, 2, "GPSI"),
            ("permanent_device_id", "永久设备标识", "text", 0, 1, 1, 3, "PEIMEI"),
            ("user_private_ip", "用户私网IP地址", "text", 1, 0, 0, 4, "私网IP"),
            ("source_public_ip", "源公网IP地址", "text", 1, 0, 0, 5, "源公网IP"),
            ("private_port", "私网端口号", "text", 0, 0, 0, 6, ""),
            ("source_port", "源端口号", "text", 0, 0, 0, 7, ""),
            ("dest_ip", "目的IP地址", "text", 0, 0, 0, 8, ""),
            ("dest_port", "目的端口号", "text", 0, 0, 0, 9, ""),
            ("transport_protocol", "数据传输协议", "text", 0, 0, 0, 10, ""),
            ("user_url", "用户访问URL", "text", 0, 0, 0, 11, ""),
            ("access_location", "接入位置", "text", 0, 0, 0, 12, ""),
            ("login_cell_id", "登录小区号", "text", 0, 0, 0, 13, ""),
            ("logout_cell_id", "下线小区号", "text", 0, 0, 0, 14, ""),
            ("base_station_id", "基站标识", "text", 0, 0, 0, 15, ""),
            ("visit_network_id", "拜访网络标识", "text", 0, 0, 0, 16, ""),
            ("network_type", "网络类型", "text", 0, 0, 0, 17, "字典: NETWORK_TYPE"),
            ("roam_flag", "用户漫游标志", "text", 0, 0, 0, 18, ""),
            ("slice_id", "网络切片选择辅助标识", "text", 0, 0, 0, 19, ""),
            ("start_time", "访问开始时间", "datetime", 1, 0, 0, 20, ""),
            ("end_time", "访问结束时间", "datetime", 1, 0, 0, 21, ""),
            ("visit_duration", "访问时长", "text", 0, 0, 0, 22, "秒"),
            ("send_bytes", "发送字节数", "text", 0, 0, 0, 23, ""),
            ("recv_bytes", "接收字节数", "text", 0, 0, 0, 24, ""),
            ("send_packets", "发送包数", "text", 0, 0, 0, 25, ""),
            ("recv_packets", "接收包数", "text", 0, 0, 0, 26, ""),
            ("pdu_session_id", "PDU会话标识", "text", 0, 0, 0, 27, ""),
            ("nat_device_id", "NAT设备标识", "text", 0, 0, 0, 28, ""),
            ("operator_id", "运营商标识", "text", 0, 0, 0, 29, ""),
            ("access_mode_5g", "5GSA/NSA接入标识", "text", 0, 0, 0, 30, ""),
            ("dnn", "DNN", "text", 0, 0, 0, 31, ""),
            ("collector_left_ip", "采集点左侧网元IP", "text", 0, 0, 0, 32, ""),
            ("collector_right_ip", "采集点右侧网元IP", "text", 0, 0, 0, 33, ""),
            ("protocol_type", "协议类型", "text", 0, 0, 0, 34, ""),
            ("business_type", "业务类型", "text", 0, 0, 0, 35, ""),
            ("http_method", "http请求类型", "text", 0, 0, 0, 36, ""),
            ("home_id", "归属地标识", "text", 0, 0, 0, 37, ""),
            ("link_access_id", "链接访问标识", "text", 0, 0, 0, 38, ""),
            ("vpn_id", "VPN标识", "text", 0, 0, 0, 39, ""),
            ("location_type", "位置区类型", "text", 0, 0, 0, 40, ""),
            ("location_id", "位置区标识", "text", 0, 0, 0, 41, ""),
            ("city_id", "城市编码", "text", 0, 0, 0, 42, "字典: CITY -> CITY_NAME"),
        ],
    },
    "家宽用户模板": {
        "scene_type": "家宽",
        "description": "家宽测试集(动态)字段模板 - SUBSCRIBERID/时间/IPV4/IPV6/NAT端口/CITY_ID等8字段",
        "fields": [
            ("subscriber_id", "用户标识SUBSCRIBERID", "text", 1, 1, 1, 1, "家宽用户唯一标识"),
            ("start_time", "开始时间BEGINTIME", "datetime", 1, 0, 0, 2, ""),
            ("end_time", "结束时间ENDTIME", "datetime", 1, 0, 0, 3, ""),
            ("ipv4_address", "IPv4地址", "text", 1, 0, 0, 4, ""),
            ("ipv6_address", "IPv6地址", "text", 0, 0, 0, 5, ""),
            ("nat_begin_port", "NAT起始端口", "text", 0, 0, 0, 6, ""),
            ("nat_end_port", "NAT终止端口", "text", 0, 0, 0, 7, ""),
            ("city_id", "城市编码CITY_ID", "text", 1, 0, 0, 8, "字典: CITY -> CITY_NAME"),
        ],
    },
    "信安系统模板": {
        "scene_type": "专线",
        "description": "信安系统测试集(静态)字段模板 - IDC/ISP许可证/单位/责任人/机房/IP等28字段",
        "fields": [
            ("isp_license", "IDC/ISP许可证号", "text", 1, 0, 0, 1, "必填"),
            ("unit_name", "单位名称", "text", 1, 0, 0, 2, "必填"),
            ("unit_attr", "单位属性", "text", 1, 0, 0, 3, "字典: UNIT_ATTR"),
            ("cert_type", "证件类型", "text", 1, 0, 0, 4, "字典: CERT_TYPE"),
            ("cert_no", "证件号码", "text", 1, 0, 0, 5, "必填"),
            ("postal_code", "邮政编码", "text", 0, 0, 0, 6, "选填"),
            ("register_time", "注册时间", "datetime", 1, 0, 0, 7, "必填"),
            ("service_open_time", "服务开通时间", "datetime", 1, 0, 0, 8, "必填"),
            ("unit_address", "单位地址", "text", 1, 0, 0, 9, "必填"),
            ("security_person_name", "信息安全责任人-姓名", "text", 1, 1, 1, 10, "必填,敏感"),
            ("security_person_cert_type", "信息安全责任人-证件类型", "text", 1, 0, 0, 11, "必填"),
            ("security_person_cert_no", "信息安全责任人-证件号码", "text", 1, 1, 1, 12, "必填,敏感"),
            ("security_person_phone", "信息安全责任人-固定电话", "text", 1, 0, 0, 13, "必填"),
            ("security_person_mobile", "信息安全责任人-移动电话", "text", 1, 1, 1, 14, "必填,敏感"),
            ("security_person_email", "信息安全责任人-Email", "text", 1, 0, 0, 15, "必填"),
            ("user_remark", "用户备注信息", "text", 0, 0, 0, 16, "选填"),
            ("machine_room", "所属机房", "text", 1, 0, 0, 17, "必填"),
            ("machine_room_area", "机房区域名称", "text", 1, 0, 0, 18, "必填"),
            ("rack_name", "机柜名称", "text", 0, 0, 0, 19, "选填"),
            ("resource_alloc_time", "资源分配时间", "datetime", 1, 0, 0, 20, "必填"),
            ("ip_type_code", "IP类型", "text", 1, 0, 0, 21, "必填"),
            ("public_ip_start", "外网起始IP", "text", 1, 0, 0, 22, "必填"),
            ("public_ip_end", "外网终止IP", "text", 1, 0, 0, 23, "必填"),
            ("network_bandwidth", "网络带宽", "text", 0, 0, 0, 24, "选填"),
            ("region_code", "所属区域", "text", 1, 0, 0, 25, "必填"),
            ("app_service_type", "应用服务类型", "text", 1, 0, 0, 26, "字典: APP_SERVICE_TYPE"),
            ("business_type", "业务类型", "text", 1, 0, 0, 27, "字典: BUSINESS_TYPE"),
            ("link_info", "用户使用链路信息", "text", 0, 0, 0, 28, "选填"),
        ],
    },
    "综资系统模板": {
        "scene_type": "专线",
        "description": "综资测试集(静态)字段模板 - IPv4/单位/联系人/网关/业务/设备等31字段",
        "fields": [
            ("ip_address", "IPv4地址名称", "text", 1, 0, 0, 1, ""),
            ("is_pro_company", "是否是专业公司", "text", 0, 0, 0, 2, ""),
            ("pro_company_name", "专业公司名称", "text", 0, 0, 0, 3, ""),
            ("unit_name", "单位名称/具体业务信息", "text", 0, 0, 0, 4, ""),
            ("unit_category", "单位所属分类", "text", 0, 0, 0, 5, ""),
            ("unit_nature", "单位性质", "text", 0, 0, 0, 6, ""),
            ("region_code", "所属地市", "text", 0, 0, 0, 7, "字典: CITY"),
            ("machine_room_area", "所属区县", "text", 0, 0, 0, 8, ""),
            ("unit_admin_level", "单位行政级别", "text", 0, 0, 0, 9, ""),
            ("unit_industry", "单位所属行业分类", "text", 0, 0, 0, 10, ""),
            ("unit_address", "地址详细地址", "text", 0, 0, 0, 11, ""),
            ("contact_person_client", "联系人姓名(客户侧)", "text", 0, 1, 1, 12, "敏感"),
            ("contact_phone_client", "联系人电话(客户侧)", "text", 0, 1, 1, 13, "敏感"),
            ("contact_email_client", "联系人邮箱(客户侧)", "text", 0, 0, 0, 14, ""),
            ("gateway_location", "网关物理位置", "text", 0, 0, 0, 15, ""),
            ("use_mode", "使用方式", "text", 0, 0, 0, 16, ""),
            ("gateway_ip", "网关IP地址", "text", 0, 0, 0, 17, ""),
            ("business_type", "业务类型", "text", 0, 0, 0, 18, "字典: BUSINESS_TYPE"),
            ("device_status", "使用状态", "text", 0, 0, 0, 19, ""),
            ("manage_status", "管理状态", "text", 0, 0, 0, 20, ""),
            ("device_room", "设备所属机房", "text", 0, 0, 0, 21, ""),
            ("loopback_ip", "Loopbak地址", "text", 0, 0, 0, 22, ""),
            ("resp_dept", "负责部门(移动侧)", "text", 0, 0, 0, 23, ""),
            ("resp_person_name", "负责人姓名(移动侧)", "text", 0, 0, 0, 24, ""),
            ("resp_person_phone", "负责人电话(移动侧)", "text", 0, 1, 1, 25, "敏感"),
            ("resp_person_email", "负责人邮箱(移动侧)", "text", 0, 0, 0, 26, ""),
            ("unit_cert_type", "单位证件类型", "text", 0, 0, 0, 27, "字典: CERT_TYPE"),
            ("unit_cert_no", "单位证件号码", "text", 0, 0, 0, 28, ""),
            ("address_type", "地址类型", "text", 0, 0, 0, 29, ""),
            ("product_instance_id", "产品实例标识", "text", 0, 0, 0, 30, ""),
            ("device_id", "所属设备", "text", 0, 0, 0, 31, ""),
            ("change_time", "变更时间", "datetime", 0, 0, 0, 32, ""),
        ],
    },
}


def cleanup_and_rebuild():
    with get_conn() as conn:
        # 1. 删除 ip_subjects 中的模拟样本数据 (source_subtype IS NULL)
        deleted_subjects = conn.execute("DELETE FROM ip_subjects WHERE source_subtype IS NULL").rowcount
        print(f"[1] 删除 ip_subjects 模拟样本: {deleted_subjects} 条")

        # 2. 删除所有"测试模板T"重复测试模板
        test_tpl_ids = [r["id"] for r in conn.execute("SELECT id FROM subject_templates WHERE name='测试模板T'").fetchall()]
        if test_tpl_ids:
            placeholders = ",".join(["?"] * len(test_tpl_ids))
            conn.execute(f"DELETE FROM subject_template_fields WHERE template_id IN ({placeholders})", test_tpl_ids)
            conn.execute(f"DELETE FROM subject_templates WHERE id IN ({placeholders})", test_tpl_ids)
        print(f"[2] 删除测试模板T: {len(test_tpl_ids)} 个")

        # 3. 删除所有现有主体模板及其字段(模拟字段或旧真实字段), 重建为真实数据源字段
        all_tpl_ids = [r["id"] for r in conn.execute("SELECT id FROM subject_templates").fetchall()]
        if all_tpl_ids:
            placeholders = ",".join(["?"] * len(all_tpl_ids))
            conn.execute(f"DELETE FROM subject_template_fields WHERE template_id IN ({placeholders})", all_tpl_ids)
            conn.execute(f"DELETE FROM subject_templates WHERE id IN ({placeholders})", all_tpl_ids)
        print(f"[3] 删除旧主体模板: {len(all_tpl_ids)} 个")

        # 4. 重建基于真实数据源字段的主体模板
        new_tpl_count = 0
        new_field_count = 0
        for tpl_name, cfg in REAL_TEMPLATES.items():
            tpl_id = gen_id("tpl_")
            conn.execute(
                "INSERT INTO subject_templates (id, name, description, scene_type, created_at, updated_at) VALUES (?,?,?,?,?,?)",
                (tpl_id, tpl_name, cfg["description"], cfg["scene_type"], now_str(), now_str()),
            )
            new_tpl_count += 1
            for f in cfg["fields"]:
                # field_name, field_label, field_type, is_required, is_encrypted, is_sensitive, field_order, description
                conn.execute(
                    "INSERT INTO subject_template_fields (id, template_id, field_name, field_label, field_type, is_required, is_encrypted, is_sensitive, field_order, description) VALUES (?,?,?,?,?,?,?,?,?,?)",
                    (gen_id("fld_"), tpl_id, *f),
                )
                new_field_count += 1
        print(f"[4] 重建主体模板: {new_tpl_count} 个, 字段: {new_field_count} 条")

        # 5. data_sources 表新增 template_id 字段(如果不存在)
        cols = [c["name"] for c in conn.execute("PRAGMA table_info(data_sources)").fetchall()]
        if "template_id" not in cols:
            conn.execute("ALTER TABLE data_sources ADD COLUMN template_id TEXT")
            print("[5] data_sources 表新增 template_id 字段")
        else:
            print("[5] data_sources.template_id 字段已存在")

        # 6. 为现有数据源关联主体模板
        ds_tpl_map = {
            "移网AAA数据源": "移网用户模板",
            "家宽BRAS数据源": "家宽用户模板",
            "专线资源系统": "综资系统模板",
            "IDC资产系统": "信安系统模板",
            "自有业务平台": "综资系统模板",
        }
        linked = 0
        for ds_name, tpl_name in ds_tpl_map.items():
            tpl = conn.execute("SELECT id FROM subject_templates WHERE name=?", (tpl_name,)).fetchone()
            if tpl:
                conn.execute("UPDATE data_sources SET template_id=? WHERE name=?", (tpl["id"], ds_name))
                linked += 1
        print(f"[6] 数据源关联主体模板: {linked} 个")

        # 7. 验证
        print("\n=== 验证结果 ===")
        print("ip_subjects 总数:", conn.execute("SELECT COUNT(*) FROM ip_subjects").fetchone()[0])
        for r in conn.execute("SELECT source_subtype, COUNT(*) as c FROM ip_subjects GROUP BY source_subtype"):
            print(f"  {r['source_subtype']}: {r['c']} 条")
        print("\n主体模板列表:")
        for r in conn.execute("SELECT name, scene_type FROM subject_templates ORDER BY created_at"):
            print(f"  {r['name']} ({r['scene_type']})")
        print("\n数据源-模板关联:")
        for r in conn.execute("SELECT ds.name, ds.source_type, t.name as tpl_name FROM data_sources ds LEFT JOIN subject_templates t ON ds.template_id=t.id"):
            print(f"  {r['name']} [{r['source_type']}] -> {r['tpl_name'] or '未关联'}")


if __name__ == "__main__":
    cleanup_and_rebuild()
    print("\n清理与重建完成!")
