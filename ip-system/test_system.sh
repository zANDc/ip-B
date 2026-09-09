#!/bin/bash
# Comprehensive system test for IP Address Query Calibration System
# Covers all test items from Appendix 2 of the test plan

BASE=${BASE_URL:-http://localhost:5001}
TOKEN=""
PASS=0
FAIL=0
FAILED_ITEMS=""

log_pass() { PASS=$((PASS+1)); echo "[PASS] $1"; }
log_fail() { FAIL=$((FAIL+1)); FAILED_ITEMS="${FAILED_ITEMS}\n$1"; echo "[FAIL] $1"; }

auth_req() {
    local method=$1 url=$2 data=$3
    if [ -z "$data" ]; then
        curl -s -X "$method" "$BASE$url" -H "Authorization: $TOKEN" -H "Content-Type: application/json"
    else
        curl -s -X "$method" "$BASE$url" -H "Authorization: $TOKEN" -H "Content-Type: application/json" -d "$data"
    fi
}

echo "=========================================="
echo "  IP地址查询校准系统 - 综合测试"
echo "=========================================="

# ============ 1. 登录认证 ============
echo ""
echo ">>> 1. 登录认证"
RESP=$(curl -s -X POST "$BASE/api/login" -H "Content-Type: application/json" -d '{"username":"admin","password":"admin123"}')
TOKEN=$(echo "$RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('token',''))")
if [ -n "$TOKEN" ]; then log_pass "1.1 用户登录"; else log_fail "1.1 用户登录"; exit 1; fi

RESP=$(curl -s -X POST "$BASE/api/login" -H "Content-Type: application/json" -d '{"username":"admin","password":"wrong"}')
if echo "$RESP" | grep -q "detail"; then log_pass "1.2 错误密码拒绝"; else log_fail "1.2 错误密码拒绝"; fi

# ============ 2. IP主体定位查询能力 ============
echo ""
echo ">>> 2. IP主体定位查询能力"
RESP=$(auth_req POST "/api/query/tasks" '{"ip_address":"192.168.1.100","start_time":"2025-01-01 00:00:00","end_time":"2025-12-31 23:59:59"}')
if echo "$RESP" | grep -q "task_id"; then log_pass "2.1 IP主体信息查询(IPv4)"; else log_fail "2.1 IP主体信息查询(IPv4)"; fi

RESP=$(auth_req POST "/api/query/tasks" '{"ip_address":"2001:db8::1","start_time":"2025-01-01 00:00:00","end_time":"2025-12-31 23:59:59"}')
if echo "$RESP" | grep -q "task_id"; then log_pass "2.2 IP主体信息查询(IPv6)"; else log_fail "2.2 IP主体信息查询(IPv6)"; fi

RESP=$(auth_req GET "/api/query/tasks?page=1&page_size=10")
if echo "$RESP" | grep -q "total\|data"; then log_pass "2.3 任务列表多维查询"; else log_fail "2.3 任务列表多维查询"; fi

TASK_ID=$(echo "$RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['data'][0]['id'] if d.get('data') else '')" 2>/dev/null)
if [ -n "$TASK_ID" ]; then
    RESP=$(auth_req GET "/api/query/tasks/$TASK_ID")
    if echo "$RESP" | grep -q "task\|results"; then log_pass "2.4 查询任务详情"; else log_fail "2.4 查询任务详情"; fi
    RESP=$(auth_req GET "/api/query/tasks/$TASK_ID/path")
    if echo "$RESP" | grep -q "paths\|task"; then log_pass "2.5 路径回放"; else log_fail "2.5 路径回放"; fi
    RESP=$(auth_req GET "/api/query/tasks/$TASK_ID/detail")
    if echo "$RESP" | grep -q "details\|results"; then log_pass "2.6 定位详情(溯源字段)"; else log_fail "2.6 定位详情(溯源字段)"; fi
fi

# ============ 3. 数据源管理 ============
echo ""
echo ">>> 3. 数据源管理"
RESP=$(auth_req GET "/api/datasources")
if echo "$RESP" | grep -q "id\|\["; then log_pass "3.1 数据源列表"; else log_fail "3.1 数据源列表"; fi

RESP=$(auth_req POST "/api/datasources" '{"name":"测试数据源T","source_type":"移网","authority_level":"高","owner":"张三","contact":"13800000000","description":"测试"}')
DS_ID=$(echo "$RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('id',''))" 2>/dev/null)
if [ -n "$DS_ID" ]; then log_pass "3.2 新增数据源"; else log_fail "3.2 新增数据源"; fi

if [ -n "$DS_ID" ]; then
    RESP=$(auth_req PUT "/api/datasources/$DS_ID" '{"name":"测试数据源T-改","source_type":"移网","authority_level":"高","owner":"张三","description":"已修改"}')
    if echo "$RESP" | grep -q "id\|message\|success"; then log_pass "3.3 修改数据源"; else log_fail "3.3 修改数据源"; fi
    RESP=$(auth_req DELETE "/api/datasources/$DS_ID")
    if echo "$RESP" | grep -q "message\|success\|{}"; then log_pass "3.4 删除数据源"; else log_fail "3.4 删除数据源"; fi
fi

# ============ 4. 主体信息模板管理 ============
echo ""
echo ">>> 4. 主体信息模板管理"
RESP=$(auth_req GET "/api/templates")
if echo "$RESP" | grep -q "id\|\["; then log_pass "4.1 模板列表"; else log_fail "4.1 模板列表"; fi

RESP=$(auth_req POST "/api/templates" '{"name":"测试模板T","description":"测试","scene_type":"移网","fields":[{"field_name":"test_field","field_label":"测试字段","field_type":"string","is_required":1,"is_encrypted":0,"is_sensitive":0,"field_order":1,"description":"测试"}]}')
TPL_ID=$(echo "$RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('id',''))" 2>/dev/null)
if [ -n "$TPL_ID" ]; then log_pass "4.2 新增模板(含字段)"; else log_fail "4.2 新增模板(含字段)"; fi

if [ -n "$TPL_ID" ]; then
    RESP=$(auth_req GET "/api/templates/$TPL_ID")
    if echo "$RESP" | grep -q "id\|name"; then log_pass "4.3 模板详情"; else log_fail "4.3 模板详情"; fi
fi

# ============ 5. 场景与路径管理 ============
echo ""
echo ">>> 5. 场景与路径管理"
RESP=$(auth_req GET "/api/scenes")
if echo "$RESP" | grep -q "id\|\["; then log_pass "5.1 场景列表"; else log_fail "5.1 场景列表"; fi

SCENE_ID=$(echo "$RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['data'][0]['id'] if d.get('data') else '')" 2>/dev/null)
if [ -n "$SCENE_ID" ]; then
    RESP=$(auth_req GET "/api/scenes/$SCENE_ID/paths")
    if echo "$RESP" | grep -q "nodes"; then log_pass "5.2 场景查询路径列表"; else log_fail "5.2 场景查询路径列表"; fi
    # Get a data source id for the path node binding
    DS_RESP=$(auth_req GET "/api/datasources?page=1&page_size=1")
    DS_ID=$(echo "$DS_RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['data'][0]['id'] if d.get('data') else '')" 2>/dev/null)
    # Create a visual path: start -> exec(ds) -> judge -> end (with branch labels)
    RESP=$(auth_req POST "/api/scenes/$SCENE_ID/paths" "{\"name\":\"测试路径T\",\"nodes\":\"[{\\\"id\\\":\\\"s1\\\",\\\"type\\\":\\\"start\\\",\\\"name\\\":\\\"开始\\\",\\\"x\\\":40,\\\"y\\\":100},{\\\"id\\\":\\\"e1\\\",\\\"type\\\":\\\"execute\\\",\\\"name\\\":\\\"查询数据源\\\",\\\"x\\\":260,\\\"y\\\":100,\\\"data_source_id\\\":\\\"$DS_ID\\\"},{\\\"id\\\":\\\"j1\\\",\\\"type\\\":\\\"judge\\\",\\\"name\\\":\\\"是否命中\\\",\\\"x\\\":480,\\\"y\\\":100,\\\"condition\\\":\\\"是否命中\\\"},{\\\"id\\\":\\\"r1\\\",\\\"type\\\":\\\"execute\\\",\\\"name\\\":\\\"返回结果\\\",\\\"x\\\":700,\\\"y\\\":100}]\",\"edges\":\"[{\\\"from\\\":\\\"s1\\\",\\\"to\\\":\\\"e1\\\"},{\\\"from\\\":\\\"e1\\\",\\\"to\\\":\\\"j1\\\"},{\\\"from\\\":\\\"j1\\\",\\\"to\\\":\\\"r1\\\",\\\"label\\\":\\\"命中\\\"},{\\\"from\\\":\\\"j1\\\",\\\"to\\\":\\\"r1\\\",\\\"label\\\":\\\"未命中\\\"}]\"}")
    PATH_ID=$(echo "$RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('id',''))" 2>/dev/null)
    if [ -n "$PATH_ID" ]; then log_pass "5.3 新增场景查询路径(含节点/连线/分支)"; else log_fail "5.3 新增场景查询路径(含节点/连线/分支)"; fi
    if [ -n "$PATH_ID" ]; then
        RESP=$(auth_req PUT "/api/scenes/$SCENE_ID/paths/$PATH_ID/publish")
        if echo "$RESP" | grep -q "message\|success\|status"; then log_pass "5.4 路径发布生效"; else log_fail "5.4 路径发布生效"; fi
    fi
fi

# ============ 6. 冲突工单管理 ============
echo ""
echo ">>> 6. 冲突工单管理"
RESP=$(auth_req GET "/api/conflicts")
if echo "$RESP" | grep -q "total\|data"; then log_pass "6.1 冲突工单列表"; else log_fail "6.1 冲突工单列表"; fi

RESP=$(auth_req POST "/api/conflicts" '{"ip_address":"192.168.1.100","conflict_type":"字段冲突","conflict_desc":"测试冲突","field_name":"user_name","source_values":"[{\"source\":\"源A\",\"value\":\"张三\"}]","suggestion":"请核实"}')
CT_ID=$(echo "$RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('id',''))" 2>/dev/null)
if [ -n "$CT_ID" ]; then log_pass "6.2 新增冲突工单"; else log_fail "6.2 新增冲突工单"; fi

if [ -n "$CT_ID" ]; then
    RESP=$(auth_req GET "/api/conflicts/$CT_ID")
    if echo "$RESP" | grep -q "id\|ticket_no"; then log_pass "6.3 工单详情"; else log_fail "6.3 工单详情"; fi
    RESP=$(auth_req GET "/api/conflicts/$CT_ID/lifecycle")
    if echo "$RESP" | grep -q "lifecycle\|ticket"; then log_pass "6.4 工单生命周期"; else log_fail "6.4 工单生命周期"; fi
    RESP=$(auth_req PUT "/api/conflicts/$CT_ID/process" '{"action":"verify","handle_remark":"已处理","handle_evidence":"证据材料"}')
    if echo "$RESP" | grep -q "status\|lifecycle\|message"; then log_pass "6.5 处理工单"; else log_fail "6.5 处理工单"; fi
fi

# ============ 7. 批量查询与人工修正 ============
echo ""
echo ">>> 7. 批量查询与人工修正"
CODE=$(curl -s -o /dev/null -w "%{http_code}" "$BASE/api/query/batch/template" -H "Authorization: $TOKEN")
if [ "$CODE" = "200" ]; then log_pass "7.1 下载批量查询模板"; else log_fail "7.1 下载批量查询模板 code=$CODE"; fi

python3 -c "
from openpyxl import Workbook
wb = Workbook()
ws = wb.active
ws.append(['序号','IP地址','IP版本','端口','开始时间','结束时间','场景类型'])
ws.append([1,'10.0.0.99','IPv4','','2025-01-01 00:00:00','2025-12-31 23:59:59','移网'])
wb.save('/tmp/test_batch.xlsx')
"
RESP=$(curl -s -X POST "$BASE/api/query/batch/import" -H "Authorization: $TOKEN" -F "file=@/tmp/test_batch.xlsx")
if echo "$RESP" | grep -q "batch_id\|total"; then log_pass "7.2 批量导入查询"; else log_fail "7.2 批量导入查询"; fi

RESP=$(auth_req POST "/api/query/manual-fix" '{"ip_address":"192.168.1.100","field_name":"user_name","field_value":"测试用户","reason":"数据错误"}')
if echo "$RESP" | grep -q "ticket_no\|success"; then log_pass "7.3 人工修正"; else log_fail "7.3 人工修正"; fi

RESP=$(auth_req POST "/api/query/approval/request" '{"target_ip":"192.168.1.100","target_field":"phone","approver":"admin","applicant":"admin"}')
if echo "$RESP" | grep -q "id\|approval\|success\|message"; then log_pass "7.4 敏感信息审批申请"; else log_fail "7.4 敏感信息审批申请"; fi

# ============ 8. 日志管理 ============
echo ""
echo ">>> 8. 日志管理"
RESP=$(auth_req GET "/api/logs")
if echo "$RESP" | grep -q "id\|\["; then log_pass "8.1 操作日志列表"; else log_fail "8.1 操作日志列表"; fi

# ============ 9. 安全配置 ============
echo ""
echo ">>> 9. 安全配置"
RESP=$(auth_req GET "/api/security/config")
if echo "$RESP" | grep -q "data\|config"; then log_pass "9.1 安全配置查询"; else log_fail "9.1 安全配置查询"; fi

RESP=$(auth_req PUT "/api/security/config" '{"config_key":"password_min_length","config_value":"8"}')
if echo "$RESP" | grep -q "message\|success"; then log_pass "9.2 修改安全配置"; else log_fail "9.2 修改安全配置"; fi

RESP=$(auth_req GET "/api/security/ip-access")
if echo "$RESP" | grep -q "data\|default"; then log_pass "9.3 IP访问规则列表"; else log_fail "9.3 IP访问规则列表"; fi

RESP=$(auth_req POST "/api/security/ip-access" '{"ip_segment":"192.168.1.0/24","description":"测试网段"}')
if echo "$RESP" | grep -q "id\|message"; then log_pass "9.4 新增IP访问规则"; else log_fail "9.4 新增IP访问规则"; fi

# ============ 10. 用户管理 ============
echo ""
echo ">>> 10. 用户管理"
RESP=$(auth_req GET "/api/users")
if echo "$RESP" | grep -q "id\|username"; then log_pass "10.1 用户列表"; else log_fail "10.1 用户列表"; fi

# ============ 11. 仪表盘 ============
echo ""
echo ">>> 11. 仪表盘统计"
RESP=$(auth_req GET "/api/dashboard/stats")
if echo "$RESP" | grep -q "task_count\|datasource_count"; then log_pass "11.1 仪表盘统计"; else log_fail "11.1 仪表盘统计"; fi

# ============ 12. 导出功能 ============
echo ""
echo ">>> 12. 导出功能"
CODE=$(curl -s -o /dev/null -w "%{http_code}" "$BASE/api/export/subjects" -H "Authorization: $TOKEN")
if [ "$CODE" = "200" ]; then log_pass "12.1 导出主体信息"; else log_fail "12.1 导出主体信息 code=$CODE"; fi

CODE=$(curl -s -o /dev/null -w "%{http_code}" "$BASE/api/export/conflicts" -H "Authorization: $TOKEN")
if [ "$CODE" = "200" ]; then log_pass "12.2 导出冲突工单"; else log_fail "12.2 导出冲突工单 code=$CODE"; fi

CODE=$(curl -s -o /dev/null -w "%{http_code}" "$BASE/api/export/logs" -H "Authorization: $TOKEN")
if [ "$CODE" = "200" ]; then log_pass "12.3 导出操作日志"; else log_fail "12.3 导出操作日志 code=$CODE"; fi

# ============ 13. 前端页面 ============
echo ""
echo ">>> 13. 前端页面"
CODE=$(curl -s -o /dev/null -w "%{http_code}" "$BASE/")
if [ "$CODE" = "200" ]; then log_pass "13.1 首页加载"; else log_fail "13.1 首页加载 code=$CODE"; fi
CODE=$(curl -s -o /dev/null -w "%{http_code}" "$BASE/static/app.js")
if [ "$CODE" = "200" ]; then log_pass "13.2 静态资源加载"; else log_fail "13.2 静态资源加载 code=$CODE"; fi

# ============ Summary ============
echo ""
echo "=========================================="
echo "  测试总结: 通过 $PASS 项, 失败 $FAIL 项"
echo "=========================================="
if [ $FAIL -gt 0 ]; then
    echo -e "失败项:$FAILED_ITEMS"
fi
