const { createApp, ref, reactive, onMounted, computed, nextTick } = Vue;
const { ElMessage, ElMessageBox } = ElementPlus;

const app = createApp({
    setup() {
        const API = (url, options = {}) => {
            const token = localStorage.getItem('token');
            return fetch(url, {
                ...options,
                headers: { 'Content-Type': 'application/json', ...(token ? { 'Authorization': token } : {}), ...options.headers },
                body: options.body ? (typeof options.body === 'string' ? options.body : JSON.stringify(options.body)) : undefined,
            }).then(async res => {
                if (res.status === 401) { localStorage.removeItem('token'); location.reload(); }
                const data = await res.json();
                if (!res.ok) throw new Error(data.detail || '请求失败');
                return data;
            });
        };

        // Auth
        const token = ref(localStorage.getItem('token'));
        const loginForm = reactive({ username: 'admin', password: 'admin123' });
        const currentUser = ref({});
        const handleLogin = async () => {
            try {
                const res = await API('/api/login', { method: 'POST', body: JSON.stringify(loginForm) });
                token.value = res.token; currentUser.value = res.user;
                localStorage.setItem('token', res.token);
                localStorage.setItem('user', JSON.stringify(res.user));
                ElMessage.success('登录成功');
                loadDashboard();
            } catch(e) { ElMessage.error(e.message); }
        };
        const logout = () => { localStorage.clear(); token.value = null; };

        // Navigation
        const activeMenu = ref('dashboard');
        const menuTitles = {
            'dashboard': '系统首页', 'query-create': 'IP主体信息查询', 'query-list': '任务列表查询', 'query-batch': '批量导入查询',
            'datasource': '数据源管理', 'template': '主体信息管理', 'scene': '场景路径管理',
            'conflict': '冲突工单检测', 'log': '日志管理', 'security': '安全配置'
        };
        const pageTitle = computed(() => menuTitles[activeMenu.value] || '');
        const handleMenuSelect = (key) => {
            activeMenu.value = key;
            if (key === 'dashboard') loadDashboard();
            if (key === 'query-list') loadTasks(1);
            if (key === 'query-batch') { /* ready */ }
            if (key === 'datasource') loadDataSources(1);
            if (key === 'template') loadTemplates(1);
            if (key === 'scene') loadScenes(1);
            if (key === 'conflict') loadConflicts(1);
            if (key === 'log') loadLogs(1);
            if (key === 'security') loadSecurityConfig();
        };

        // Dashboard
        const stats = ref({});
        const dashboardCards = computed(() => [
            { title: '查询任务', value: stats.value.task_count || 0, icon: 'Search', color: '#409EFF' },
            { title: '数据源', value: stats.value.datasource_count || 0, icon: 'Coin', color: '#67C23A' },
            { title: '待处理工单', value: stats.value.conflict_open || 0, icon: 'Warning', color: '#E6A23C' },
            { title: 'IP主体数据', value: stats.value.ip_subject_count || 0, icon: 'DataAnalysis', color: '#F56C6C' },
        ]);
        const loadDashboard = async () => {
            try { stats.value = await API('/api/dashboard/stats'); } catch(e) { console.error(e); }
        };

        // IP Query
        const queryForm = reactive({ ip_address: '', ip_version: '', port: '', start_time: '', end_time: '', scene_type: '' });
        const queryRules = {
            ip_address: [{ required: true, message: '请输入IP地址', trigger: 'blur' }],
            start_time: [{ required: true, message: '请选择开始时间', trigger: 'change' }],
            end_time: [{ required: true, message: '请选择结束时间', trigger: 'change' }],
        };
        const queryLoading = ref(false);
        const queryResult = ref(null);
        const showPathReplay = ref(false);

        const handleQuery = async () => {
            if (!queryForm.ip_address) { ElMessage.warning('请输入IP地址'); return; }
            if (!queryForm.start_time || !queryForm.end_time) { ElMessage.warning('请选择时间范围'); return; }
            queryLoading.value = true;
            try {
                queryResult.value = await API('/api/query/tasks', { method: 'POST', body: queryForm });
                showPathReplay.value = true;
                ElMessage.success(`查询完成，共${queryResult.value.count}条结果`);
            } catch(e) { ElMessage.error(e.message); }
            queryLoading.value = false;
        };
        const viewPathReplay = () => { showPathReplay.value = !showPathReplay.value; };

        // Manual Fix
        const showManualFixDialog = ref(false);
        const manualFixForm = reactive({ ip_address: '', field_name: 'user_name', field_value: '', reason: '' });
        const showManualFix = (row) => { manualFixForm.ip_address = row.ip_address; manualFixForm.field_value = ''; manualFixForm.reason = ''; showManualFixDialog.value = true; };
        const submitManualFix = async () => {
            try {
                await API('/api/query/manual-fix', { method: 'POST', body: manualFixForm });
                ElMessage.success('修正已提交，已生成用户修正冲突工单');
                showManualFixDialog.value = false;
                loadConflicts(1);
            } catch(e) { ElMessage.error(e.message); }
        };

        // Sensitive Info
        const showSensitiveDialog = ref(false);
        const sensitiveForm = reactive({ target_ip: '', target_field: 'user_name', approver: '' });
        const sensitiveResult = ref(null);
        const sensitiveVerifyCode = ref('');
        const showSensitive = () => {
            sensitiveForm.target_ip = queryResult.value?.results?.[0]?.ip_address || '';
            sensitiveResult.value = null;
            sensitiveVerifyCode.value = '';
            showSensitiveDialog.value = true;
        };
        const requestSensitiveApproval = async () => {
            try {
                sensitiveResult.value = await API('/api/query/approval/request', { method: 'POST', body: sensitiveForm });
                ElMessage.success('验证码已发送');
            } catch(e) { ElMessage.error(e.message); }
        };
        const verifySensitiveApproval = async () => {
            try {
                const res = await API('/api/query/approval/verify', { method: 'POST', body: { approval_id: sensitiveResult.value.approval_id, verify_code: sensitiveVerifyCode.value } });
                ElMessage.success(`验证通过: ${res.field} = ${res.plain_value}`);
                showSensitiveDialog.value = false;
            } catch(e) { ElMessage.error(e.message); }
        };

        // Location Detail
        const showLocationDialog = ref(false);
        const locationDetail = ref(null);
        const showLocationDetail = (row) => {
            locationDetail.value = {
                field_name: 'IP地址', trace_value: row.ip_address, data_source: row.data_source,
                location: row.location, access_node: row.access_node, ip_type: row.ip_type,
                scene_type: row.scene_type, raw_data: row.raw_data
            };
            showLocationDialog.value = true;
        };

        // Task List
        const taskQuery = reactive({ ip_address: '', ip_version: '', scene_type: '', task_name: '', status: '' });
        const taskList = ref([]);
        const taskPage = ref(1);
        const taskTotal = ref(0);
        const loadTasks = async (page) => {
            taskPage.value = page;
            const params = new URLSearchParams({ page, page_size: 10, ...Object.fromEntries(Object.entries(taskQuery).filter(([_,v]) => v)) });
            try { const res = await API('/api/query/tasks?' + params); taskList.value = res.data; taskTotal.value = res.total; } catch(e) { ElMessage.error(e.message); }
        };
        const resetTaskQuery = () => { Object.keys(taskQuery).forEach(k => taskQuery[k] = ''); loadTasks(1); };

        // Task Detail Dialogs
        const showTaskResultDialog = ref(false);
        const showTaskPathDialog = ref(false);
        const taskDetail = ref(null);
        const viewTaskResult = async (row) => {
            try { taskDetail.value = await API('/api/query/tasks/' + row.id); showTaskResultDialog.value = true; } catch(e) { ElMessage.error(e.message); }
        };
        const viewTaskPath = async (row) => {
            try { taskDetail.value = await API('/api/query/tasks/' + row.id + '/path'); showTaskPathDialog.value = true; } catch(e) { ElMessage.error(e.message); }
        };
        const viewTaskDetail = async (row) => {
            try { const res = await API('/api/query/tasks/' + row.id + '/detail'); taskDetail.value = res; showTaskResultDialog.value = true; } catch(e) { ElMessage.error(e.message); }
        };

        // Batch Import
        const batchResult = ref(null);
        const downloadTemplate = () => { window.open('/api/query/batch/template'); };
        const beforeBatchUpload = (file) => {
            if (file.size > 5*1024*1024) { ElMessage.error('文件大小超出限制(最大5MB)'); return false; }
            if (!file.name.endsWith('.xlsx')) { ElMessage.error('仅支持xlsx格式'); return false; }
            return true;
        };
        const handleBatchUpload = async (options) => {
            const formData = new FormData();
            formData.append('file', options.file);
            try {
                const res = await fetch('/api/query/batch/import', { method: 'POST', body: formData });
                batchResult.value = await res.json();
                ElMessage.success(`批量导入成功，共${batchResult.value.total}个IP`);
            } catch(e) { ElMessage.error('导入失败'); }
        };
        const viewBatchTask = (row) => { /* navigate to task */ activeMenu.value = 'query-list'; loadTasks(1); };

        // Data Sources
        const dsQuery = reactive({ name: '', source_type: '', authority_level: '' });
        const dsList = ref([]);
        const dsPage = ref(1);
        const dsTotal = ref(0);
        const loadDataSources = async (page) => {
            dsPage.value = page;
            const params = new URLSearchParams({ page, page_size: 10, ...Object.fromEntries(Object.entries(dsQuery).filter(([_,v]) => v)) });
            try { const res = await API('/api/datasources?' + params); dsList.value = res.data; dsTotal.value = res.total; } catch(e) { ElMessage.error(e.message); }
        };
        const resetDsQuery = () => { Object.keys(dsQuery).forEach(k => dsQuery[k] = ''); loadDataSources(1); };
        const showDsDialog = ref(false);
        const dsForm = reactive({ id: '', name: '', source_type: '移网', authority_level: '高', owner: '', contact: '', description: '', alarm_enabled: 0, config_attrs: '{}' });
        const openDataSourceDialog = (row) => {
            if (row) { Object.keys(dsForm).forEach(k => dsForm[k] = row[k]); } else { Object.assign(dsForm, { id: '', name: '', source_type: '移网', authority_level: '高', owner: '', contact: '', description: '', alarm_enabled: 0, config_attrs: '{}' }); }
            showDsDialog.value = true;
        };
        const saveDataSource = async () => {
            try {
                if (dsForm.id) { await API('/api/datasources/' + dsForm.id, { method: 'PUT', body: dsForm }); }
                else { await API('/api/datasources', { method: 'POST', body: dsForm }); }
                ElMessage.success('保存成功'); showDsDialog.value = false; loadDataSources(dsPage.value);
            } catch(e) { ElMessage.error(e.message); }
        };
        const deleteDataSource = async (row) => {
            try { await ElMessageBox.confirm('确认删除?', '提示', { type: 'warning' }); await API('/api/datasources/' + row.id, { method: 'DELETE' }); ElMessage.success('删除成功'); loadDataSources(dsPage.value); } catch(e) {}
        };
        const showDsDetailDialog = ref(false);
        const dsDetail = ref(null);
        const viewDataSource = async (row) => { dsDetail.value = row; showDsDetailDialog.value = true; };

        // IP主体数据导入
        const downloadSubjectTemplate = async () => {
            try {
                const resp = await fetch('/api/subjects/import/template', { headers: { Authorization: token.value } });
                const blob = await resp.blob();
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url; a.download = 'IP主体数据导入模板.xlsx'; a.click();
                URL.revokeObjectURL(url);
                ElMessage.success('模板下载成功');
            } catch(e) { ElMessage.error('下载失败: ' + e.message); }
        };
        const handleSubjectImport = async (file) => {
            const formData = new FormData();
            formData.append('file', file);
            try {
                const resp = await fetch('/api/subjects/import', {
                    method: 'POST', headers: { Authorization: token.value }, body: formData
                });
                const res = await resp.json();
                if (res.imported > 0) {
                    ElMessage.success(res.message);
                    if (res.errors && res.errors.length > 0) {
                        ElMessageBox.alert(res.errors.join('\n'), '部分数据导入失败', { type: 'warning' });
                    }
                } else {
                    ElMessage.error('未导入任何数据，请检查文件格式');
                }
            } catch(e) { ElMessage.error('导入失败: ' + (e.message || '服务器错误')); }
            return false;
        };

        // Templates
        const templateList = ref([]);
        const tplPage = ref(1);
        const tplTotal = ref(0);
        const loadTemplates = async (page) => {
            tplPage.value = page;
            try { const res = await API('/api/templates?page=' + page + '&page_size=10'); templateList.value = res.data; tplTotal.value = res.total; } catch(e) { ElMessage.error(e.message); }
        };
        const showTemplateDialog = ref(false);
        const templateForm = reactive({ id: '', name: '', scene_type: '', description: '' });
        const openTemplateDialog = (row) => {
            if (row) { Object.assign(templateForm, { id: row.id, name: row.name, scene_type: row.scene_type, description: row.description }); }
            else { Object.assign(templateForm, { id: '', name: '', scene_type: '', description: '' }); }
            showTemplateDialog.value = true;
        };
        const saveTemplate = async () => {
            try {
                if (templateForm.id) { await API('/api/templates/' + templateForm.id, { method: 'PUT', body: templateForm }); }
                else { await API('/api/templates', { method: 'POST', body: templateForm }); }
                ElMessage.success('保存成功'); showTemplateDialog.value = false; loadTemplates(tplPage.value);
            } catch(e) { ElMessage.error(e.message); }
        };
        const deleteTemplate = async (row) => {
            try { await ElMessageBox.confirm('确认删除?', '提示', { type: 'warning' }); await API('/api/templates/' + row.id, { method: 'DELETE' }); ElMessage.success('删除成功'); loadTemplates(tplPage.value); } catch(e) {}
        };
        const showTemplateDetailDialog = ref(false);
        const templateDetail = ref(null);
        const viewTemplate = async (row) => { try { templateDetail.value = await API('/api/templates/' + row.id); showTemplateDetailDialog.value = true; } catch(e) { ElMessage.error(e.message); } };

        // Field Management
        const showFieldDialog = ref(false);
        const fieldList = ref([]);
        const currentTplId = ref('');
        const fieldForm = reactive({ id: '', field_name: '', field_label: '', field_type: 'text', is_required: 0, is_encrypted: 0, is_sensitive: 0, field_order: 0, description: '' });
        const openFieldDialog = (row) => {
            currentTplId.value = row.id;
            fieldList.value = row.fields || [];
            resetFieldForm();
            showFieldDialog.value = true;
        };
        const resetFieldForm = () => { Object.assign(fieldForm, { id: '', field_name: '', field_label: '', field_type: 'text', is_required: 0, is_encrypted: 0, is_sensitive: 0, field_order: 0, description: '' }); };
        const openEditField = (row) => { Object.assign(fieldForm, row); };
        const saveField = async () => {
            try {
                if (fieldForm.id) { await API(`/api/templates/${currentTplId.value}/fields/${fieldForm.id}`, { method: 'PUT', body: fieldForm }); }
                else { await API(`/api/templates/${currentTplId.value}/fields`, { method: 'POST', body: fieldForm }); }
                ElMessage.success('保存成功');
                const res = await API('/api/templates/' + currentTplId.value);
                fieldList.value = res.fields || [];
                resetFieldForm();
            } catch(e) { ElMessage.error(e.message); }
        };
        const deleteField = async (row) => {
            try { await API(`/api/templates/${currentTplId.value}/fields/${row.id}`, { method: 'DELETE' }); ElMessage.success('删除成功'); const res = await API('/api/templates/' + currentTplId.value); fieldList.value = res.fields || []; } catch(e) { ElMessage.error(e.message); }
        };

        // Scenes
        const sceneList = ref([]);
        const scenePage = ref(1);
        const sceneTotal = ref(0);
        const loadScenes = async (page) => {
            scenePage.value = page;
            try { const res = await API('/api/scenes?page=' + page + '&page_size=10'); sceneList.value = res.data; sceneTotal.value = res.total; } catch(e) { ElMessage.error(e.message); }
        };
        const showSceneDialog = ref(false);
        const sceneForm = reactive({ id: '', name: '', scene_type: '', ip_range: '', description: '' });
        const openSceneDialog = (row) => {
            if (row) { Object.assign(sceneForm, { id: row.id, name: row.name, scene_type: row.scene_type, ip_range: row.ip_range, description: row.description }); }
            else { Object.assign(sceneForm, { id: '', name: '', scene_type: '', ip_range: '', description: '' }); }
            showSceneDialog.value = true;
        };
        const saveScene = async () => {
            try {
                if (sceneForm.id) { await API('/api/scenes/' + sceneForm.id, { method: 'PUT', body: sceneForm }); }
                else { await API('/api/scenes', { method: 'POST', body: sceneForm }); }
                ElMessage.success('保存成功'); showSceneDialog.value = false; loadScenes(scenePage.value);
            } catch(e) { ElMessage.error(e.message); }
        };
        const deleteScene = async (row) => {
            try { await ElMessageBox.confirm('确认删除未被引用的场景?', '提示', { type: 'warning' }); await API('/api/scenes/' + row.id, { method: 'DELETE' }); ElMessage.success('删除成功'); loadScenes(scenePage.value); } catch(e) {}
        };
        const toggleScene = async (row) => {
            try { await API('/api/scenes/' + row.id + '/toggle', { method: 'PUT' }); ElMessage.success('状态已切换'); loadScenes(scenePage.value); } catch(e) { ElMessage.error(e.message); }
        };

        // Path Builder (drag-drop)
        const showPathBuilder = ref(false);
        const pathNodes = ref([]);
        const pathEdges = ref([]);
        const selectedNode = ref(null);
        const currentSceneId = ref('');
        const currentPathInfo = ref(null);
        const openPathBuilder = async (row) => {
            currentSceneId.value = row.id;
            currentPathInfo.value = { name: row.name + '路径', status: 'draft' };
            // Load existing path
            try {
                const res = await API('/api/scenes/' + row.id + '/paths');
                if (res.data && res.data.length > 0) {
                    const p = res.data[0];
                    currentPathInfo.value = { id: p.id, name: p.name, status: p.status };
                    pathNodes.value = JSON.parse(p.nodes || '[]');
                    pathEdges.value = JSON.parse(p.edges || '[]');
                } else {
                    pathNodes.value = [
                        { id: 'n1', type: 'start', name: '开始', x: 50, y: 50 },
                        { id: 'n2', type: 'execute', name: '查询数据源', x: 300, y: 50 },
                        { id: 'n3', type: 'judge', name: '判断是否命中', x: 550, y: 50 },
                    ];
                    pathEdges.value = [{ from: 'n1', to: 'n2' }, { from: 'n2', to: 'n3' }];
                }
            } catch(e) { ElMessage.error(e.message); }
            showPathBuilder.value = true;
        };
        const addNode = (type) => {
            const names = { start: '开始节点', execute: '执行节点', judge: '判断节点' };
            pathNodes.value.push({ id: 'n' + Date.now(), type, name: names[type] + (pathNodes.value.length + 1), x: 50 + Math.random() * 600, y: 50 + Math.random() * 300 });
        };
        const clearCanvas = () => { pathNodes.value = []; pathEdges.value = []; selectedNode.value = null; };
        const selectNode = (node) => {
            if (selectedNode.value && selectedNode.value.id !== node.id) {
                // Create edge
                pathEdges.value.push({ from: selectedNode.value.id, to: node.id });
                selectedNode.value = null;
            } else {
                selectedNode.value = node;
            }
        };
        const deleteNode = (node) => {
            pathNodes.value = pathNodes.value.filter(n => n.id !== node.id);
            pathEdges.value = pathEdges.value.filter(e => e.from !== node.id && e.to !== node.id);
        };
        const getNodePos = (id) => {
            const n = pathNodes.value.find(n => n.id === id);
            return n ? { x: n.x, y: n.y } : { x: 0, y: 0 };
        };
        const savePath = async () => {
            try {
                const body = { name: currentPathInfo.value.name, nodes: JSON.stringify(pathNodes.value), edges: JSON.stringify(pathEdges.value) };
                if (currentPathInfo.value.id) {
                    await API(`/api/scenes/${currentSceneId.value}/paths/${currentPathInfo.value.id}`, { method: 'PUT', body });
                } else {
                    const res = await API(`/api/scenes/${currentSceneId.value}/paths`, { method: 'POST', body });
                    currentPathInfo.value.id = res.id;
                }
                ElMessage.success('路径保存成功');
            } catch(e) { ElMessage.error(e.message); }
        };
        const publishPath = async () => {
            await savePath();
            try {
                await API(`/api/scenes/${currentSceneId.value}/paths/${currentPathInfo.value.id}/publish`, { method: 'PUT' });
                ElMessage.success('路径发布成功');
                currentPathInfo.value.status = 'published';
            } catch(e) { ElMessage.error(e.message); }
        };
        const handleCanvasRightClick = (e) => { /* just prevent default */ };

        // Conflict Tickets
        const conflictQuery = reactive({ ticket_no: '', ip_address: '', conflict_source: '', conflict_type: '', status: '', field_name: '' });
        const conflictList = ref([]);
        const conflictPage = ref(1);
        const conflictTotal = ref(0);
        const loadConflicts = async (page) => {
            conflictPage.value = page;
            const params = new URLSearchParams({ page, page_size: 10, ...Object.fromEntries(Object.entries(conflictQuery).filter(([_,v]) => v)) });
            try { const res = await API('/api/conflicts?' + params); conflictList.value = res.data; conflictTotal.value = res.total; } catch(e) { ElMessage.error(e.message); }
        };
        const resetConflictQuery = () => { Object.keys(conflictQuery).forEach(k => conflictQuery[k] = ''); loadConflicts(1); };
        const showConflictDetailDialog = ref(false);
        const conflictDetail = ref(null);
        const conflictLifecycle = ref(null);
        const viewConflictDetail = async (row) => {
            try { conflictDetail.value = await API('/api/conflicts/' + row.id); showConflictDetailDialog.value = true; const lc = await API('/api/conflicts/' + row.id + '/lifecycle'); conflictLifecycle.value = lc.lifecycle; } catch(e) { ElMessage.error(e.message); }
        };
        const showProcessDialog = ref(false);
        const processForm = reactive({ action: '', handle_remark: '', handle_evidence: '', handler: 'admin', ticket_id: '' });
        const processConflict = (row, action) => { Object.assign(processForm, { action, handle_remark: '', handle_evidence: '', handler: 'admin', ticket_id: row.id }); showProcessDialog.value = true; };
        const submitProcessConflict = async () => {
            try { await API('/api/conflicts/' + processForm.ticket_id + '/process', { method: 'PUT', body: processForm }); ElMessage.success('处理成功'); showProcessDialog.value = false; loadConflicts(conflictPage.value); } catch(e) { ElMessage.error(e.message); }
        };

        // Logs
        const logQuery = reactive({ operation_type: '', operation_detail: '', operator: '', start_time: '', end_time: '' });
        const logList = ref([]);
        const logPage = ref(1);
        const logTotal = ref(0);
        const loadLogs = async (page) => {
            logPage.value = page;
            const params = new URLSearchParams({ page, page_size: 10, ...Object.fromEntries(Object.entries(logQuery).filter(([_,v]) => v)) });
            try { const res = await API('/api/logs?' + params); logList.value = res.data; logTotal.value = res.total; } catch(e) { ElMessage.error(e.message); }
        };
        const resetLogQuery = () => { Object.keys(logQuery).forEach(k => logQuery[k] = ''); loadLogs(1); };

        // Security Config
        const securityTab = ref('password');
        const securityConfig = reactive({});
        const loadSecurityConfig = async () => {
            try { const res = await API('/api/security/config'); res.data.forEach(item => { securityConfig[item.config_key] = item.config_value; }); } catch(e) {}
        };
        const saveSecurityConfig = async () => {
            try {
                const keys = ['password_history_count', 'password_valid_days', 'password_expire_remind_days', 'password_min_length', 'password_complexity_desc', 'login_fail_lock_threshold', 'account_lock_duration', 'session_idle_timeout'];
                for (const key of keys) {
                    if (securityConfig[key] !== undefined) { await API('/api/security/config', { method: 'PUT', body: { config_key: key, config_value: String(securityConfig[key]) } }); }
                }
                ElMessage.success('配置保存成功');
            } catch(e) { ElMessage.error(e.message); }
        };
        const ipAccessList = ref([]);
        const loadIpAccess = async () => { try { const res = await API('/api/security/ip-access'); ipAccessList.value = res.data; } catch(e) {} };
        const showIpAccessDialog = ref(false);
        const ipAccessForm = reactive({ ip_segment: '', description: '' });
        const openIpAccessDialog = () => { Object.assign(ipAccessForm, { ip_segment: '', description: '' }); showIpAccessDialog.value = true; };
        const saveIpAccess = async () => { try { await API('/api/security/ip-access', { method: 'POST', body: ipAccessForm }); ElMessage.success('创建成功'); showIpAccessDialog.value = false; loadIpAccess(); } catch(e) { ElMessage.error(e.message); } };
        const toggleIpAccess = async (row) => { try { await API('/api/security/ip-access/' + row.id + '/toggle', { method: 'PUT' }); loadIpAccess(); } catch(e) {} };
        const deleteIpAccess = async (row) => { try { await API('/api/security/ip-access/' + row.id, { method: 'DELETE' }); ElMessage.success('删除成功'); loadIpAccess(); } catch(e) {} };

        onMounted(() => {
            const savedUser = localStorage.getItem('user');
            if (savedUser) currentUser.value = JSON.parse(savedUser);
            if (token.value) loadDashboard();
            loadIpAccess();
        });

        return {
            token, loginForm, currentUser, handleLogin, logout,
            activeMenu, pageTitle, handleMenuSelect,
            stats, dashboardCards,
            queryForm, queryRules, queryLoading, queryResult, handleQuery, showPathReplay, viewPathReplay,
            showManualFixDialog, manualFixForm, showManualFix, submitManualFix,
            showSensitiveDialog, sensitiveForm, sensitiveResult, sensitiveVerifyCode, showSensitive, requestSensitiveApproval, verifySensitiveApproval,
            showLocationDialog, locationDetail, showLocationDetail,
            taskQuery, taskList, taskPage, taskTotal, loadTasks, resetTaskQuery,
            showTaskResultDialog, showTaskPathDialog, taskDetail, viewTaskResult, viewTaskPath, viewTaskDetail,
            batchResult, downloadTemplate, beforeBatchUpload, handleBatchUpload, viewBatchTask,
            dsQuery, dsList, dsPage, dsTotal, loadDataSources, resetDsQuery, showDsDialog, dsForm, openDataSourceDialog, saveDataSource, deleteDataSource, showDsDetailDialog, dsDetail, viewDataSource, downloadSubjectTemplate, handleSubjectImport,
            templateList, tplPage, tplTotal, loadTemplates, showTemplateDialog, templateForm, openTemplateDialog, saveTemplate, deleteTemplate, showTemplateDetailDialog, templateDetail, viewTemplate,
            showFieldDialog, fieldList, currentTplId, fieldForm, openFieldDialog, resetFieldForm, openEditField, saveField, deleteField,
            sceneList, scenePage, sceneTotal, loadScenes, showSceneDialog, sceneForm, openSceneDialog, saveScene, deleteScene, toggleScene,
            showPathBuilder, pathNodes, pathEdges, selectedNode, currentSceneId, currentPathInfo, openPathBuilder, addNode, clearCanvas, selectNode, deleteNode, getNodePos, savePath, publishPath, handleCanvasRightClick,
            conflictQuery, conflictList, conflictPage, conflictTotal, loadConflicts, resetConflictQuery, showConflictDetailDialog, conflictDetail, conflictLifecycle, viewConflictDetail, showProcessDialog, processForm, processConflict, submitProcessConflict,
            logQuery, logList, logPage, logTotal, loadLogs, resetLogQuery,
            securityTab, securityConfig, loadSecurityConfig, saveSecurityConfig, ipAccessList, loadIpAccess, showIpAccessDialog, ipAccessForm, openIpAccessDialog, saveIpAccess, toggleIpAccess, deleteIpAccess,
        };
    }
});

// Register Element Plus and icons
app.use(ElementPlus);
for (const [key, comp] of Object.entries(ElementPlusIconsVue)) {
    app.component(key, comp);
}
app.mount('#app');
