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
            'confidence': '置信度说明', 'datasource': '数据源管理', 'template': '主体信息管理', 'scene': '场景路径管理', 'dictionary': '数据字典配置',
            'conflict': '冲突工单检测', 'log': '日志管理', 'security': '安全配置'
        };
        const pageTitle = computed(() => menuTitles[activeMenu.value] || '');
        const handleMenuSelect = (key) => {
            activeMenu.value = key;
            if (key === 'dashboard') loadDashboard();
            if (key === 'query-list') loadTasks(1);
            if (key === 'query-batch') { /* ready */ }
            if (key === 'confidence') loadConfidenceStats();
            if (key === 'datasource') { loadAllTemplates(); loadDataSources(1); }
            if (key === 'template') loadTemplates(1);
            if (key === 'scene') { loadAllDataSources(); loadScenes(1); }
            if (key === 'dictionary') { loadDictionaryTypes(); loadDictionary(1); }
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

        // 置信度统计
        const confidenceStats = ref(null);
        const confidenceBySource = ref([]);
        const confidenceDetails = ref([]);  // 每条IP主体结果的置信度明细
        const loadConfidenceStats = async () => {
            try {
                const r = await API('/api/dashboard/confidence');
                confidenceStats.value = r;
                confidenceBySource.value = r.by_source || [];
                confidenceDetails.value = r.details || [];
            } catch(e) { ElMessage.error(e.message); }
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
        const dsForm = reactive({ id: '', name: '', source_type: '移网', authority_level: '高', owner: '', contact: '', description: '', alarm_enabled: 0, config_attrs: '{}', template_id: '' });
        const openDataSourceDialog = (row) => {
            if (row) { Object.keys(dsForm).forEach(k => dsForm[k] = row[k] !== undefined ? row[k] : (k==='template_id'?'':dsForm[k])); }
            else { Object.assign(dsForm, { id: '', name: '', source_type: '移网', authority_level: '高', owner: '', contact: '', description: '', alarm_enabled: 0, config_attrs: '{}', template_id: '' }); }
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
        const allTemplates = ref([]);
        const loadTemplates = async (page) => {
            tplPage.value = page;
            try { const res = await API('/api/templates?page=' + page + '&page_size=10'); templateList.value = res.data; tplTotal.value = res.total; } catch(e) { ElMessage.error(e.message); }
        };
        const loadAllTemplates = async () => {
            try { const res = await API('/api/templates?page=1&page_size=100'); allTemplates.value = res.data || []; } catch(e) { console.error(e); }
        };
        const tplNameOf = (tplId) => {
            if (!tplId) return '';
            const t = allTemplates.value.find(x => x.id === tplId);
            return t ? t.name : '';
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
        const sceneForm = reactive({ id: '', name: '', scene_type: '', ip_range: '', description: '', datasource_ids_arr: [] });
        const openSceneDialog = (row) => {
            if (row) { Object.assign(sceneForm, { id: row.id, name: row.name, scene_type: row.scene_type, ip_range: row.ip_range, description: row.description, datasource_ids_arr: row.datasource_ids ? [...row.datasource_ids] : [] }); }
            else { Object.assign(sceneForm, { id: '', name: '', scene_type: '', ip_range: '', description: '', datasource_ids_arr: [] }); }
            showSceneDialog.value = true;
        };
        const saveScene = async () => {
            try {
                const payload = { ...sceneForm, datasource_ids: (sceneForm.datasource_ids_arr || []).join(',') };
                delete payload.datasource_ids_arr;
                if (sceneForm.id) { await API('/api/scenes/' + sceneForm.id, { method: 'PUT', body: payload }); }
                else { await API('/api/scenes', { method: 'POST', body: payload }); }
                ElMessage.success('保存成功'); showSceneDialog.value = false; loadScenes(scenePage.value);
            } catch(e) { ElMessage.error(e.message); }
        };
        const deleteScene = async (row) => {
            try { await ElMessageBox.confirm('确认删除未被引用的场景?', '提示', { type: 'warning' }); await API('/api/scenes/' + row.id, { method: 'DELETE' }); ElMessage.success('删除成功'); loadScenes(scenePage.value); } catch(e) {}
        };
        const toggleScene = async (row) => {
            try { await API('/api/scenes/' + row.id + '/toggle', { method: 'PUT' }); ElMessage.success('状态已切换'); loadScenes(scenePage.value); } catch(e) { ElMessage.error(e.message); }
        };

        // Path Builder (visual drag-drop)
        const showPathBuilder = ref(false);
        const allDataSources = ref([]);
        const currentSceneId = ref('');
        const currentSceneInfo = ref(null);
        const currentPathInfo = ref(null);
        const pathNodes = ref([]);
        const pathEdges = ref([]);
        // LogicFlow instance (non-reactive)
        let lfInstance = null;
        let lfDragType = null;
        // branch picker
        const showBranchPicker = ref(false);
        const pendingLinkFrom = ref(null);
        const pendingLinkTo = ref(null);
        // node config
        const showNodeConfig = ref(false);
        const nodeConfigForm = reactive({ id: '', type: '', name: '', data_source_id: '', query_target: '', condition: '是否命中' });
        const pathCanvas = ref(null);

        const loadAllDataSources = async () => {
            try {
                const res = await API('/api/datasources?page=1&page_size=100');
                allDataSources.value = res.data || [];
            } catch(e) { ElMessage.error(e.message); }
        };

        const fillDsNames = (nodes) => {
            for (const n of nodes) {
                if (n.data_source_id) {
                    const ds = allDataSources.value.find(d => d.id === n.data_source_id);
                    n.data_source_name = ds ? ds.name : '';
                } else {
                    n.data_source_name = '';
                }
            }
            return nodes;
        };

        // ---- LogicFlow data conversion ----
        // Our format <-> LogicFlow format
        const toLfData = (nodes, edges) => {
            const lfNodes = (nodes || []).map(n => ({
                id: n.id,
                type: n.type === 'judge' ? 'judge-node' : (n.type === 'start' ? 'start-node' : 'execute-node'),
                x: n.x || 0, y: n.y || 0,
                text: n.name || n.type,
                properties: {
                    nodeType: n.type,
                    name: n.name,
                    data_source_id: n.data_source_id || '',
                    data_source_name: n.data_source_name || '',
                    query_target: n.query_target || '',
                    condition: n.condition || '',
                },
            }));
            const lfEdges = (edges || []).map((e, i) => ({
                id: 'e_' + (e.from || '') + '_' + (e.to || '') + '_' + i,
                type: 'polyline',
                sourceNodeId: e.from,
                targetNodeId: e.to,
                text: e.label || '',
            }));
            return { nodes: lfNodes, edges: lfEdges };
        };
        const fromLfData = (lfData) => {
            const nodes = (lfData.nodes || []).map(n => {
                const p = n.properties || {};
                return {
                    id: n.id,
                    type: p.nodeType || (n.type === 'judge-node' ? 'judge' : n.type === 'start-node' ? 'start' : 'execute'),
                    name: p.name || n.text || '',
                    x: Math.round(n.x || 0), y: Math.round(n.y || 0),
                    data_source_id: p.data_source_id || '',
                    data_source_name: p.data_source_name || '',
                    query_target: p.query_target || '',
                    condition: p.condition || '',
                };
            });
            const edges = (lfData.edges || []).map(e => ({
                from: e.sourceNodeId,
                to: e.targetNodeId,
                label: e.text || '',
            }));
            return { nodes, edges };
        };

        // ---- LogicFlow init ----
        const registerCustomNodes = (lf) => {
            // Start node (blue rect)
            lf.register({
                type: 'start-node',
                view: Core.RectNode,
                model: class extends Core.RectNodeModel {
                    getNodeStyle() {
                        const s = super.getNodeStyle();
                        s.fill = '#409EFF'; s.stroke = '#337ecc'; s.radius = 6;
                        return s;
                    }
                    getTextStyle() {
                        const t = super.getTextStyle();
                        t.color = '#fff'; t.fontSize = 13;
                        return t;
                    }
                },
            });
            // Execute node (green rect)
            lf.register({
                type: 'execute-node',
                view: Core.RectNode,
                model: class extends Core.RectNodeModel {
                    getNodeStyle() {
                        const s = super.getNodeStyle();
                        s.fill = '#67C23A'; s.stroke = '#529b2e'; s.radius = 6;
                        return s;
                    }
                    getTextStyle() {
                        const t = super.getTextStyle();
                        t.color = '#fff'; t.fontSize = 13;
                        return t;
                    }
                },
            });
            // Judge node (orange diamond)
            lf.register({
                type: 'judge-node',
                view: Core.DiamondNode,
                model: class extends Core.DiamondNodeModel {
                    getNodeStyle() {
                        const s = super.getNodeStyle();
                        s.fill = '#E6A23C'; s.stroke = '#b88230';
                        return s;
                    }
                    getTextStyle() {
                        const t = super.getTextStyle();
                        t.color = '#fff'; t.fontSize = 13;
                        return t;
                    }
                },
            });
        };

        const initLogicFlow = () => {
            if (!pathCanvas.value) return;
            if (lfInstance) { try { lfInstance.clearData(); } catch(e){} }
            lfInstance = new Core.LogicFlow({
                container: pathCanvas.value,
                grid: { size: 20, type: 'dot', config: { color: '#dcdfe6', thickness: 1 } },
                edgeTextDraggable: true,
                adjustEdge: true,
                keyboard: { enabled: true },
            });
            registerCustomNodes(lfInstance);
            lfInstance.setTheme({
                edge: { stroke: '#409EFF', strokeWidth: 2 },
                edgeText: { color: '#E6A23C', fontSize: 12, fontWeight: 'bold', background: { fill: '#fff', stroke: 'transparent', radius: 3 } },
                polyline: { stroke: '#409EFF', strokeWidth: 2 },
            });
            // Events
            lfInstance.on('node:dbclick', (ev) => {
                const node = ev.data || ev;
                if (node) openNodeConfig(node.id, node.properties || {});
            });
            lfInstance.on('node:contextmenu', (ev) => {
                const node = ev.data || ev;
                if (node && node.id) { lfInstance.deleteNode(node.id); syncCount(); }
            });
            lfInstance.on('edge:contextmenu', (ev) => {
                const edge = ev.data || ev;
                if (edge && edge.id) { lfInstance.deleteEdge(edge.id); syncCount(); }
            });
            lfInstance.on('connection', (ev) => {
                const conn = ev.data || ev;
                const srcId = conn.sourceNodeId || conn.source || '';
                const tgtId = conn.targetNodeId || conn.target || '';
                const edgeId = conn.id || '';
                const srcModel = lfInstance.getNodeModelById(srcId);
                const srcType = srcModel ? (srcModel.properties || {}).nodeType : '';
                if (srcType === 'judge') {
                    // Show branch picker
                    pendingLinkFrom.value = { id: srcId, name: srcModel ? srcModel.text.value : '' };
                    pendingLinkTo.value = { id: tgtId };
                    showBranchPicker.value = true;
                    // Store edge id for label application
                    pendingEdgeId.value = edgeId;
                }
            });
        };

        // Pending edge id for branch label
        const pendingEdgeId = ref(null);

        const syncCount = () => {
            if (!lfInstance) return;
            const d = lfInstance.getGraphData();
            pathNodes.value = (d.nodes || []).map(n => ({ id: n.id, type: (n.properties||{}).nodeType || 'execute' }));
            pathEdges.value = (d.edges || []).map(e => ({ from: e.sourceNodeId, to: e.targetNodeId, label: (typeof e.text === 'string' ? e.text : (e.text && e.text.value) || '') }));
        };

        const onPathBuilderOpened = async () => {
            await nextTick();
            if (!pathCanvas.value) { ElMessage.error('画布容器未就绪'); return; }
            initLogicFlow();
            // Render existing path data
            const lfData = toLfData(pathNodes.value, pathEdges.value);
            lfInstance.render(lfData);
            // Center view
            try { lfInstance.fitView(20); } catch(e) {}
        };

        const onPathBuilderClosed = () => {
            if (lfInstance) { try { lfInstance.clearData(); } catch(e){} lfInstance = null; }
        };

        const openPathBuilder = async (row) => {
            currentSceneId.value = row.id;
            currentSceneInfo.value = row;
            currentPathInfo.value = { name: row.name + '查询路径', status: 'draft' };
            pathNodes.value = [];
            pathEdges.value = [];
            await loadAllDataSources();
            await loadAllTemplates();
            try {
                const res = await API('/api/scenes/' + row.id + '/paths');
                if (res.data && res.data.length > 0) {
                    const p = res.data[0];
                    currentPathInfo.value = { id: p.id, name: p.name, status: p.status };
                    pathNodes.value = fillDsNames(JSON.parse(p.nodes || '[]'));
                    pathEdges.value = JSON.parse(p.edges || '[]');
                } else {
                    pathNodes.value = fillDsNames([
                        { id: 'n_start', type: 'start', name: '开始', x: 100, y: 200 },
                        { id: 'n_end', type: 'execute', name: '返回结果', x: 400, y: 200 },
                    ]);
                    pathEdges.value = [{ from: 'n_start', to: 'n_end' }];
                }
            } catch(e) { ElMessage.error(e.message); }
            showPathBuilder.value = true;
        };

        // ---- toolbar drag to LogicFlow ----
        const onDragStart = (e, type) => { lfDragType = type; e.dataTransfer.effectAllowed = 'copy'; };
        const onDrop = (e) => {
            if (!lfDragType || !lfInstance) return;
            // Convert screen coords to LogicFlow canvas coords
            const rect = pathCanvas.value.getBoundingClientRect();
            const lfPoint = lfInstance.clientToLocalPoint ? lfInstance.clientToLocalPoint(e.clientX - rect.left, e.clientY - rect.top) : { x: e.clientX - rect.left, y: e.clientY - rect.top };
            addNode(lfDragType, lfPoint.x, lfPoint.y);
            lfDragType = null;
        };

        const addNode = (type, x, y) => {
            const names = { start: '开始', execute: '执行节点', judge: '判断节点' };
            const lfType = type === 'judge' ? 'judge-node' : (type === 'start' ? 'start-node' : 'execute-node');
            const id = 'n' + Date.now() + Math.floor(Math.random() * 1000);
            const props = { nodeType: type, name: names[type], data_source_id: '', data_source_name: '', query_target: '', condition: type === 'judge' ? '是否命中' : '' };
            lfInstance.addNode({ id, type: lfType, x: Math.round(x), y: Math.round(y), text: names[type], properties: props });
            syncCount();
            if (type !== 'start') ElMessage.info('双击节点可配置' + (type === 'execute' ? '查询数据源' : '判断条件'));
        };

        // ---- zoom ----
        const lfZoom = (up) => { if (!lfInstance) return; lfInstance.zoom(up ? 1.2 : 0.8); };
        const lfResetView = () => { if (!lfInstance) return; try { lfInstance.resetZoom(); lfInstance.resetTranslateX(); lfInstance.resetTranslateY(); } catch(e) {} try { lfInstance.fitView(20); } catch(e) {} };

        // ---- branch label ----
        const applyBranch = (label) => {
            showBranchPicker.value = false;
            if (pendingEdgeId.value && lfInstance) {
                // Set edge text (label)
                const edgeModel = lfInstance.getEdgeModelById ? lfInstance.getEdgeModelById(pendingEdgeId.value) : null;
                if (edgeModel) {
                    lfInstance.updateText ? lfInstance.updateText(pendingEdgeId.value, label) : null;
                }
            }
            pendingLinkFrom.value = null;
            pendingLinkTo.value = null;
            pendingEdgeId.value = null;
            syncCount();
        };

        // ---- clear ----
        const clearCanvas = () => {
            if (lfInstance) lfInstance.clearData();
            pathNodes.value = []; pathEdges.value = [];
        };

        // ---- node config ----
        const currentDsFields = ref([]);
        const loadDsTemplateFields = async (dsId) => {
            currentDsFields.value = [];
            if (!dsId) return;
            try {
                const ds = allDataSources.value.find(d => d.id === dsId);
                if (!ds || !ds.template_id) return;
                const res = await API('/api/templates/' + ds.template_id);
                if (res && res.fields) currentDsFields.value = res.fields;
            } catch(e) { console.error(e); }
        };
        const onNodeDsChange = (dsId) => { loadDsTemplateFields(dsId); };
        const openNodeConfig = (nodeId, props) => {
            const p = props || {};
            const type = p.nodeType || 'execute';
            nodeConfigForm.id = nodeId;
            nodeConfigForm.type = type;
            nodeConfigForm.name = p.name || '';
            nodeConfigForm.data_source_id = p.data_source_id || '';
            nodeConfigForm.query_target = p.query_target || '';
            nodeConfigForm.condition = p.condition || '是否命中';
            if (type === 'execute' && p.data_source_id) loadDsTemplateFields(p.data_source_id);
            else currentDsFields.value = [];
            showNodeConfig.value = true;
        };
        const applyNodeConfig = () => {
            if (lfInstance) {
                const model = lfInstance.getNodeModelById(nodeConfigForm.id);
                if (model) {
                    // Update text (name)
                    if (lfInstance.updateText) lfInstance.updateText(nodeConfigForm.id, nodeConfigForm.name);
                    // Update properties
                    const newProps = {
                        nodeType: nodeConfigForm.type,
                        name: nodeConfigForm.name,
                        data_source_id: nodeConfigForm.data_source_id || '',
                        data_source_name: '',
                        query_target: nodeConfigForm.query_target || '',
                        condition: nodeConfigForm.condition || '',
                    };
                    if (nodeConfigForm.type === 'execute' && nodeConfigForm.data_source_id) {
                        const ds = allDataSources.value.find(d => d.id === nodeConfigForm.data_source_id);
                        newProps.data_source_name = ds ? ds.name : '';
                    }
                    if (model.setProperties) model.setProperties(newProps);
                }
            }
            showNodeConfig.value = false;
            syncCount();
        };

        // ---- save & publish ----
        const savePath = async () => {
            if (!lfInstance) { ElMessage.warning('画布未初始化'); return; }
            // Export from LogicFlow and convert to our format
            const lfData = lfInstance.getGraphData();
            const { nodes: cleanNodes, edges: cleanEdges } = fromLfData(lfData);
            if (!cleanNodes.some(n => n.type === 'start')) { ElMessage.warning('路径需包含开始节点'); return; }
            syncCount();
            try {
                const body = { name: currentPathInfo.value.name, nodes: JSON.stringify(cleanNodes), edges: JSON.stringify(cleanEdges) };
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
            if (!currentPathInfo.value.id) return;
            try {
                await API(`/api/scenes/${currentSceneId.value}/paths/${currentPathInfo.value.id}/publish`, { method: 'PUT' });
                ElMessage.success('路径发布成功，查询流程已生效');
                currentPathInfo.value.status = 'published';
            } catch(e) { ElMessage.error(e.message); }
        };

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

        // Data Dictionary (CITY_ID -> CITY_NAME, etc.)
        const dictQuery = reactive({ dict_type: '', keyword: '' });
        const dictList = ref([]);
        const dictTypes = ref([]);
        const dictPage = ref(1);
        const dictTotal = ref(0);
        const showDictDialog = ref(false);
        const dictForm = reactive({ id: '', dict_type: 'CITY', dict_code: '', dict_name: '', description: '', status: 'active' });

        const loadDictionary = async (page) => {
            dictPage.value = page;
            const params = new URLSearchParams({ page, page_size: 20, ...Object.fromEntries(Object.entries(dictQuery).filter(([_, v]) => v)) });
            try { const res = await API('/api/dictionary?' + params); dictList.value = res.data; dictTotal.value = res.total; } catch(e) { ElMessage.error(e.message); }
        };
        const loadDictionaryTypes = async () => {
            try { const res = await API('/api/dictionary/types'); dictTypes.value = res.data || []; } catch(e) { console.error(e); }
        };
        const resetDictQuery = () => { dictQuery.dict_type = ''; dictQuery.keyword = ''; loadDictionary(1); };
        const openDictionaryDialog = (row) => {
            if (row) { Object.keys(dictForm).forEach(k => dictForm[k] = row[k] !== undefined ? row[k] : dictForm[k]); }
            else { Object.assign(dictForm, { id: '', dict_type: dictQuery.dict_type || 'CITY', dict_code: '', dict_name: '', description: '', status: 'active' }); }
            showDictDialog.value = true;
        };
        const saveDictionary = async () => {
            if (!dictForm.dict_type || !dictForm.dict_code || !dictForm.dict_name) {
                ElMessage.warning('字典类型、编码、名称不能为空'); return;
            }
            try {
                const payload = { dict_type: dictForm.dict_type, dict_code: String(dictForm.dict_code), dict_name: dictForm.dict_name, description: dictForm.description || '', status: dictForm.status || 'active' };
                if (dictForm.id) { await API('/api/dictionary/' + dictForm.id, { method: 'PUT', body: payload }); }
                else { await API('/api/dictionary', { method: 'POST', body: payload }); }
                ElMessage.success('保存成功'); showDictDialog.value = false; loadDictionary(dictPage.value); loadDictionaryTypes();
            } catch(e) { ElMessage.error(e.message); }
        };
        const deleteDictionary = async (row) => {
            try { await ElMessageBox.confirm('确认删除字典条目 [' + row.dict_type + '/' + row.dict_code + ']?', '提示', { type: 'warning' }); await API('/api/dictionary/' + row.id, { method: 'DELETE' }); ElMessage.success('删除成功'); loadDictionary(dictPage.value); loadDictionaryTypes(); } catch(e) { if (e && e.message) ElMessage.error(e.message); }
        };

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
            confidenceStats, confidenceBySource, confidenceDetails, loadConfidenceStats,
            queryForm, queryRules, queryLoading, queryResult, handleQuery, showPathReplay, viewPathReplay,
            showManualFixDialog, manualFixForm, showManualFix, submitManualFix,
            showSensitiveDialog, sensitiveForm, sensitiveResult, sensitiveVerifyCode, showSensitive, requestSensitiveApproval, verifySensitiveApproval,
            showLocationDialog, locationDetail, showLocationDetail,
            taskQuery, taskList, taskPage, taskTotal, loadTasks, resetTaskQuery,
            showTaskResultDialog, showTaskPathDialog, taskDetail, viewTaskResult, viewTaskPath, viewTaskDetail,
            batchResult, downloadTemplate, beforeBatchUpload, handleBatchUpload, viewBatchTask,
            dsQuery, dsList, dsPage, dsTotal, loadDataSources, resetDsQuery, showDsDialog, dsForm, openDataSourceDialog, saveDataSource, deleteDataSource, showDsDetailDialog, dsDetail, viewDataSource, downloadSubjectTemplate, handleSubjectImport,
            templateList, tplPage, tplTotal, loadTemplates, allTemplates, loadAllTemplates, tplNameOf, showTemplateDialog, templateForm, openTemplateDialog, saveTemplate, deleteTemplate, showTemplateDetailDialog, templateDetail, viewTemplate,
            showFieldDialog, fieldList, currentTplId, fieldForm, openFieldDialog, resetFieldForm, openEditField, saveField, deleteField,
            sceneList, scenePage, sceneTotal, loadScenes, showSceneDialog, sceneForm, openSceneDialog, saveScene, deleteScene, toggleScene,
            showPathBuilder, allDataSources, currentSceneId, currentSceneInfo, currentPathInfo, openPathBuilder,
            pathNodes, pathEdges, pathCanvas,
            onDragStart, onDrop, lfZoom, lfResetView, applyBranch,
            onPathBuilderOpened, onPathBuilderClosed,
            clearCanvas,
            showBranchPicker, pendingLinkFrom, showNodeConfig, nodeConfigForm, openNodeConfig, applyNodeConfig, currentDsFields, onNodeDsChange,
            savePath, publishPath,
            conflictQuery, conflictList, conflictPage, conflictTotal, loadConflicts, resetConflictQuery, showConflictDetailDialog, conflictDetail, conflictLifecycle, viewConflictDetail, showProcessDialog, processForm, processConflict, submitProcessConflict,
            logQuery, logList, logPage, logTotal, loadLogs, resetLogQuery,
            dictQuery, dictList, dictTypes, dictPage, dictTotal, loadDictionary, loadDictionaryTypes, resetDictQuery, showDictDialog, dictForm, openDictionaryDialog, saveDictionary, deleteDictionary,
            securityTab, securityConfig, loadSecurityConfig, saveSecurityConfig, ipAccessList, loadIpAccess, showIpAccessDialog, ipAccessForm, openIpAccessDialog, saveIpAccess, toggleIpAccess, deleteIpAccess,
        };
    }
});

// Path Replay component: renders the executed configured scene path (read-only diagram)
// plus per-node detailed execution results. Usage: <path-replay :path=".." :records=".." :fit="900"/>
app.component('path-replay', {
    props: {
        path: { type: Object, default: null },   // {name, nodes, edges} snapshot of the configured path
        records: { type: Array, default: () => [] }, // task_paths rows (node_id, node_name, node_type, status, detail, data_source...)
        fit: { type: Number, default: 900 },     // available width for auto-scaling
    },
    template: `
    <div class="replay-box">
        <div class="replay-meta" v-if="path">
            <el-tag type="success" effect="dark">执行路径: {{path.name}}</el-tag>
            <el-tag type="info">节点 {{(path.nodes||[]).length}}</el-tag>
            <el-tag type="info">连线 {{(path.edges||[]).length}}</el-tag>
            <el-tag type="warning">未走分支虚线显示</el-tag>
        </div>
        <div class="replay-canvas" v-if="path && (path.nodes||[]).length">
            <div class="rp-sizer" :style="{width: (size.w*scale)+'px', height: (size.h*scale)+'px'}">
                <div class="pb-inner rp-inner" :style="innerStyle">
                    <svg class="path-edges rp-svg" :width="size.w" :height="size.h">
                        <defs>
                            <marker id="rp-arrow" markerWidth="10" markerHeight="10" refX="8" refY="3" orient="auto">
                                <path d="M0,0 L0,6 L8,3 z" fill="#409EFF"></path>
                            </marker>
                        </defs>
                        <g v-for="(e,idx) in (path.edges||[])" :key="'rp-e'+idx">
                            <line :x1="anchorPos(e.from).x" :y1="anchorPos(e.from).y"
                                  :x2="nodePos(e.to).x" :y2="nodePos(e.to).y"
                                  :class="['rp-edge', isTraversed(e) ? 'rp-edge-on' : 'rp-edge-off']"
                                  marker-end="url(#rp-arrow)"/>
                            <text v-if="e.label" :x="(anchorPos(e.from).x+nodePos(e.to).x)/2"
                                  :y="(anchorPos(e.from).y+nodePos(e.to).y)/2-6"
                                  fill="#E6A23C" font-size="12" font-weight="bold">{{e.label}}</text>
                        </g>
                    </svg>
                    <div v-for="n in (path.nodes||[])" :key="n.id"
                         class="path-node rp-node" :class="['node-'+(n.type||'execute'), nodeStatus(n)==='failed' ? 'rp-node-failed' : '', nodeStatus(n) ? '' : 'rp-node-idle']"
                         :style="{left:(n.x||0)+'px', top:(n.y||0)+'px'}" :title="nodeTitle(n)">
                        <el-icon><component :is="n.type==='start'?'Flag':n.type==='judge'?'Switch':'Cpu'"/></el-icon>
                        <span class="pb-node-name">{{n.name}}</span>
                        <span class="rp-status" v-if="nodeStatus(n)">{{nodeStatus(n)==='failed'?'✗':'✓'}}</span>
                        <div class="node-ds" v-if="n.data_source_name">{{n.data_source_name}}</div>
                        <div class="node-cond" v-if="n.condition">{{n.condition}}</div>
                    </div>
                </div>
            </div>
        </div>
        <el-timeline class="rp-timeline">
            <el-timeline-item v-for="(p,idx) in records" :key="'rp-r'+idx"
                :type="p.status==='success'?'success':'danger'" :timestamp="p.started_at" placement="top">
                <el-card shadow="never" class="rp-card">
                    <h4>{{p.node_name}}
                        <el-tag size="small" :type="p.node_type==='start'?'info':p.node_type==='judge'?'warning':'success'">{{p.node_type}}</el-tag>
                        <el-tag size="small" :type="p.status==='success'?'success':'danger'">{{p.status}}</el-tag>
                    </h4>
                    <p>{{p.detail}}</p>
                    <p v-if="p.data_source">数据源: {{p.data_source}}</p>
                </el-card>
            </el-timeline-item>
        </el-timeline>
    </div>`,
    setup(props) {
        const { computed } = Vue;
        const NODE_W = 140, NODE_H = 40;
        const nodeById = (id) => (props.path && props.path.nodes ? props.path.nodes.find(n => n.id === id) : null) || null;
        const nodePos = (id) => { const n = nodeById(id); return { x: (n && n.x) || 0, y: ((n && n.y) || 0) + NODE_H / 2 }; };
        const anchorPos = (id) => { const n = nodeById(id); return { x: ((n && n.x) || 0) + NODE_W, y: ((n && n.y) || 0) + NODE_H / 2 }; };
        const recordByNode = (id) => (props.records || []).find(p => p.node_id === id) || null;
        const nodeStatus = (n) => { const r = recordByNode(n.id); return r ? r.status : null; };
        const nodeTitle = (n) => {
            const r = recordByNode(n.id);
            if (r) return (r.detail || r.node_name);
            return (n.data_source_name ? '数据源: ' + n.data_source_name + ' (未执行)' : (n.condition || n.name) + ' (未执行)');
        };
        // edges actually walked = consecutive executed node ids
        const traversedSet = computed(() => {
            const s = new Set();
            const recs = props.records || [];
            for (let i = 1; i < recs.length; i++) {
                if (recs[i-1].node_id && recs[i].node_id) s.add(recs[i-1].node_id + '->' + recs[i].node_id);
            }
            return s;
        });
        const isTraversed = (e) => traversedSet.value.has((e.from || '') + '->' + (e.to || ''));
        const size = computed(() => {
            const nodes = (props.path && props.path.nodes) || [];
            if (!nodes.length) return { w: 800, h: 260 };
            return {
                w: Math.max(...nodes.map(n => (n.x || 0) + NODE_W)) + 60,
                h: Math.max(...nodes.map(n => (n.y || 0) + NODE_H)) + 60,
            };
        });
        const scale = computed(() => Math.max(0.3, Math.min(1, props.fit / size.value.w)));
        const innerStyle = computed(() => ({ width: size.value.w + 'px', height: size.value.h + 'px', transform: 'scale(' + scale.value + ')', transformOrigin: '0 0' }));
        return { nodePos, anchorPos, nodeStatus, nodeTitle, isTraversed, size, scale, innerStyle };
    }
});

// Register Element Plus and icons
app.use(ElementPlus);
for (const [key, comp] of Object.entries(ElementPlusIconsVue)) {
    app.component(key, comp);
}
app.mount('#app');
