(function () {
    const sanitize = (str) => {
        if (typeof DOMPurify !== 'undefined' && DOMPurify.sanitize) {
            return DOMPurify.sanitize(str);
        }
        return String(str).replace(/[&<>"']/g, (s) => ({
            '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
        })[s]);
    };

    const severityOptions = [
        { value: 'critical', label: 'Critical' },
        { value: 'high', label: 'High' },
        { value: 'medium', label: 'Medium' },
        { value: 'cautionary', label: 'Cautionary' },
        { value: 'low', label: 'Low' },
        { value: 'informational', label: 'Informational' },
    ];
    const severityOptionValues = severityOptions.map((option) => option.value);

    const comparatorOptions = [
        { value: 'equals', label: 'Equals' },
        { value: 'not_equals', label: 'Does not equal' },
        { value: 'contains', label: 'Contains' },
        { value: 'not_contains', label: 'Does not contain' },
        { value: 'greater_than', label: 'Greater than' },
        { value: 'less_than', label: 'Less than' },
        { value: 'between', label: 'Between' },
        { value: 'matches_port_group', label: 'Matches port group' },
        { value: 'matches_admin_port', label: 'Matches admin port' },
        { value: 'starts_with', label: 'Starts with' },
        { value: 'ends_with', label: 'Ends with' },
        { value: 'in', label: 'In list' },
    ];
    const comparatorValueModes = {
        multi: new Set(['in', 'matches_port_group', 'between']),
        none: new Set(['matches_admin_port']),
    };

    const DEFAULT_RULE_CONDITIONS_YAML = 'logic: all\nconditions: []\ngroups: []\n';
    const DEFAULT_ANALYZERS_YAML = '{}\n';

    const ruleConfigApi = createRuleConfigApi();
    if (typeof window !== 'undefined') {
        window.firefindRuleConfigApi = ruleConfigApi;
    }

    const configState = {
        riskLevels: [],
        cidrLimitSets: [],
        portGroups: [],
        ruleLogic: [],
    };

    let passthroughConfig = {};
    let validationState = {
        riskLevels: {},
        cidrLimitSets: {},
        portGroups: {},
        ruleLogic: {},
    };
    let lastValidationMessage = '';
    const defaultValidationOptions = { suppressErrorToast: false };
    let validationOptions = { ...defaultValidationOptions };
    let ruleListView = null;
    let ruleEditor = null;

    function createConditionGroup(logic = 'all') {
        return {
            id: generateId('group'),
            logic: logic === 'any' ? 'any' : 'all',
            conditions: [],
            groups: [],
        };
    }

    function createConditionEntry() {
        return {
            id: generateId('condition'),
            field: '',
            comparator: 'equals',
            value: '',
            values: [],
        };
    }

    function cloneConditionGroup(group) {
        const base = createConditionGroup(group?.logic);
        const cloned = {
            ...base,
            id: group?.id || base.id,
            logic: group?.logic === 'any' ? 'any' : 'all',
            conditions: Array.isArray(group?.conditions)
                ? group.conditions.map((condition) => ({
                      id: condition?.id || generateId('condition'),
                      field: condition?.field ? String(condition.field) : '',
                      comparator: condition?.comparator ? String(condition.comparator) : 'equals',
                      value: condition?.value === null || condition?.value === undefined ? '' : String(condition.value),
                      values: Array.isArray(condition?.values)
                          ? condition.values.map((value) => String(value)).filter(Boolean)
                          : [],
                  }))
                : [],
            groups: Array.isArray(group?.groups)
                ? group.groups.map((child) => cloneConditionGroup(child))
                : [],
        };
        return cloned;
    }

    function normalizeConditionGroup(raw) {
        if (!raw || typeof raw !== 'object') {
            return createConditionGroup();
        }
        const group = createConditionGroup(raw.logic);
        group.id = raw.id || group.id;
        group.logic = raw.logic === 'any' ? 'any' : 'all';
        group.conditions = Array.isArray(raw.conditions)
            ? raw.conditions.map((entry) => normalizeConditionEntry(entry))
            : [];
        group.groups = Array.isArray(raw.groups)
            ? raw.groups.map((child) => normalizeConditionGroup(child))
            : [];
        return group;
    }

    function normalizeConditionEntry(raw) {
        const entry = createConditionEntry();
        if (!raw || typeof raw !== 'object') {
            return entry;
        }
        entry.id = raw.id || entry.id;
        entry.field = raw.field ? String(raw.field) : '';
        entry.comparator = raw.comparator ? String(raw.comparator) : 'equals';
        if (Array.isArray(raw.values)) {
            entry.values = raw.values.map((value) => String(value)).filter((value) => value !== '');
        } else if (raw.values !== undefined && raw.values !== null) {
            entry.values = splitList(raw.values);
        }
        if (raw.value !== undefined && raw.value !== null) {
            entry.value = String(raw.value);
        } else if (entry.values.length === 1 && raw.value === undefined) {
            entry.value = entry.values[0];
            entry.values = [];
        }
        return entry;
    }

    function conditionGroupToParsed(group) {
        const safeGroup = group || createConditionGroup();
        return {
            logic: safeGroup.logic === 'any' ? 'any' : 'all',
            conditions: Array.isArray(safeGroup.conditions)
                ? safeGroup.conditions
                      .map((entry) => conditionEntryToParsed(entry))
                      .filter((entry) => entry !== null)
                : [],
            groups: Array.isArray(safeGroup.groups)
                ? safeGroup.groups.map((child) => conditionGroupToParsed(child))
                : [],
        };
    }

    function conditionEntryToParsed(entry) {
        if (!entry || typeof entry !== 'object') {
            return null;
        }
        const field = (entry.field || '').trim();
        const comparator = (entry.comparator || '').trim();
        if (!field || !comparator) {
            return null;
        }
        const parsed = {
            field,
            comparator,
        };
        const hasMultiValues = Array.isArray(entry.values) && entry.values.some((value) => String(value).trim() !== '');
        if (hasMultiValues) {
            parsed.values = entry.values
                .map((value) => String(value).trim())
                .filter((value) => value !== '')
                .map((value) => tryConvertValue(value));
        } else {
            const value = entry.value === undefined || entry.value === null ? '' : String(entry.value).trim();
            if (value !== '') {
                parsed.value = tryConvertValue(value);
            }
        }
        return parsed;
    }

    function tryConvertValue(value) {
        const numeric = Number(value);
        if (!Number.isNaN(numeric) && String(numeric) === value) {
            return numeric;
        }
        if (value === 'true') {
            return true;
        }
        if (value === 'false') {
            return false;
        }
        return value;
    }

    function createThresholds() {
        return {
            min_score: '',
            max_score: '',
            min_findings: '',
            max_findings: '',
        };
    }

    function cloneThresholds(raw) {
        const base = createThresholds();
        if (!raw || typeof raw !== 'object') {
            return base;
        }
        Object.keys(base).forEach((key) => {
            const value = raw[key];
            base[key] = value === null || value === undefined ? '' : String(value);
        });
        return base;
    }

    function clonePerRiskThresholds(raw) {
        const result = {};
        if (!raw || typeof raw !== 'object') {
            return result;
        }
        Object.entries(raw).forEach(([risk, value]) => {
            result[risk] = cloneThresholds(value);
        });
        return result;
    }

    function clonePerRiskPortMap(raw) {
        const result = {};
        if (!raw || typeof raw !== 'object') {
            return result;
        }
        Object.entries(raw).forEach(([risk, values]) => {
            result[risk] = Array.isArray(values)
                ? values.map((entry) => String(entry).trim()).filter(Boolean)
                : splitList(values);
        });
        return result;
    }

    function createSeverityOverrideMap() {
        return severityOptionValues.reduce((acc, severity) => {
            acc[severity] = '';
            return acc;
        }, {});
    }

    function createAnalyzerEntry() {
        return {
            id: generateId('analyzer'),
            key: '',
            enabled: true,
            notes: '',
            severityOverrides: createSeverityOverrideMap(),
            baselineThresholds: createThresholds(),
            perRiskThresholds: {},
            baselineAdminPorts: [],
            perRiskAdminPorts: {},
        };
    }

    function cloneAnalyzerEntry(entry) {
        const base = createAnalyzerEntry();
        if (!entry || typeof entry !== 'object') {
            return base;
        }
        const severityOverrides = createSeverityOverrideMap();
        Object.entries(entry.severityOverrides || {}).forEach(([severity, value]) => {
            if (severityOptionValues.includes(severity)) {
                severityOverrides[severity] = value === null || value === undefined ? '' : String(value);
            }
        });
        return {
            ...base,
            id: entry.id || base.id,
            key: entry.key ? String(entry.key) : '',
            enabled: entry.enabled === false ? false : true,
            notes: entry.notes ? String(entry.notes) : '',
            severityOverrides,
            baselineThresholds: cloneThresholds(entry.baselineThresholds),
            perRiskThresholds: clonePerRiskThresholds(entry.perRiskThresholds),
            baselineAdminPorts: Array.isArray(entry.baselineAdminPorts)
                ? entry.baselineAdminPorts.map((value) => String(value)).filter(Boolean)
                : splitList(entry.baselineAdminPorts),
            perRiskAdminPorts: clonePerRiskPortMap(entry.perRiskAdminPorts),
        };
    }

    function normalizeAnalyzerEntries(raw) {
        if (!raw || typeof raw !== 'object') {
            return [createAnalyzerEntry()];
        }
        const entries = Object.entries(raw).map(([key, value]) => {
            const base = createAnalyzerEntry();
            const severityOverrides = createSeverityOverrideMap();
            Object.entries(value?.severity_overrides || {}).forEach(([severity, override]) => {
                if (severityOptionValues.includes(severity)) {
                    severityOverrides[severity] = override === null || override === undefined ? '' : String(override);
                }
            });
            const perRiskThresholds = {};
            Object.entries(value?.per_risk_thresholds || {}).forEach(([riskKey, thresholds]) => {
                perRiskThresholds[riskKey] = cloneThresholds(thresholds);
            });
            const adminPorts = value?.admin_ports || {};
            const baselineAdminPorts = Array.isArray(adminPorts.baseline)
                ? adminPorts.baseline.map((entry) => String(entry)).filter(Boolean)
                : splitList(adminPorts.baseline);
            const perRiskAdminPorts = {};
            Object.entries(adminPorts.per_risk_overrides || {}).forEach(([riskKey, ports]) => {
                perRiskAdminPorts[riskKey] = Array.isArray(ports)
                    ? ports.map((entry) => String(entry)).filter(Boolean)
                    : splitList(ports);
            });

            return {
                ...base,
                id: generateId('analyzer'),
                key: key ? String(key) : '',
                enabled: value?.enabled === false ? false : true,
                notes: value?.notes ? String(value.notes) : '',
                severityOverrides,
                baselineThresholds: cloneThresholds(value?.thresholds),
                perRiskThresholds,
                baselineAdminPorts,
                perRiskAdminPorts,
            };
        });
        return entries.length > 0 ? entries : [createAnalyzerEntry()];
    }

    function analyzerEntriesToParsed(entries) {
        const result = {};
        if (!Array.isArray(entries)) {
            return result;
        }
        entries.forEach((entry) => {
            const key = (entry.key || '').trim();
            if (!key) {
                return;
            }
            const payload = {
                enabled: entry.enabled !== false,
            };
            if (entry.notes && entry.notes.trim().length > 0) {
                payload.notes = entry.notes.trim();
            }
            const severityOverrides = {};
            Object.entries(entry.severityOverrides || {}).forEach(([severity, value]) => {
                const trimmed = typeof value === 'string' ? value.trim() : value;
                if (severityOptionValues.includes(severity) && trimmed) {
                    severityOverrides[severity] = trimmed;
                }
            });
            if (Object.keys(severityOverrides).length > 0) {
                payload.severity_overrides = severityOverrides;
            }

            const thresholds = thresholdsForExport(entry.baselineThresholds);
            if (thresholds) {
                payload.thresholds = thresholds;
            }
            const perRiskThresholds = {};
            Object.entries(entry.perRiskThresholds || {}).forEach(([riskKey, thresholdsValue]) => {
                const converted = thresholdsForExport(thresholdsValue);
                if (converted) {
                    perRiskThresholds[riskKey] = converted;
                }
            });
            if (Object.keys(perRiskThresholds).length > 0) {
                payload.per_risk_thresholds = perRiskThresholds;
            }

            const adminPorts = adminPortsForExport(entry);
            if (adminPorts) {
                payload.admin_ports = adminPorts;
            }

            result[key] = payload;
        });
        return result;
    }

    function thresholdsForExport(source) {
        if (!source || typeof source !== 'object') {
            return null;
        }
        const payload = {};
        let hasValue = false;
        Object.entries(source).forEach(([key, value]) => {
            const numberValue = toNumber(value);
            if (numberValue !== null && numberValue !== undefined) {
                payload[key] = numberValue;
                hasValue = true;
            }
        });
        return hasValue ? payload : null;
    }

    function adminPortsForExport(entry) {
        if (!entry || typeof entry !== 'object') {
            return null;
        }
        const baseline = normalizePortNumbers(entry.baselineAdminPorts);
        const perRisk = {};
        Object.entries(entry.perRiskAdminPorts || {}).forEach(([riskKey, values]) => {
            const ports = normalizePortNumbers(values);
            if (ports.length > 0) {
                perRisk[riskKey] = ports;
            }
        });
        if (baseline.length === 0 && Object.keys(perRisk).length === 0) {
            return null;
        }
        const payload = {};
        if (baseline.length > 0) {
            payload.baseline = baseline;
        }
        if (Object.keys(perRisk).length > 0) {
            payload.per_risk_overrides = perRisk;
        }
        return payload;
    }

    function normalizePortNumbers(values) {
        if (!Array.isArray(values)) {
            if (values === undefined || values === null) {
                return [];
            }
            if (typeof values === 'string') {
                values = splitList(values);
            } else {
                values = [values];
            }
        }
        const seen = new Set();
        const result = [];
        values.forEach((value) => {
            const numeric = toNumber(value);
            if (numeric === null || numeric === undefined) {
                return;
            }
            const port = Math.round(numeric);
            if (Number.isInteger(port) && port >= 1 && port <= 65535 && !seen.has(port)) {
                seen.add(port);
                result.push(port);
            }
        });
        return result.sort((a, b) => a - b);
    }

    function ensureConditionTree(rule) {
        if (!rule) {
            return;
        }
        if (!rule.conditionTree) {
            if (isPlainObject(rule.parsedConditions)) {
                rule.conditionTree = normalizeConditionGroup(rule.parsedConditions);
            } else {
                rule.conditionTree = createConditionGroup();
            }
        }
    }

    function ensureAnalyzerEntries(rule) {
        if (!rule) {
            return;
        }
        if (!Array.isArray(rule.analyzerEntries) || rule.analyzerEntries.length === 0) {
            if (isPlainObject(rule.parsedAnalyzers) && Object.keys(rule.parsedAnalyzers).length > 0) {
                rule.analyzerEntries = normalizeAnalyzerEntries(rule.parsedAnalyzers);
            } else {
                rule.analyzerEntries = [createAnalyzerEntry()];
            }
        }
    }

    function syncRuleConditions(rule) {
        if (!rule) {
            return;
        }
        ensureConditionTree(rule);
        rule.parsedConditions = conditionGroupToParsed(rule.conditionTree);
        rule.conditionsText = toYamlString(rule.parsedConditions, DEFAULT_RULE_CONDITIONS_YAML);
    }

    function syncRuleAnalyzers(rule) {
        if (!rule) {
            return;
        }
        ensureAnalyzerEntries(rule);
        rule.parsedAnalyzers = analyzerEntriesToParsed(rule.analyzerEntries);
        rule.analyzersText = toYamlString(rule.parsedAnalyzers, DEFAULT_ANALYZERS_YAML);
    }

    function getRuleDisplayName(rule) {
        const label = (rule?.label || '').trim();
        if (label) {
            return label;
        }
        const key = (rule?.key || '').trim();
        if (key) {
            return key;
        }
        return 'New rule definition';
    }

    function getPrimaryAnalyzer(rule) {
        if (!rule || !Array.isArray(rule.analyzerEntries)) {
            return createAnalyzerEntry();
        }
        return (
            rule.analyzerEntries.find((entry) => (entry.key || '').trim().length > 0) ||
            rule.analyzerEntries[0] ||
            createAnalyzerEntry()
        );
    }

    function getPrimarySeverity(entry) {
        if (!entry || !entry.severityOverrides) {
            return 'Not set';
        }
        for (let index = 0; index < severityOptionValues.length; index += 1) {
            const severity = severityOptionValues[index];
            const value = entry.severityOverrides[severity];
            if (value && String(value).trim().length > 0) {
                return String(value).trim();
            }
        }
        return 'Not set';
    }

    function isRuleEnabled(rule) {
        if (!rule || !Array.isArray(rule.analyzerEntries)) {
            return true;
        }
        return rule.analyzerEntries.some((entry) => entry.enabled !== false);
    }

    function setRuleEnabled(rule, enabled) {
        if (!rule) {
            return;
        }
        ensureAnalyzerEntries(rule);
        rule.analyzerEntries.forEach((entry) => {
            entry.enabled = !!enabled;
        });
        syncRuleAnalyzers(rule);
    }

    function getConditionStats(group) {
        if (!group || typeof group !== 'object') {
            return { conditions: 0, groups: 0 };
        }
        let conditionCount = Array.isArray(group.conditions)
            ? group.conditions.filter((condition) => (condition.field || '').trim()).length
            : 0;
        let groupCount = Array.isArray(group.groups) ? group.groups.length : 0;
        if (Array.isArray(group.groups)) {
            group.groups.forEach((child) => {
                const stats = getConditionStats(child);
                conditionCount += stats.conditions;
                groupCount += stats.groups;
            });
        }
        return { conditions: conditionCount, groups: groupCount };
    }


    const selectors = {
        riskList: '#riskLevelsList',
        cidrList: '#cidrSetsList',
        portList: '#portGroupsList',
        ruleList: '#ruleLogicList',
        validationSummary: '#validationSummary',
        exportButton: '#exportYamlBtn',
        importButton: '#importYamlBtn',
        importInput: '#yamlFileInput',
        toast: '#adminToast',
    };

    const STORAGE_KEY = 'firefind:admin-state:v1';
    const storageAvailable = checkLocalStorageAvailability();

    document.addEventListener('DOMContentLoaded', async () => {
        restoreStateFromCache();
        bindStaticActions();
        renderAll();
        runValidation();
        await loadInitialConfigFromApi();
    });

    function bindStaticActions() {
        const addRiskBtn = document.getElementById('addRiskLevelBtn');
        const addCidrBtn = document.getElementById('addCidrSetBtn');
        const addPortBtn = document.getElementById('addPortGroupBtn');
        const addRuleBtn = document.getElementById('addRuleLogicBtn');
        const exportBtn = document.querySelector(selectors.exportButton);
        const importBtn = document.querySelector(selectors.importButton);
        const importInput = document.querySelector(selectors.importInput);

        addRiskBtn?.addEventListener('click', () => {
            configState.riskLevels.push(createRiskLevel());
            renderRiskLevels();
            runValidation({ suppressErrorToast: true });
            showToast('New risk level added. Populate the fields to finish configuring it.');
        });

        addCidrBtn?.addEventListener('click', () => {
            configState.cidrLimitSets.push(createCidrSet());
            renderCidrSets();
            runValidation({ suppressErrorToast: true });
            showToast('New CIDR limit set added. Provide policy details to complete setup.');
        });

        addPortBtn?.addEventListener('click', () => {
            configState.portGroups.push(createPortGroup());
            renderPortGroups();
            runValidation({ suppressErrorToast: true });
            showToast('New port group added. Add ranges and protocol details to complete configuration.');
        });

        addRuleBtn?.addEventListener('click', () => {
            configState.ruleLogic.push(createRuleDefinition());
            renderRuleLogic();
            runValidation({ suppressErrorToast: true });
            showToast('New rule definition added. Provide identifiers, conditions, and analyzer overrides.');
        });

        exportBtn?.addEventListener('click', () => {
            const snapshot = buildConfigSnapshot();
            const yaml = window.jsyaml.dump(snapshot, { lineWidth: 120 });
            const blob = new Blob([yaml], { type: 'text/yaml' });
            const url = URL.createObjectURL(blob);
            const link = document.createElement('a');
            link.href = url;
            const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
            link.download = `firefind-config-${timestamp}.yaml`;
            link.click();
            URL.revokeObjectURL(url);
            showToast('Exported YAML snapshot.');
        });

        importBtn?.addEventListener('click', () => importInput?.click());

        importInput?.addEventListener('change', (event) => {
            const file = event.target.files?.[0];
            if (!file) {
                return;
            }
            const reader = new FileReader();
            reader.onload = (e) => {
                try {
                    const rawText = String(e.target?.result ?? '');
                    const parsed = window.jsyaml.load(rawText);
                    applyImportedConfig(parsed);
                    showToast(`Imported configuration from ${file.name}.`);
                } catch (error) {
                    console.error('Failed to import YAML', error);
                    showToast('Unable to import file. Ensure it is a valid YAML snapshot.', true);
                } finally {
                    event.target.value = '';
                }
            };
            reader.readAsText(file);
        });
    }

    function renderAll() {
        renderRiskLevels();
        renderCidrSets();
        renderPortGroups();
        renderRuleLogic();
    }

    async function loadInitialConfigFromApi() {
        if (!shouldLoadConfigFromApi()) {
            return;
        }
        try {
            const response = await ruleConfigApi.fetchConfig({ token: 'dev-admin-token' });
            if (response && typeof response === 'object' && response.config && typeof response.config === 'object') {
                applyImportedConfig(response.config);
                showToast('Loaded configuration from backend.', false);
            }
        } catch (error) {
            console.warn('Failed to load configuration from backend.', error);
        }
    }

    function shouldLoadConfigFromApi() {
        const hasPassthroughData =
            passthroughConfig &&
            typeof passthroughConfig === 'object' &&
            Object.keys(passthroughConfig).length > 0;
        return !hasPassthroughData && isEditorStateEmpty();
    }

    function isEditorStateEmpty() {
        return (
            configState.riskLevels.length === 0 &&
            configState.cidrLimitSets.length === 0 &&
            configState.portGroups.length === 0 &&
            configState.ruleLogic.length === 0
        );
    }

    function renderRiskLevels() {
        const container = document.querySelector(selectors.riskList);
        if (!container) {
            return;
        }
        container.innerHTML = '';
        configState.riskLevels.forEach((level) => {
            const card = document.createElement('article');
            card.className = 'config-card risk-level-card';
            card.dataset.levelId = level.id;

            const header = document.createElement('div');
            header.className = 'card-header';
            const title = document.createElement('h3');
            title.textContent = level.name || 'New risk level';
            header.appendChild(title);

            const deleteBtn = document.createElement('button');
            deleteBtn.type = 'button';
            deleteBtn.className = 'icon-btn danger';
            deleteBtn.innerHTML = '<i class="fa-solid fa-trash"></i>';
            deleteBtn.title = 'Delete risk level';
            deleteBtn.addEventListener('click', () => {
                configState.riskLevels = configState.riskLevels.filter((item) => item.id !== level.id);
                renderRiskLevels();
                runValidation();
                showToast(`Removed risk level '${level.name || 'unnamed'}'.`);
            });
            header.appendChild(deleteBtn);
            card.appendChild(header);

            const body = document.createElement('div');
            body.className = 'card-body';

            body.appendChild(createTextField('Identifier', level.name, (value) => {
                level.name = value;
                title.textContent = value || 'New risk level';
                runValidation();
            }, {
                placeholder: 'critical',
                help: 'Unique key used in YAML. Lowercase letters, numbers, dashes or underscores recommended.',
                errorKey: 'name',
            }));

            body.appendChild(createTextField('Label', level.label, (value) => {
                level.label = value;
                runValidation();
            }, {
                placeholder: 'Critical Risk',
                errorKey: 'label',
            }));

            body.appendChild(createSelectField('Severity', severityOptions, level.severity, (value) => {
                level.severity = value;
                runValidation();
            }, {
                errorKey: 'severity',
            }));

            const thresholdsGroup = document.createElement('div');
            thresholdsGroup.className = 'fieldset';
            const thresholdsLegend = document.createElement('div');
            thresholdsLegend.className = 'fieldset-legend';
            thresholdsLegend.innerHTML = '<span>Numeric Thresholds</span><span class="fieldset-hint">Optional bounds controlling how findings roll into this level.</span>';
            thresholdsGroup.appendChild(thresholdsLegend);

            const thresholdsGrid = document.createElement('div');
            thresholdsGrid.className = 'field-grid';
            thresholdsGrid.appendChild(createNumberField('Min Score', level.thresholds.min_score, (value) => {
                level.thresholds.min_score = value;
                runValidation();
            }, {
                min: 0,
                max: 100,
                placeholder: 'e.g. 80',
                errorKey: 'min_score',
            }));
            thresholdsGrid.appendChild(createNumberField('Max Score', level.thresholds.max_score, (value) => {
                level.thresholds.max_score = value;
                runValidation();
            }, {
                min: 0,
                max: 100,
                placeholder: 'e.g. 100',
                errorKey: 'max_score',
            }));
            thresholdsGrid.appendChild(createNumberField('Min Findings', level.thresholds.min_findings, (value) => {
                level.thresholds.min_findings = value;
                runValidation();
            }, {
                min: 0,
                placeholder: 'e.g. 1',
                errorKey: 'min_findings',
            }));
            thresholdsGrid.appendChild(createNumberField('Max Findings', level.thresholds.max_findings, (value) => {
                level.thresholds.max_findings = value;
                runValidation();
            }, {
                min: 0,
                placeholder: 'e.g. 5',
                errorKey: 'max_findings',
            }));
            thresholdsGroup.appendChild(thresholdsGrid);
            thresholdsGroup.appendChild(createFieldError('thresholds'));
            body.appendChild(thresholdsGroup);

            const rationaleGroup = document.createElement('div');
            rationaleGroup.className = 'fieldset';
            const rationaleLegend = document.createElement('div');
            rationaleLegend.className = 'fieldset-legend';
            rationaleLegend.innerHTML = '<span>Rationale</span><span class="fieldset-hint">Explain why this risk level exists. References accept comma or newline separated values.</span>';
            rationaleGroup.appendChild(rationaleLegend);

            rationaleGroup.appendChild(createTextField('Summary', level.rationale.summary, (value) => {
                level.rationale.summary = value;
                runValidation();
            }, {
                placeholder: 'High business impact exposure',
                errorKey: 'rationale_summary',
            }));

            rationaleGroup.appendChild(createTextareaField('Details', level.rationale.details, (value) => {
                level.rationale.details = value;
                runValidation();
            }, {
                rows: 3,
                placeholder: 'Describe the justification or remediation guidance.',
                errorKey: 'rationale_details',
            }));

            rationaleGroup.appendChild(createTextareaField('References', level.rationale.references.join('\n'), (value) => {
                level.rationale.references = splitList(value);
                runValidation();
            }, {
                rows: 2,
                placeholder: 'https://example.com/standard\nPolicy-1234',
                errorKey: 'rationale_references',
            }));

            body.appendChild(rationaleGroup);
            body.appendChild(createFieldError('general'));

            card.appendChild(body);
            container.appendChild(card);
        });
    }

    function renderCidrSets() {
        const container = document.querySelector(selectors.cidrList);
        if (!container) {
            return;
        }
        container.innerHTML = '';
        configState.cidrLimitSets.forEach((set) => {
            const card = document.createElement('article');
            card.className = 'config-card cidr-card';
            card.dataset.setId = set.id;

            const header = document.createElement('div');
            header.className = 'card-header';
            const title = document.createElement('h3');
            title.textContent = set.name || 'New CIDR limit set';
            header.appendChild(title);

            const deleteBtn = document.createElement('button');
            deleteBtn.type = 'button';
            deleteBtn.className = 'icon-btn danger';
            deleteBtn.innerHTML = '<i class="fa-solid fa-trash"></i>';
            deleteBtn.title = 'Delete CIDR limit set';
            deleteBtn.addEventListener('click', () => {
                configState.cidrLimitSets = configState.cidrLimitSets.filter((item) => item.id !== set.id);
                renderCidrSets();
                runValidation();
                showToast(`Removed CIDR set '${set.name || 'unnamed'}'.`);
            });
            header.appendChild(deleteBtn);
            card.appendChild(header);

            const body = document.createElement('div');
            body.className = 'card-body';

            body.appendChild(createTextField('Identifier', set.name, (value) => {
                set.name = value;
                title.textContent = value || 'New CIDR limit set';
                runValidation();
            }, {
                placeholder: 'default_inbound_limits',
                errorKey: 'name',
            }));

            body.appendChild(createPolicyFields('Default Policy', set.defaultPolicy, () => runValidation(), 'default'));

            const overridesSection = document.createElement('div');
            overridesSection.className = 'fieldset';
            const overridesLegend = document.createElement('div');
            overridesLegend.className = 'fieldset-legend';
            overridesLegend.innerHTML = '<span>Overrides</span><span class="fieldset-hint">Apply analyzer, vendor, direction, or vendor+direction specific policies.</span>';
            overridesSection.appendChild(overridesLegend);

            const overridesList = document.createElement('div');
            overridesList.className = 'overrides-list';
            overridesList.dataset.setId = set.id;

            set.overrides.forEach((override) => {
                overridesList.appendChild(renderOverrideRow(set, override));
            });

            const addOverrideBtn = document.createElement('button');
            addOverrideBtn.type = 'button';
            addOverrideBtn.className = 'btn tertiary';
            addOverrideBtn.innerHTML = '<i class="fa-solid fa-layer-group"></i> Add Override';
            addOverrideBtn.addEventListener('click', () => {
                const override = createCidrOverride();
                set.overrides.push(override);
                renderCidrSets();
                runValidation();
            });

            overridesSection.appendChild(overridesList);
            overridesSection.appendChild(addOverrideBtn);
            overridesSection.appendChild(createFieldError('overrides'));
            body.appendChild(overridesSection);
            body.appendChild(createFieldError('general'));

            card.appendChild(body);
            container.appendChild(card);
        });
    }

    function renderOverrideRow(set, override) {
        const row = document.createElement('div');
        row.className = 'override-row';
        row.dataset.overrideId = override.id;

        const typeField = createSelectField('Type', [
            { value: 'analyzer', label: 'Analyzer' },
            { value: 'vendor', label: 'Vendor' },
            { value: 'direction', label: 'Direction' },
            { value: 'vendor_direction', label: 'Vendor + Direction' },
        ], override.scope, (value) => {
            override.scope = value;
            if (value !== 'vendor_direction') {
                override.vendor = '';
                override.direction = '';
            }
            renderCidrSets();
            runValidation();
        }, {
            compact: true,
            errorKey: `${override.id}_scope`,
        });
        row.appendChild(typeField);

        if (override.scope === 'vendor_direction') {
            row.appendChild(createTextField('Vendor', override.vendor, (value) => {
                override.vendor = value;
                runValidation();
            }, { compact: true, placeholder: 'vendor-name', errorKey: `${override.id}_vendor` }));
            row.appendChild(createTextField('Direction', override.direction, (value) => {
                override.direction = value;
                runValidation();
            }, { compact: true, placeholder: 'outbound', errorKey: `${override.id}_direction` }));
        } else {
            row.appendChild(createTextField('Key', override.key, (value) => {
                override.key = value;
                runValidation();
            }, { compact: true, placeholder: 'analyzer id', errorKey: `${override.id}_key` }));
        }

        row.appendChild(createPolicyFields('Policy', override.policy, () => runValidation(), override.id, true));

        const deleteBtn = document.createElement('button');
        deleteBtn.type = 'button';
        deleteBtn.className = 'icon-btn';
        deleteBtn.innerHTML = '<i class="fa-solid fa-xmark"></i>';
        deleteBtn.title = 'Remove override';
        deleteBtn.addEventListener('click', () => {
            set.overrides = set.overrides.filter((item) => item.id !== override.id);
            renderCidrSets();
            runValidation();
        });
        row.appendChild(deleteBtn);

        return row;
    }

    function renderPortGroups() {
        const container = document.querySelector(selectors.portList);
        if (!container) {
            return;
        }
        container.innerHTML = '';
        configState.portGroups.forEach((group) => {
            const card = document.createElement('article');
            card.className = 'config-card port-group-card';
            card.dataset.groupId = group.id;

            const header = document.createElement('div');
            header.className = 'card-header';
            const title = document.createElement('h3');
            title.textContent = group.name || 'New port group';
            header.appendChild(title);

            const deleteBtn = document.createElement('button');
            deleteBtn.type = 'button';
            deleteBtn.className = 'icon-btn danger';
            deleteBtn.innerHTML = '<i class="fa-solid fa-trash"></i>';
            deleteBtn.title = 'Delete port group';
            deleteBtn.addEventListener('click', () => {
                configState.portGroups = configState.portGroups.filter((item) => item.id !== group.id);
                renderPortGroups();
                runValidation();
                showToast(`Removed port group '${group.name || 'unnamed'}'.`);
            });
            header.appendChild(deleteBtn);
            card.appendChild(header);

            const body = document.createElement('div');
            body.className = 'card-body';

            body.appendChild(createTextField('Identifier', group.name, (value) => {
                group.name = value;
                title.textContent = value || 'New port group';
                runValidation();
            }, {
                placeholder: 'critical_admin_ports',
                errorKey: 'name',
            }));

            body.appendChild(createTextareaField('Description', group.description, (value) => {
                group.description = value;
                runValidation();
            }, {
                rows: 2,
                placeholder: 'Optional description for documentation.',
                errorKey: 'description',
            }));

            body.appendChild(createSelectField('Protocol', [
                { value: 'any', label: 'Any' },
                { value: 'tcp', label: 'TCP' },
                { value: 'udp', label: 'UDP' },
            ], group.protocol, (value) => {
                group.protocol = value;
                runValidation();
            }, {
                errorKey: 'protocol',
            }));

            const rangesSection = document.createElement('div');
            rangesSection.className = 'fieldset';
            const rangesLegend = document.createElement('div');
            rangesLegend.className = 'fieldset-legend';
            rangesLegend.innerHTML = '<span>Port Ranges</span><span class="fieldset-hint">Specify single ports or inclusive ranges. Overlaps are rejected.</span>';
            rangesSection.appendChild(rangesLegend);

            const rangesList = document.createElement('div');
            rangesList.className = 'ranges-list';
            rangesList.dataset.groupId = group.id;

            group.ranges.forEach((range) => {
                const rangeRow = document.createElement('div');
                rangeRow.className = 'range-row';
                rangeRow.dataset.rangeId = range.id;

                rangeRow.appendChild(createNumberField('Start', range.start, (value) => {
                    range.start = value;
                    runValidation();
                }, {
                    min: 1,
                    max: 65535,
                    compact: true,
                    errorKey: `start_${range.id}`,
                }));

                rangeRow.appendChild(createNumberField('End', range.end, (value) => {
                    range.end = value;
                    runValidation();
                }, {
                    min: 1,
                    max: 65535,
                    compact: true,
                    errorKey: `end_${range.id}`,
                }));

                const removeBtn = document.createElement('button');
                removeBtn.type = 'button';
                removeBtn.className = 'icon-btn';
                removeBtn.innerHTML = '<i class="fa-solid fa-xmark"></i>';
                removeBtn.title = 'Remove range';
                removeBtn.addEventListener('click', () => {
                    group.ranges = group.ranges.filter((item) => item.id !== range.id);
                    renderPortGroups();
                    runValidation();
                });
                rangeRow.appendChild(removeBtn);
                rangeRow.appendChild(createFieldError(`range_${range.id}`));
                rangesList.appendChild(rangeRow);
            });

            const addRangeBtn = document.createElement('button');
            addRangeBtn.type = 'button';
            addRangeBtn.className = 'btn tertiary';
            addRangeBtn.innerHTML = '<i class="fa-solid fa-plus"></i> Add Range';
            addRangeBtn.addEventListener('click', () => {
                group.ranges.push(createRange());
                renderPortGroups();
                runValidation();
            });

            rangesSection.appendChild(rangesList);
            rangesSection.appendChild(addRangeBtn);
            rangesSection.appendChild(createFieldError('ranges'));
            body.appendChild(rangesSection);
            body.appendChild(createFieldError('general'));

            card.appendChild(body);
            container.appendChild(card);
        });
    }

    function renderRuleLogic() {
        const container = document.querySelector(selectors.ruleList);
        if (!container) {
            return;
        }
        if (!ruleListView) {
            ruleListView = createRuleList(container);
        }
        ruleListView.update(configState.ruleLogic);
    }

    function createRuleList(container) {
        container.classList.add('rule-logic-container');
        return {
            update(rules) {
                container.innerHTML = '';
                if (!Array.isArray(rules) || rules.length === 0) {
                    const empty = document.createElement('div');
                    empty.className = 'empty-state';
                    empty.textContent = 'No rule definitions configured yet. Add a rule to begin authoring logic.';
                    container.appendChild(empty);
                    return;
                }
                rules.forEach((rule, index) => {
                    ensureConditionTree(rule);
                    ensureAnalyzerEntries(rule);
                    const card = buildRuleCard(rule, index);
                    container.appendChild(card);
                    updateRulePreview(card, rule);
                });
            },
        };
    }

    function buildRuleCard(rule, index) {
        const card = document.createElement('article');
        card.className = 'config-card rule-logic-card';
        card.dataset.ruleId = rule.id;

        const header = document.createElement('div');
        header.className = 'card-header rule-card-header';

        const titleGroup = document.createElement('div');
        titleGroup.className = 'rule-card-header-info';
        const title = document.createElement('h3');
        title.className = 'rule-card-title';
        title.textContent = getRuleDisplayName(rule);
        title.id = `${rule.id}-title`;
        titleGroup.appendChild(title);

        const meta = document.createElement('div');
        meta.className = 'rule-card-meta';
        const primaryAnalyzer = getPrimaryAnalyzer(rule);
        const severityLabel = getPrimarySeverity(primaryAnalyzer);
        const conditionStats = getConditionStats(rule.conditionTree);

        meta.appendChild(createMetaItem('fa-microchip', primaryAnalyzer.key ? primaryAnalyzer.key : 'Unassigned analyzer'));
        meta.appendChild(createMetaItem('fa-signal', `Severity: ${severityLabel}`));
        const conditionSummary = `${conditionStats.conditions} condition${conditionStats.conditions === 1 ? '' : 's'}`;
        const groupSummary = `${conditionStats.groups} nested group${conditionStats.groups === 1 ? '' : 's'}`;
        meta.appendChild(createMetaItem('fa-diagram-project', `${conditionSummary}, ${groupSummary}`));
        titleGroup.appendChild(meta);
        header.appendChild(titleGroup);

        const actions = document.createElement('div');
        actions.className = 'rule-card-actions';

        const toggleLabel = document.createElement('label');
        toggleLabel.className = 'toggle rule-enable-toggle';
        toggleLabel.setAttribute('aria-label', `Toggle ${getRuleDisplayName(rule)} enabled state`);
        const toggleInput = document.createElement('input');
        toggleInput.type = 'checkbox';
        toggleInput.checked = isRuleEnabled(rule);
        toggleInput.addEventListener('change', (event) => {
            setRuleEnabled(rule, event.target.checked);
            runValidation({ suppressErrorToast: true });
            renderRuleLogic();
        });
        const toggleSlider = document.createElement('span');
        toggleSlider.className = 'toggle-slider';
        toggleLabel.appendChild(toggleInput);
        toggleLabel.appendChild(toggleSlider);
        actions.appendChild(toggleLabel);

        const editBtn = document.createElement('button');
        editBtn.type = 'button';
        editBtn.className = 'btn btn-secondary rule-edit-btn';
        editBtn.innerHTML = '<i class="fa-solid fa-pen-to-square" aria-hidden="true"></i> Edit';
        editBtn.addEventListener('click', () => openRuleEditor(rule, index));
        actions.appendChild(editBtn);

        const deleteBtn = document.createElement('button');
        deleteBtn.type = 'button';
        deleteBtn.className = 'icon-btn danger';
        deleteBtn.innerHTML = '<i class="fa-solid fa-trash" aria-hidden="true"></i>';
        deleteBtn.setAttribute('aria-label', `Delete ${getRuleDisplayName(rule)}`);
        deleteBtn.addEventListener('click', () => {
            configState.ruleLogic = configState.ruleLogic.filter((item) => item.id !== rule.id);
            renderRuleLogic();
            runValidation();
            showToast(`Removed rule definition '${getRuleDisplayName(rule)}'.`);
        });
        actions.appendChild(deleteBtn);

        header.appendChild(actions);
        card.appendChild(header);

        const body = document.createElement('div');
        body.className = 'card-body rule-card-body';

        const description = document.createElement('p');
        description.className = 'rule-card-description';
        description.textContent = (rule.description || '').trim() || 'No description provided yet.';
        body.appendChild(description);

        const detailList = document.createElement('dl');
        detailList.className = 'rule-detail-list';
        appendDetail(detailList, 'Rule identifier', (rule.key || '').trim() || '—');
        appendDetail(detailList, 'Rule ID', (rule.ruleId || '').trim() || '—');
        appendDetail(
            detailList,
            'Analyzers configured',
            Array.isArray(rule.analyzerEntries)
                ? rule.analyzerEntries.filter((entry) => (entry.key || '').trim()).length || '0'
                : '0',
        );
        appendDetail(detailList, 'Condition logic', `${conditionSummary}, ${groupSummary}`);
        body.appendChild(detailList);

        const preview = document.createElement('div');
        preview.className = 'rule-card-preview';
        const previewHeading = document.createElement('h4');
        previewHeading.textContent = 'Validation';
        preview.appendChild(previewHeading);
        const previewList = document.createElement('ul');
        previewList.className = 'rule-validation-list';
        previewList.setAttribute('role', 'list');
        previewList.dataset.role = 'rule-validation-summary';
        preview.appendChild(previewList);
        body.appendChild(preview);

        const errors = document.createElement('div');
        errors.className = 'rule-card-errors';
        ['general', 'key', 'ruleId', 'label', 'conditions', 'analyzers', 'thresholds', 'adminPorts'].forEach((key) => {
            const errorEl = document.createElement('div');
            errorEl.className = 'field-error';
            errorEl.dataset.errorKey = key;
            errors.appendChild(errorEl);
        });
        body.appendChild(errors);

        card.appendChild(body);
        return card;
    }

    function createMetaItem(iconClass, text) {
        const item = document.createElement('span');
        item.className = 'rule-card-meta-item';
        const icon = document.createElement('i');
        icon.className = `fa-solid ${iconClass}`;
        icon.setAttribute('aria-hidden', 'true');
        item.appendChild(icon);
        item.appendChild(document.createTextNode(` ${text}`));
        return item;
    }

    function appendDetail(container, term, value) {
        const dt = document.createElement('dt');
        dt.textContent = term;
        const dd = document.createElement('dd');
        dd.textContent = value;
        container.appendChild(dt);
        container.appendChild(dd);
    }

    function updateRulePreview(card, rule) {
        if (!card) {
            return;
        }
        const list = card.querySelector('[data-role="rule-validation-summary"]');
        if (!list) {
            return;
        }
        list.innerHTML = '';
        const messages = Array.isArray(rule.validationMessages) ? rule.validationMessages : [];
        if (messages.length === 0) {
            const item = document.createElement('li');
            item.className = 'validation-success';
            item.textContent = 'Rule is valid.';
            list.appendChild(item);
            return;
        }
        messages.forEach((message) => {
            const item = document.createElement('li');
            item.textContent = message;
            list.appendChild(item);
        });
    }

    function openRuleEditor(rule, index = 0) {
        if (!ruleEditor) {
            ruleEditor = createRuleEditor();
        }
        ruleEditor.open(rule, index);
    }

    function createRuleEditor() {
        const backdrop = document.createElement('div');
        backdrop.className = 'modal-backdrop hidden';
        backdrop.dataset.component = 'rule-editor';

        const modal = document.createElement('div');
        modal.className = 'modal rule-editor-modal';
        modal.setAttribute('role', 'dialog');
        modal.setAttribute('aria-modal', 'true');
        modal.setAttribute('aria-labelledby', 'ruleEditorTitle');
        backdrop.appendChild(modal);

        const header = document.createElement('header');
        header.className = 'modal-header';
        const title = document.createElement('h2');
        title.id = 'ruleEditorTitle';
        title.textContent = 'Edit rule';
        header.appendChild(title);
        const subtitle = document.createElement('p');
        subtitle.className = 'modal-subtitle';
        subtitle.textContent = 'Configure metadata, condition groups, analyzer overrides, and validation thresholds.';
        header.appendChild(subtitle);
        const closeBtn = document.createElement('button');
        closeBtn.type = 'button';
        closeBtn.className = 'icon-btn';
        closeBtn.innerHTML = '<i class="fa-solid fa-xmark" aria-hidden="true"></i><span class="sr-only">Close editor</span>';
        header.appendChild(closeBtn);
        modal.appendChild(header);

        const form = document.createElement('form');
        form.className = 'rule-editor-form';
        form.noValidate = true;
        modal.appendChild(form);

        const metadataSection = document.createElement('section');
        metadataSection.className = 'rule-editor-section';
        metadataSection.dataset.section = 'metadata';
        form.appendChild(metadataSection);

        const conditionsSection = document.createElement('section');
        conditionsSection.className = 'rule-editor-section';
        conditionsSection.dataset.section = 'conditions';
        form.appendChild(conditionsSection);

        const analyzersSection = document.createElement('section');
        analyzersSection.className = 'rule-editor-section';
        analyzersSection.dataset.section = 'analyzers';
        form.appendChild(analyzersSection);

        const validationSection = document.createElement('section');
        validationSection.className = 'rule-editor-section';
        validationSection.dataset.section = 'validation';
        const validationHeading = document.createElement('h3');
        validationHeading.textContent = 'Validation summary';
        validationSection.appendChild(validationHeading);
        const validationList = document.createElement('ul');
        validationList.className = 'rule-validation-list';
        validationList.setAttribute('role', 'list');
        validationList.dataset.role = 'editor-validation-summary';
        validationSection.appendChild(validationList);
        form.appendChild(validationSection);

        const footer = document.createElement('footer');
        footer.className = 'modal-footer';
        const cancelBtn = document.createElement('button');
        cancelBtn.type = 'button';
        cancelBtn.className = 'btn btn-secondary';
        cancelBtn.textContent = 'Cancel';
        const saveBtn = document.createElement('button');
        saveBtn.type = 'submit';
        saveBtn.className = 'btn btn-primary';
        saveBtn.textContent = 'Save rule';
        footer.appendChild(cancelBtn);
        footer.appendChild(saveBtn);
        modal.appendChild(footer);

        document.body.appendChild(backdrop);

        let activeRule = null;
        let draft = null;
        let returnFocus = null;
        const errorTargets = new Map();

        function open(rule) {
            activeRule = rule;
            ensureConditionTree(rule);
            ensureAnalyzerEntries(rule);
            draft = createRuleDraft(rule);
            title.textContent = `Edit rule – ${getRuleDisplayName(draft)}`;
            renderMetadataSection();
            renderConditionSection();
            renderAnalyzerSection();
            collectErrorTargets();
            updateDraftValidation();
            backdrop.classList.add('visible');
            backdrop.classList.remove('hidden');
            backdrop.hidden = false;
            returnFocus = document.activeElement;
            focusFirstField();
            updateFocusableElements();
        }

        function close() {
            backdrop.classList.remove('visible');
            backdrop.classList.add('hidden');
            backdrop.hidden = true;
            activeRule = null;
            draft = null;
            if (returnFocus && typeof returnFocus.focus === 'function') {
                returnFocus.focus();
            }
        }

        function collectErrorTargets() {
            errorTargets.clear();
            backdrop.querySelectorAll('.field-error[data-error-key]').forEach((element) => {
                const key = element.dataset.errorKey;
                if (key) {
                    errorTargets.set(key, element);
                }
            });
        }

        function applyEditorErrors(errors = {}) {
            errorTargets.forEach((element, key) => {
                const message = errors[key];
                if (message) {
                    element.textContent = message;
                    element.classList.add('visible');
                } else {
                    element.textContent = '';
                    element.classList.remove('visible');
                }
            });
        }

        function renderMetadataSection() {
            metadataSection.innerHTML = '';
            const heading = document.createElement('h3');
            heading.textContent = 'Rule metadata';
            metadataSection.appendChild(heading);

            const grid = document.createElement('div');
            grid.className = 'editor-grid';
            grid.appendChild(
                createTextField('Rule identifier', draft.key, (value) => {
                    draft.key = value;
                    title.textContent = `Edit rule – ${getRuleDisplayName(draft)}`;
                    updateDraftValidation();
                }, {
                    placeholder: 'admin_port_exposed',
                    help: 'Unique key used within the exported YAML rules mapping.',
                    errorKey: 'key',
                    spellcheck: false,
                }),
            );
            grid.appendChild(
                createTextField('Rule ID', draft.ruleId, (value) => {
                    draft.ruleId = value;
                    updateDraftValidation();
                }, {
                    placeholder: 'admin_port_exposed',
                    help: 'Defaults to the rule identifier when omitted.',
                    errorKey: 'ruleId',
                    spellcheck: false,
                }),
            );
            grid.appendChild(
                createTextField('Label', draft.label, (value) => {
                    draft.label = value;
                    title.textContent = `Edit rule – ${getRuleDisplayName(draft)}`;
                    updateDraftValidation();
                }, {
                    placeholder: 'Administrative Port Exposure',
                    errorKey: 'label',
                }),
            );
            metadataSection.appendChild(grid);

            metadataSection.appendChild(
                createTextareaField('Description', draft.description, (value) => {
                    draft.description = value;
                    updateDraftValidation();
                }, {
                    rows: 4,
                    placeholder: 'Explain what the rule detects and how results should be interpreted.',
                    errorKey: 'description',
                }),
            );
        }

        function renderConditionSection() {
            conditionsSection.innerHTML = '';
            const heading = document.createElement('h3');
            heading.textContent = 'Condition groups';
            conditionsSection.appendChild(heading);
            const help = document.createElement('p');
            help.className = 'section-hint';
            help.textContent = 'Construct nested ALL/ANY groups with field comparators to describe when the rule should trigger.';
            conditionsSection.appendChild(help);

            const treeContainer = document.createElement('div');
            treeContainer.className = 'condition-tree';
            conditionsSection.appendChild(treeContainer);
            renderConditionGroupEditor(treeContainer, draft.conditionTree, []);
        }

        function renderAnalyzerSection() {
            analyzersSection.innerHTML = '';
            const heading = document.createElement('h3');
            heading.textContent = 'Analyzer overrides';
            analyzersSection.appendChild(heading);
            const help = document.createElement('p');
            help.className = 'section-hint';
            help.textContent = 'Bind analyzers to this rule, configure severity overrides, thresholds, and administrative port handling.';
            analyzersSection.appendChild(help);

            const list = document.createElement('div');
            list.className = 'analyzer-editor-list';
            analyzersSection.appendChild(list);

            draft.analyzerEntries.forEach((entry, index) => {
                list.appendChild(createAnalyzerEditor(entry, index));
            });

            const addButton = document.createElement('button');
            addButton.type = 'button';
            addButton.className = 'btn btn-secondary';
            addButton.innerHTML = '<i class="fa-solid fa-plus" aria-hidden="true"></i> Add analyzer';
            addButton.addEventListener('click', () => {
                const newEntry = createAnalyzerEntry();
                draft.analyzerEntries.push(newEntry);
                renderAnalyzerSection();
                updateDraftValidation();
                requestAnimationFrame(() => {
                    const field = analyzersSection.querySelector(`[data-analyzer-id="${newEntry.id}"] input[type="text"]`);
                    field?.focus();
                });
            });
            analyzersSection.appendChild(addButton);
            collectErrorTargets();
        }

        function renderConditionGroupEditor(container, group, path) {
            const groupWrapper = document.createElement('div');
            groupWrapper.className = 'condition-group';
            groupWrapper.dataset.groupId = group.id;

            const headerRow = document.createElement('div');
            headerRow.className = 'condition-group-header';
            const logicLabel = document.createElement('label');
            logicLabel.className = 'condition-logic-label';
            logicLabel.textContent = 'Logic';
            const logicSelect = document.createElement('select');
            logicSelect.className = 'condition-logic-select';
            const allOption = document.createElement('option');
            allOption.value = 'all';
            allOption.textContent = 'ALL conditions must match';
            const anyOption = document.createElement('option');
            anyOption.value = 'any';
            anyOption.textContent = 'ANY condition may match';
            logicSelect.appendChild(allOption);
            logicSelect.appendChild(anyOption);
            logicSelect.value = group.logic === 'any' ? 'any' : 'all';
            logicSelect.addEventListener('change', (event) => {
                group.logic = event.target.value === 'any' ? 'any' : 'all';
                updateDraftValidation();
            });
            logicLabel.appendChild(logicSelect);
            headerRow.appendChild(logicLabel);

            if (path.length > 0) {
                const removeGroupBtn = document.createElement('button');
                removeGroupBtn.type = 'button';
                removeGroupBtn.className = 'icon-btn danger';
                removeGroupBtn.innerHTML = '<i class="fa-solid fa-trash" aria-hidden="true"></i><span class="sr-only">Remove group</span>';
                removeGroupBtn.addEventListener('click', () => {
                    const parentGroup = getGroupAtPath(draft.conditionTree, path.slice(0, -1));
                    if (!parentGroup) {
                        return;
                    }
                    parentGroup.groups.splice(path[path.length - 1], 1);
                    groupWrapper.remove();
                    updateDraftValidation();
                    collectErrorTargets();
                });
                headerRow.appendChild(removeGroupBtn);
            }

            groupWrapper.appendChild(headerRow);

            const conditionList = document.createElement('div');
            conditionList.className = 'condition-list';
            group.conditions.forEach((condition) => {
                conditionList.appendChild(createConditionRow(group, condition));
            });
            groupWrapper.appendChild(conditionList);

            const addConditionBtn = document.createElement('button');
            addConditionBtn.type = 'button';
            addConditionBtn.className = 'btn btn-tertiary';
            addConditionBtn.innerHTML = '<i class="fa-solid fa-plus" aria-hidden="true"></i> Add condition';
            addConditionBtn.addEventListener('click', () => {
                const newCondition = createConditionEntry();
                group.conditions.push(newCondition);
                const row = createConditionRow(group, newCondition);
                conditionList.appendChild(row);
                updateDraftValidation();
                requestAnimationFrame(() => {
                    row.querySelector('input')?.focus();
                });
                collectErrorTargets();
            });

            const addGroupBtn = document.createElement('button');
            addGroupBtn.type = 'button';
            addGroupBtn.className = 'btn btn-tertiary';
            addGroupBtn.innerHTML = '<i class="fa-solid fa-diagram-project" aria-hidden="true"></i> Add nested group';
            addGroupBtn.addEventListener('click', () => {
                const newGroup = createConditionGroup('all');
                group.groups.push(newGroup);
                renderConditionGroupEditor(childrenContainer, newGroup, [...path, group.groups.length - 1]);
                updateDraftValidation();
                collectErrorTargets();
            });

            const actionsRow = document.createElement('div');
            actionsRow.className = 'condition-actions';
            actionsRow.appendChild(addConditionBtn);
            actionsRow.appendChild(addGroupBtn);
            groupWrapper.appendChild(actionsRow);

            const childrenContainer = document.createElement('div');
            childrenContainer.className = 'condition-children';
            group.groups.forEach((childGroup, childIndex) => {
                renderConditionGroupEditor(childrenContainer, childGroup, [...path, childIndex]);
            });
            groupWrapper.appendChild(childrenContainer);

            container.appendChild(groupWrapper);
        }

        function getGroupAtPath(group, path) {
            let current = group;
            for (let index = 0; index < path.length; index += 1) {
                if (!current || !Array.isArray(current.groups)) {
                    return null;
                }
                current = current.groups[path[index]];
            }
            return current;
        }

        function createConditionRow(group, condition) {
            const row = document.createElement('div');
            row.className = 'condition-row';
            row.dataset.conditionId = condition.id;

            const fieldInput = document.createElement('input');
            fieldInput.type = 'text';
            fieldInput.className = 'condition-field-input';
            fieldInput.placeholder = 'Field';
            fieldInput.value = condition.field || '';
            fieldInput.addEventListener('input', (event) => {
                condition.field = event.target.value;
                updateDraftValidation();
            });
            row.appendChild(fieldInput);

            const comparatorSelect = document.createElement('select');
            comparatorSelect.className = 'condition-comparator-select';
            comparatorOptions.forEach((option) => {
                const opt = document.createElement('option');
                opt.value = option.value;
                opt.textContent = option.label;
                comparatorSelect.appendChild(opt);
            });
            comparatorSelect.value = condition.comparator || 'equals';
            comparatorSelect.addEventListener('change', (event) => {
                condition.comparator = event.target.value;
                adjustValueFields();
                updateDraftValidation();
            });
            row.appendChild(comparatorSelect);

            const valueWrapper = document.createElement('div');
            valueWrapper.className = 'condition-value-wrapper';
            const valueInput = document.createElement('input');
            valueInput.type = 'text';
            valueInput.placeholder = 'Value';
            valueInput.value = condition.value || '';
            valueInput.addEventListener('input', (event) => {
                condition.value = event.target.value;
                updateDraftValidation();
            });
            valueWrapper.appendChild(valueInput);

            const multiWrapper = document.createElement('div');
            multiWrapper.className = 'condition-multi-wrapper';
            const multiTextarea = document.createElement('textarea');
            multiTextarea.rows = 2;
            multiTextarea.placeholder = 'Value per line';
            multiTextarea.value = Array.isArray(condition.values) ? condition.values.join('\n') : '';
            multiTextarea.addEventListener('input', (event) => {
                condition.values = splitList(event.target.value);
                updateDraftValidation();
            });
            multiWrapper.appendChild(multiTextarea);

            row.appendChild(valueWrapper);
            row.appendChild(multiWrapper);

            const removeBtn = document.createElement('button');
            removeBtn.type = 'button';
            removeBtn.className = 'icon-btn danger';
            removeBtn.innerHTML = '<i class="fa-solid fa-trash" aria-hidden="true"></i><span class="sr-only">Remove condition</span>';
            removeBtn.addEventListener('click', () => {
                const index = group.conditions.indexOf(condition);
                if (index >= 0) {
                    group.conditions.splice(index, 1);
                }
                row.remove();
                updateDraftValidation();
                collectErrorTargets();
            });
            row.appendChild(removeBtn);

            const errorEl = document.createElement('div');
            errorEl.className = 'field-error';
            errorEl.dataset.errorKey = `condition_${condition.id}`;
            row.appendChild(errorEl);

            function adjustValueFields() {
                const comparator = condition.comparator || 'equals';
                const isMulti = comparatorValueModes.multi.has(comparator);
                const noValue = comparatorValueModes.none.has(comparator);
                if (noValue) {
                    valueInput.value = '';
                    condition.value = '';
                    multiTextarea.value = '';
                    condition.values = [];
                }
                valueWrapper.classList.toggle('hidden', isMulti || noValue);
                multiWrapper.classList.toggle('hidden', !isMulti);
            }

            adjustValueFields();
            return row;
        }

        function createAnalyzerEditor(entry, index) {
            const panel = document.createElement('div');
            panel.className = 'analyzer-panel';
            panel.dataset.analyzerId = entry.id;

            const heading = document.createElement('header');
            heading.className = 'analyzer-panel-header';
            const title = document.createElement('h4');
            title.textContent = entry.key ? entry.key : `Analyzer ${index + 1}`;
            heading.appendChild(title);

            const enabledToggle = document.createElement('label');
            enabledToggle.className = 'toggle';
            enabledToggle.setAttribute('aria-label', `Toggle analyzer ${index + 1}`);
            const enabledInput = document.createElement('input');
            enabledInput.type = 'checkbox';
            enabledInput.checked = entry.enabled !== false;
            enabledInput.addEventListener('change', (event) => {
                entry.enabled = event.target.checked;
                updateDraftValidation();
            });
            const enabledSlider = document.createElement('span');
            enabledSlider.className = 'toggle-slider';
            enabledToggle.appendChild(enabledInput);
            enabledToggle.appendChild(enabledSlider);
            heading.appendChild(enabledToggle);

            const removeBtn = document.createElement('button');
            removeBtn.type = 'button';
            removeBtn.className = 'icon-btn danger';
            removeBtn.innerHTML = '<i class="fa-solid fa-trash" aria-hidden="true"></i><span class="sr-only">Remove analyzer</span>';
            removeBtn.addEventListener('click', () => {
                draft.analyzerEntries.splice(index, 1);
                renderAnalyzerSection();
                updateDraftValidation();
            });
            heading.appendChild(removeBtn);

            panel.appendChild(heading);

            const body = document.createElement('div');
            body.className = 'analyzer-panel-body';

            body.appendChild(
                createTextField('Analyzer key', entry.key, (value) => {
                    entry.key = value;
                    title.textContent = value.trim() || `Analyzer ${index + 1}`;
                    updateDraftValidation();
                }, {
                    spellcheck: false,
                    errorKey: `analyzer_${entry.id}_key`,
                    placeholder: 'admin_port_exposed',
                }),
            );

            body.appendChild(
                createTextareaField('Notes', entry.notes, (value) => {
                    entry.notes = value;
                }, {
                    rows: 3,
                    placeholder: 'Explain analyzer-specific behaviour for this rule.',
                }),
            );

            const severityTable = document.createElement('div');
            severityTable.className = 'severity-grid';
            severityOptions.forEach((option) => {
                const label = document.createElement('label');
                label.className = 'form-field compact';
                label.innerHTML = `<span class="field-label">${option.label}</span>`;
                const select = document.createElement('select');
                const inheritOption = document.createElement('option');
                inheritOption.value = '';
                inheritOption.textContent = 'Inherit';
                select.appendChild(inheritOption);
                severityOptions.forEach((severity) => {
                    const opt = document.createElement('option');
                    opt.value = severity.value;
                    opt.textContent = severity.label;
                    select.appendChild(opt);
                });
                select.value = entry.severityOverrides?.[option.value] || '';
                select.addEventListener('change', (event) => {
                    entry.severityOverrides[option.value] = event.target.value;
                    updateDraftValidation();
                });
                label.appendChild(select);
                severityTable.appendChild(label);
            });
            body.appendChild(severityTable);

            const thresholds = document.createElement('div');
            thresholds.className = 'thresholds-section';
            const thresholdsHeading = document.createElement('h5');
            thresholdsHeading.textContent = 'Thresholds';
            thresholds.appendChild(thresholdsHeading);
            thresholds.appendChild(createThresholdGrid(entry.baselineThresholds, (key, value) => {
                entry.baselineThresholds[key] = value;
                updateDraftValidation();
            }, `analyzer_${entry.id}_thresholds`));

            const perRiskContainer = document.createElement('div');
            perRiskContainer.className = 'per-risk-container';
            const perRiskHeading = document.createElement('h6');
            perRiskHeading.textContent = 'Per risk overrides';
            perRiskContainer.appendChild(perRiskHeading);
            Object.entries(entry.perRiskThresholds || {}).forEach(([riskKey, value]) => {
                perRiskContainer.appendChild(createRiskThresholdEditor(entry, riskKey, value));
            });
            const addRiskBtn = document.createElement('button');
            addRiskBtn.type = 'button';
            addRiskBtn.className = 'btn btn-tertiary';
            addRiskBtn.textContent = 'Add risk override';
            addRiskBtn.addEventListener('click', () => {
                const newKey = '';
                entry.perRiskThresholds[newKey] = createThresholds();
                renderAnalyzerSection();
                updateDraftValidation();
            });
            perRiskContainer.appendChild(addRiskBtn);
            thresholds.appendChild(perRiskContainer);
            body.appendChild(thresholds);

            const adminPorts = document.createElement('div');
            adminPorts.className = 'admin-port-section';
            const portsHeading = document.createElement('h5');
            portsHeading.textContent = 'Administrative ports';
            adminPorts.appendChild(portsHeading);

            adminPorts.appendChild(
                createTextareaField('Baseline ports', entry.baselineAdminPorts.join('\n'), (value) => {
                    entry.baselineAdminPorts = splitList(value);
                    updateDraftValidation();
                }, {
                    rows: 3,
                    placeholder: '22\n443\n3389',
                    errorKey: `analyzer_${entry.id}_baseline_ports`,
                    spellcheck: false,
                }),
            );

            const perRiskPorts = document.createElement('div');
            perRiskPorts.className = 'per-risk-container';
            const portsSubHeading = document.createElement('h6');
            portsSubHeading.textContent = 'Per risk overrides';
            perRiskPorts.appendChild(portsSubHeading);
            Object.entries(entry.perRiskAdminPorts || {}).forEach(([riskKey, values]) => {
                perRiskPorts.appendChild(createRiskPortEditor(entry, riskKey, values));
            });
            const addPortRisk = document.createElement('button');
            addPortRisk.type = 'button';
            addPortRisk.className = 'btn btn-tertiary';
            addPortRisk.textContent = 'Add risk override';
            addPortRisk.addEventListener('click', () => {
                entry.perRiskAdminPorts[''] = [];
                renderAnalyzerSection();
                updateDraftValidation();
            });
            perRiskPorts.appendChild(addPortRisk);
            adminPorts.appendChild(perRiskPorts);

            body.appendChild(adminPorts);

            const analyzerErrors = document.createElement('div');
            analyzerErrors.className = 'analyzer-errors';
            ['analyzer', 'thresholds', 'adminPorts'].forEach((key) => {
                const error = document.createElement('div');
                error.className = 'field-error';
                error.dataset.errorKey = `analyzer_${entry.id}_${key}`;
                analyzerErrors.appendChild(error);
            });
            body.appendChild(analyzerErrors);

            panel.appendChild(body);
            return panel;
        }

        function createThresholdGrid(source, onChange, errorKeyPrefix) {
            const wrapper = document.createElement('div');
            wrapper.className = 'threshold-grid';
            const fields = [
                { key: 'min_score', label: 'Min score' },
                { key: 'max_score', label: 'Max score' },
                { key: 'min_findings', label: 'Min findings' },
                { key: 'max_findings', label: 'Max findings' },
            ];
            fields.forEach((field) => {
                wrapper.appendChild(
                    createNumberField(field.label, source[field.key], (value) => {
                        source[field.key] = value;
                        onChange(field.key, value);
                    }, {
                        min: 0,
                        errorKey: `${errorKeyPrefix}_${field.key}`,
                        compact: true,
                    }),
                );
            });
            return wrapper;
        }

        function createRiskThresholdEditor(entry, riskKey, thresholds) {
            const container = document.createElement('div');
            container.className = 'per-risk-entry';
            let currentKey = riskKey;

            const keyField = createTextField('Risk key', riskKey, (value) => {
                const normalized = value.trim();
                if (normalized === currentKey) {
                    updateDraftValidation();
                    return;
                }
                const existing = entry.perRiskThresholds[currentKey] || thresholds;
                delete entry.perRiskThresholds[currentKey];
                entry.perRiskThresholds[normalized] = existing;
                currentKey = normalized;
                renderAnalyzerSection();
                updateDraftValidation();
            }, {
                errorKey: `analyzer_${entry.id}_risk_${riskKey}_key`,
            });
            container.appendChild(keyField);

            container.appendChild(
                createThresholdGrid(thresholds, (key, value) => {
                    thresholds[key] = value;
                    updateDraftValidation();
                }, `analyzer_${entry.id}_risk_${riskKey}`),
            );

            const removeBtn = document.createElement('button');
            removeBtn.type = 'button';
            removeBtn.className = 'icon-btn danger';
            removeBtn.innerHTML = '<i class="fa-solid fa-trash" aria-hidden="true"></i><span class="sr-only">Remove risk override</span>';
            removeBtn.addEventListener('click', () => {
                delete entry.perRiskThresholds[currentKey];
                renderAnalyzerSection();
                updateDraftValidation();
            });
            container.appendChild(removeBtn);
            return container;
        }

        function createRiskPortEditor(entry, riskKey, values) {
            const container = document.createElement('div');
            container.className = 'per-risk-entry';
            let currentKey = riskKey;

            const keyField = createTextField('Risk key', riskKey, (value) => {
                const normalized = value.trim();
                if (normalized === currentKey) {
                    updateDraftValidation();
                    return;
                }
                const existing = entry.perRiskAdminPorts[currentKey] || values;
                delete entry.perRiskAdminPorts[currentKey];
                entry.perRiskAdminPorts[normalized] = Array.isArray(existing) ? existing : splitList(existing);
                currentKey = normalized;
                renderAnalyzerSection();
                updateDraftValidation();
            }, {
                errorKey: `analyzer_${entry.id}_port_risk_${riskKey}_key`,
            });
            container.appendChild(keyField);

            container.appendChild(
                createTextareaField('Ports', Array.isArray(values) ? values.join('\n') : '', (value) => {
                    entry.perRiskAdminPorts[currentKey] = splitList(value);
                    updateDraftValidation();
                }, {
                    rows: 2,
                    placeholder: '22\n443',
                    errorKey: `analyzer_${entry.id}_port_risk_${riskKey}`,
                    spellcheck: false,
                }),
            );

            const removeBtn = document.createElement('button');
            removeBtn.type = 'button';
            removeBtn.className = 'icon-btn danger';
            removeBtn.innerHTML = '<i class="fa-solid fa-trash" aria-hidden="true"></i><span class="sr-only">Remove port override</span>';
            removeBtn.addEventListener('click', () => {
                delete entry.perRiskAdminPorts[currentKey];
                renderAnalyzerSection();
                updateDraftValidation();
            });
            container.appendChild(removeBtn);
            return container;
        }

        function renderValidationSummary(messages = []) {
            validationList.innerHTML = '';
            if (!messages || messages.length === 0) {
                const item = document.createElement('li');
                item.className = 'validation-success';
                item.textContent = 'Rule is valid.';
                validationList.appendChild(item);
                return;
            }
            messages.forEach((message) => {
                const item = document.createElement('li');
                item.textContent = message;
                validationList.appendChild(item);
            });
        }

        function updateDraftValidation() {
            if (!draft) {
                return;
            }
            const simulatedRule = {
                ...activeRule,
                key: draft.key,
                ruleId: draft.ruleId,
                label: draft.label,
                description: draft.description,
                conditionTree: draft.conditionTree,
                analyzerEntries: draft.analyzerEntries,
            };
            const result = validateRule(simulatedRule, {
                allRules: configState.ruleLogic,
                currentRuleId: activeRule?.id,
            });
            renderValidationSummary(result.messages);
            applyEditorErrors(result.detailedErrors);
        }

        function focusFirstField() {
            const firstInput = modal.querySelector('input, textarea, select, button');
            firstInput?.focus();
        }

        let focusable = [];
        function updateFocusableElements() {
            focusable = Array.from(
                modal.querySelectorAll(
                    'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])',
                ),
            ).filter((element) => !element.hasAttribute('disabled') && !element.getAttribute('aria-hidden'));
        }

        modal.addEventListener('keydown', (event) => {
            if (event.key === 'Tab') {
                updateFocusableElements();
                if (focusable.length === 0) {
                    event.preventDefault();
                    return;
                }
                const first = focusable[0];
                const last = focusable[focusable.length - 1];
                if (event.shiftKey) {
                    if (document.activeElement === first) {
                        event.preventDefault();
                        last.focus();
                    }
                } else if (document.activeElement === last) {
                    event.preventDefault();
                    first.focus();
                }
            } else if (event.key === 'Escape') {
                close();
            }
        });

        form.addEventListener('submit', (event) => {
            event.preventDefault();
            if (!draft || !activeRule) {
                return;
            }
            const simulatedRule = {
                ...activeRule,
                key: draft.key,
                ruleId: draft.ruleId,
                label: draft.label,
                description: draft.description,
                conditionTree: draft.conditionTree,
                analyzerEntries: draft.analyzerEntries,
            };
            const result = validateRule(simulatedRule, {
                allRules: configState.ruleLogic,
                currentRuleId: activeRule.id,
            });
            if (Object.keys(result.detailedErrors || {}).length > 0) {
                applyEditorErrors(result.detailedErrors);
                renderValidationSummary(result.messages);
                showToast('Resolve validation issues before saving this rule.', true);
                return;
            }
            activeRule.key = draft.key;
            activeRule.ruleId = draft.ruleId;
            activeRule.label = draft.label;
            activeRule.description = draft.description;
            activeRule.conditionTree = cloneConditionGroup(draft.conditionTree);
            activeRule.analyzerEntries = draft.analyzerEntries.map((entry) => cloneAnalyzerEntry(entry));
            syncRuleConditions(activeRule);
            syncRuleAnalyzers(activeRule);
            runValidation({ suppressErrorToast: true });
            renderRuleLogic();
            close();
            showToast(`Saved rule '${getRuleDisplayName(activeRule)}'.`);
        });

        cancelBtn.addEventListener('click', () => close());
        closeBtn.addEventListener('click', () => close());
        backdrop.addEventListener('mousedown', (event) => {
            if (event.target === backdrop) {
                close();
            }
        });

        return {
            open,
            close,
        };
    }

    function createRuleDraft(rule) {
        return {
            id: rule.id,
            key: rule.key || '',
            ruleId: rule.ruleId || '',
            label: rule.label || '',
            description: rule.description || '',
            conditionTree: cloneConditionGroup(rule.conditionTree),
            analyzerEntries: Array.isArray(rule.analyzerEntries)
                ? rule.analyzerEntries.map((entry) => cloneAnalyzerEntry(entry))
                : [createAnalyzerEntry()],
        };
    }

    function createTextField(labelText, value, onInput, options = {}) {
        const wrapper = document.createElement('label');
        wrapper.className = `form-field${options.compact ? ' compact' : ''}`;
        wrapper.innerHTML = `<span class="field-label">${sanitize(labelText)}</span>`;


        const input = document.createElement('input');
        input.type = 'text';
        input.value = value ?? '';
        if (options.placeholder) {
            input.placeholder = options.placeholder;
        }
        if (options.spellcheck !== undefined) {
            input.spellcheck = options.spellcheck;
        }
        input.addEventListener('input', (event) => onInput(event.target.value));
        wrapper.appendChild(input);

        if (options.help) {
            const help = document.createElement('div');
            help.className = 'field-hint';
            help.textContent = options.help;
            wrapper.appendChild(help);
        }

        wrapper.appendChild(createFieldError(options.errorKey));
        return wrapper;
    }

    function createSelectField(labelText, choices, selected, onChange, options = {}) {
        const wrapper = document.createElement('label');
        wrapper.className = `form-field${options.compact ? ' compact' : ''}`;
        wrapper.innerHTML = `<span class="field-label">${sanitize(labelText)}</span>`;

        const select = document.createElement('select');
        choices.forEach((choice) => {
            const option = document.createElement('option');
            option.value = choice.value;
            option.textContent = choice.label;
            if ((selected ?? '') === choice.value) {
                option.selected = true;
            }
            select.appendChild(option);
        });
        select.addEventListener('change', (event) => onChange(event.target.value));
        wrapper.appendChild(select);
        wrapper.appendChild(createFieldError(options.errorKey));
        return wrapper;
    }

    function createNumberField(labelText, value, onChange, options = {}) {
        const wrapper = document.createElement('label');
        wrapper.className = `form-field${options.compact ? ' compact' : ''}`;
        wrapper.innerHTML = `<span class="field-label">${sanitize(labelText)}</span>`;

        const input = document.createElement('input');
        input.type = 'number';
        if (value !== null && value !== undefined && value !== '') {
            input.value = value;
        }
        if (options.placeholder) {
            input.placeholder = options.placeholder;
        }
        if (options.min !== undefined) {
            input.min = String(options.min);
        }
        if (options.max !== undefined) {
            input.max = String(options.max);
        }
        input.addEventListener('input', (event) => onChange(event.target.value));
        wrapper.appendChild(input);
        wrapper.appendChild(createFieldError(options.errorKey));
        return wrapper;
    }

    function createTextareaField(labelText, value, onInput, options = {}) {
        const wrapper = document.createElement('label');
        wrapper.className = 'form-field textarea-field';
        wrapper.innerHTML = `<span class="field-label">${sanitize(labelText)}</span>`;

        const textarea = document.createElement('textarea');
        textarea.value = value ?? '';
        if (options.rows) {
            textarea.rows = options.rows;
        }
        if (options.placeholder) {
            textarea.placeholder = options.placeholder;
        }
        if (options.monospace) {
            textarea.classList.add('code-textarea');
        }
        if (options.spellcheck !== undefined) {
            textarea.spellcheck = options.spellcheck;
        }
        textarea.addEventListener('input', (event) => onInput(event.target.value));
        wrapper.appendChild(textarea);
        if (options.help) {
            const help = document.createElement('div');
            help.className = 'field-hint';
            help.textContent = options.help;
            wrapper.appendChild(help);
        }
        wrapper.appendChild(createFieldError(options.errorKey));
        return wrapper;
    }

    function createPolicyFields(title, policy, onChange, errorPrefix, compact = false) {
        const wrapper = document.createElement('div');
        wrapper.className = `fieldset${compact ? ' compact' : ''}`;
        
        const legend = document.createElement('div');
        legend.className = 'fieldset-legend';
        legend.innerHTML = `<span>${sanitize(title)}</span><span class="fieldset-hint">Set prefix limits and CIDRs</span>`;
        wrapper.appendChild(legend);

        const grid = document.createElement('div');
        grid.className = 'field-grid';

        grid.appendChild(createNumberField('Max Prefix', policy.max_prefix, (value) => {
            policy.max_prefix = value;
            onChange();
        }, { min: 0, max: 128, placeholder: 'e.g. 24', errorKey: `${errorPrefix}_max_prefix`, compact }));
        grid.appendChild(createNumberField('Min Prefix', policy.min_prefix, (value) => {
            policy.min_prefix = value;
            onChange();
        }, { min: 0, max: 128, placeholder: 'e.g. 8', errorKey: `${errorPrefix}_min_prefix`, compact }));
        grid.appendChild(createTextareaField('Blocked CIDRs', policy.blocked.join('\n'), (value) => {
            policy.blocked = splitList(value);
            onChange();
        }, { rows: compact ? 2 : 3, placeholder: '10.0.0.0/8\n0.0.0.0/0', errorKey: `${errorPrefix}_blocked` }));
        grid.appendChild(createTextareaField('Exempt CIDRs', policy.exempt.join('\n'), (value) => {
            policy.exempt = splitList(value);
            onChange();
        }, { rows: compact ? 2 : 3, placeholder: '192.168.0.0/16', errorKey: `${errorPrefix}_exempt` }));
        grid.appendChild(createTextareaField('Description', policy.description, (value) => {
            policy.description = value;
            onChange();
        }, { rows: compact ? 2 : 3, placeholder: 'Context for this policy override.', errorKey: `${errorPrefix}_description` }));

        wrapper.appendChild(grid);
        wrapper.appendChild(createFieldError(`${errorPrefix}_general`));
        return wrapper;
    }

    function createFieldError(key) {
        const error = document.createElement('div');
        error.className = 'field-error';
        if (key) {
            error.dataset.errorKey = key;
        }
        return error;
    }

    function runValidation(options = {}) {
        validationOptions = {
            ...defaultValidationOptions,
            ...(options || {}),
        };
        validationState = {
            riskLevels: validateRiskLevels(),
            cidrLimitSets: validateCidrSets(),
            portGroups: validatePortGroups(),
            ruleLogic: validateRuleLogic(),
        };
        applyValidationState();
        updateExportState();
        persistState();
        validationOptions = { ...defaultValidationOptions };
    }

    function applyValidationState() {
        applySectionValidation('.risk-level-card', validationState.riskLevels);
        applySectionValidation('.cidr-card', validationState.cidrLimitSets);
        applySectionValidation('.port-group-card', validationState.portGroups);
        applySectionValidation('.rule-logic-card', validationState.ruleLogic);

        const summary = document.querySelector(selectors.validationSummary);
        if (!summary) {
            return;
        }
        const allErrors = [
            ...Object.values(validationState.riskLevels || {}).flatMap((value) => Object.values(value)),
            ...Object.values(validationState.cidrLimitSets || {}).flatMap((value) => Object.values(value)),
            ...Object.values(validationState.portGroups || {}).flatMap((value) => Object.values(value)),
            ...Object.values(validationState.ruleLogic || {}).flatMap((value) => Object.values(value)),
        ].filter(Boolean);

        if (allErrors.length === 0) {
            summary.textContent = 'Configuration is valid and ready to export.';
            summary.classList.remove('has-errors');
            lastValidationMessage = '';
        } else {
            const firstError = allErrors[0];
            summary.textContent = firstError;
            summary.classList.add('has-errors');
            if (!validationOptions.suppressErrorToast && lastValidationMessage !== firstError) {
                showToast(firstError, true);
            }
            lastValidationMessage = firstError;
        }
    }

    function applySectionValidation(selector, sectionErrors) {
        document.querySelectorAll(selector).forEach((card) => {
            const id =
                card.dataset.levelId ||
                card.dataset.setId ||
                card.dataset.groupId ||
                card.dataset.ruleId;
            const errors = sectionErrors[id] || {};
            let hasError = false;
            card.querySelectorAll('.field-error').forEach((errorEl) => {
                const key = errorEl.dataset.errorKey;
                const message = key ? errors[key] : '';
                if (message) {
                    errorEl.textContent = message;
                    errorEl.classList.add('visible');
                    hasError = true;
                } else {
                    errorEl.textContent = '';
                    errorEl.classList.remove('visible');
                }
            });
            card.classList.toggle('has-error', hasError);
            if (card.classList.contains('rule-logic-card')) {
                const rule = configState.ruleLogic.find((entry) => entry.id === id);
                if (rule) {
                    updateRulePreview(card, rule);
                }
            }
        });
    }

    function updateExportState() {
        const exportBtn = document.querySelector(selectors.exportButton);
        if (!exportBtn) {
            return;
        }
        const hasErrors = Object.values(validationState).some((section) =>
            Object.values(section).some((entry) =>
                entry &&
                Object.values(entry).some((message) => typeof message === 'string' ? message.trim() !== '' : Boolean(message))
            )
        );
        const hasData =
            configState.riskLevels.length > 0 ||
            configState.cidrLimitSets.length > 0 ||
            configState.portGroups.length > 0 ||
            configState.ruleLogic.length > 0 ||
            Object.keys(passthroughConfig || {}).length > 0;
        exportBtn.disabled = hasErrors || !hasData;
    }

    function validateRiskLevels() {
        const errors = {};
        const nameCounts = {};
        configState.riskLevels.forEach((level) => {
            if (!errors[level.id]) {
                errors[level.id] = {};
            }
            const trimmedName = (level.name || '').trim();
            if (!trimmedName) {
                errors[level.id].name = 'Identifier is required.';
            } else if (!/^[-_a-zA-Z0-9]+$/.test(trimmedName)) {
                errors[level.id].name = 'Identifier must contain only letters, numbers, underscores or dashes.';
            }
            const normalized = trimmedName.toLowerCase();
            nameCounts[normalized] = (nameCounts[normalized] || 0) + 1;

            if (!(level.label || '').trim()) {
                errors[level.id].label = 'Label is required for UI display.';
            }

            if (!severityOptions.some((option) => option.value === level.severity)) {
                errors[level.id].severity = 'Severity must match backend enumeration.';
            }

            const thresholds = level.thresholds;
            const minScore = toNumber(thresholds.min_score);
            const maxScore = toNumber(thresholds.max_score);
            if (minScore !== null && (minScore < 0 || minScore > 100)) {
                errors[level.id].min_score = 'Minimum score must be between 0 and 100.';
            }
            if (maxScore !== null && (maxScore < 0 || maxScore > 100)) {
                errors[level.id].max_score = 'Maximum score must be between 0 and 100.';
            }
            if (minScore !== null && maxScore !== null && minScore > maxScore) {
                errors[level.id].thresholds = 'Minimum score cannot exceed maximum score.';
            }

            const minFindings = toNumber(thresholds.min_findings);
            const maxFindings = toNumber(thresholds.max_findings);
            if (minFindings !== null && minFindings < 0) {
                errors[level.id].min_findings = 'Minimum findings cannot be negative.';
            }
            if (maxFindings !== null && maxFindings < 0) {
                errors[level.id].max_findings = 'Maximum findings cannot be negative.';
            }
            if (minFindings !== null && maxFindings !== null && minFindings > maxFindings) {
                errors[level.id].thresholds = 'Minimum findings cannot exceed maximum findings.';
            }

            if (Object.keys(errors[level.id]).length === 0) {
                delete errors[level.id];
            }
        });

        Object.entries(nameCounts).forEach(([name, count]) => {
            if (!name) {
                return;
            }
            if (count > 1) {
                configState.riskLevels.forEach((level) => {
                    if ((level.name || '').trim().toLowerCase() === name) {
                        if (!errors[level.id]) {
                            errors[level.id] = {};
                        }
                        errors[level.id].name = 'Identifier must be unique.';
                    }
                });
            }
        });
        return errors;
    }

    function validateCidrSets() {
        const errors = {};
        const nameCounts = {};
        configState.cidrLimitSets.forEach((set) => {
            const setErrors = {};
            const trimmedName = (set.name || '').trim();
            if (!trimmedName) {
                setErrors.name = 'Identifier is required.';
            } else {
                const normalized = trimmedName.toLowerCase();
                nameCounts[normalized] = (nameCounts[normalized] || 0) + 1;
            }

            const defaultErrors = validatePolicy(set.defaultPolicy, 'Default policy');
            Object.assign(setErrors, prefixErrors(defaultErrors, 'default'));

            set.overrides.forEach((override) => {
                const overrideErrors = {};
                if (!override.scope) {
                    overrideErrors[`${override.id}_scope`] = 'Override type is required.';
                }
                if (override.scope === 'vendor_direction') {
                    if (!(override.vendor || '').trim()) {
                        overrideErrors[`${override.id}_vendor`] = 'Vendor is required for this override.';
                    }
                    if (!(override.direction || '').trim()) {
                        overrideErrors[`${override.id}_direction`] = 'Direction is required for this override.';
                    }
                } else {
                    if (!(override.key || '').trim()) {
                        overrideErrors[`${override.id}_key`] = 'Override key is required.';
                    }
                }
                Object.assign(overrideErrors, prefixErrors(validatePolicy(override.policy, 'Override policy'), override.id));
                Object.assign(setErrors, overrideErrors);
            });

            if (Object.keys(setErrors).length > 0) {
                errors[set.id] = setErrors;
            }
        });

        Object.entries(nameCounts).forEach(([name, count]) => {
            if (count > 1) {
                configState.cidrLimitSets.forEach((set) => {
                    if ((set.name || '').trim().toLowerCase() === name) {
                        if (!errors[set.id]) {
                            errors[set.id] = {};
                        }
                        errors[set.id].name = 'Identifier must be unique.';
                    }
                });
            }
        });
        return errors;
    }

    function validatePortGroups() {
        const errors = {};
        const nameCounts = {};
        configState.portGroups.forEach((group) => {
            const groupErrors = {};
            const trimmedName = (group.name || '').trim();
            if (!trimmedName) {
                groupErrors.name = 'Identifier is required.';
            } else {
                const normalized = trimmedName.toLowerCase();
                nameCounts[normalized] = (nameCounts[normalized] || 0) + 1;
            }

            if (!['any', 'tcp', 'udp'].includes(group.protocol)) {
                groupErrors.protocol = 'Protocol must be any, tcp, or udp.';
            }

            if (group.ranges.length === 0) {
                groupErrors.ranges = 'At least one range is required.';
            }

            const sorted = group.ranges
                .map((range) => ({
                    ...range,
                    startNum: toNumber(range.start),
                    endNum: toNumber(range.end ?? range.start),
                }))
                .sort((a, b) => (a.startNum ?? 0) - (b.startNum ?? 0));

            sorted.forEach((range) => {
                if (range.startNum === null || range.endNum === null) {
                    groupErrors[`range_${range.id}`] = 'Both start and end ports are required.';
                    return;
                }
                if (range.startNum < 1 || range.startNum > 65535) {
                    groupErrors[`start_${range.id}`] = 'Start port must be between 1 and 65535.';
                }
                if (range.endNum < 1 || range.endNum > 65535) {
                    groupErrors[`end_${range.id}`] = 'End port must be between 1 and 65535.';
                }
                if (range.startNum > range.endNum) {
                    groupErrors[`range_${range.id}`] = 'Start port cannot exceed end port.';
                }
            });

            for (let i = 1; i < sorted.length; i += 1) {
                const previous = sorted[i - 1];
                const current = sorted[i];
                if (previous.endNum !== null && current.startNum !== null && previous.endNum >= current.startNum) {
                    groupErrors[`range_${current.id}`] = `Range ${previous.startNum}-${previous.endNum} overlaps with ${current.startNum}-${current.endNum}.`;
                }
            }

            if (Object.keys(groupErrors).length > 0) {
                errors[group.id] = groupErrors;
            }
        });

        Object.entries(nameCounts).forEach(([name, count]) => {
            if (count > 1) {
                configState.portGroups.forEach((group) => {
                    if ((group.name || '').trim().toLowerCase() === name) {
                        if (!errors[group.id]) {
                            errors[group.id] = {};
                        }
                        errors[group.id].name = 'Identifier must be unique.';
                    }
                });
            }
        });
        return errors;
    }

    function validateRuleLogic() {
        const errors = {};
        const allRules = configState.ruleLogic || [];
        allRules.forEach((rule) => {
            const result = validateRule(rule, { allRules, currentRuleId: rule.id });
            rule.validationMessages = result.messages;
            if (Object.keys(result.fieldErrors).length > 0) {
                errors[rule.id] = result.fieldErrors;
            }
        });
        return errors;
    }

    function validateRule(rule, context = {}) {
        const fieldErrors = {};
        const detailedErrors = {};
        const messages = [];

        if (!rule) {
            return { fieldErrors, detailedErrors, messages };
        }

        ensureConditionTree(rule);
        ensureAnalyzerEntries(rule);
        syncRuleConditions(rule);
        syncRuleAnalyzers(rule);

        const identifier = (rule.key || '').trim();
        if (!identifier) {
            const message = 'Rule identifier is required.';
            fieldErrors.key = message;
            detailedErrors.key = message;
            messages.push(message);
        } else if (!/^[-_a-zA-Z0-9]+$/.test(identifier)) {
            const message = 'Rule identifier must contain only letters, numbers, underscores or dashes.';
            fieldErrors.key = message;
            detailedErrors.key = message;
            messages.push(message);
        } else if (Array.isArray(context.allRules)) {
            const duplicate = context.allRules.some((candidate) => {
                if (context.currentRuleId && candidate.id === context.currentRuleId) {
                    return false;
                }
                return (candidate.key || '').trim().toLowerCase() === identifier.toLowerCase();
            });
            if (duplicate) {
                const message = 'Rule identifier must be unique.';
                fieldErrors.key = message;
                detailedErrors.key = message;
                messages.push(message);
            }
        }

        const ruleId = (rule.ruleId || '').trim();
        if (!ruleId) {
            const message = 'Rule ID is required.';
            fieldErrors.ruleId = message;
            detailedErrors.ruleId = message;
            messages.push(message);
        }

        const label = (rule.label || '').trim();
        if (!label) {
            const message = 'Label is required.';
            fieldErrors.label = message;
            detailedErrors.label = message;
            messages.push(message);
        }

        const conditionResult = validateConditionGroupStructure(rule.conditionTree);
        if (conditionResult.messages.length > 0) {
            fieldErrors.conditions = conditionResult.messages[0];
            messages.push(...conditionResult.messages);
        }
        Object.assign(detailedErrors, conditionResult.detailed);

        const analyzerResult = validateAnalyzerEntries(rule.analyzerEntries, context);
        if (analyzerResult.analyzerMessage) {
            fieldErrors.analyzers = analyzerResult.analyzerMessage;
        }
        if (analyzerResult.thresholdMessage) {
            fieldErrors.thresholds = analyzerResult.thresholdMessage;
        }
        if (analyzerResult.adminPortMessage) {
            fieldErrors.adminPorts = analyzerResult.adminPortMessage;
        }
        if (analyzerResult.messages.length > 0) {
            messages.push(...analyzerResult.messages);
        }
        Object.assign(detailedErrors, analyzerResult.detailed);

        const uniqueMessages = Array.from(new Set(messages.filter(Boolean)));
        return {
            fieldErrors,
            detailedErrors,
            messages: uniqueMessages,
        };
    }

    function validateConditionGroupStructure(group) {
        const detailed = {};
        const messages = [];
        if (!group || typeof group !== 'object') {
            messages.push('Define at least one condition group.');
            return { detailed, messages };
        }

        const logic = group.logic === 'any' ? 'any' : group.logic === 'all' ? 'all' : null;
        if (!logic) {
            const message = 'Group logic must be ALL or ANY.';
            messages.push(message);
        }
        group.logic = logic || 'all';

        const hasConditions = Array.isArray(group.conditions) && group.conditions.length > 0;
        const hasGroups = Array.isArray(group.groups) && group.groups.length > 0;
        if (!hasConditions && !hasGroups) {
            messages.push('Each group must contain at least one condition or nested group.');
        }

        if (Array.isArray(group.conditions)) {
            group.conditions.forEach((condition) => {
                const errors = [];
                const field = (condition.field || '').trim();
                const comparator = (condition.comparator || '').trim();
                if (!field) {
                    errors.push('Field is required.');
                }
                if (!comparator) {
                    errors.push('Comparator is required.');
                }
                const requiresValue = comparator && !comparatorValueModes.none.has(comparator);
                const isMulti = comparatorValueModes.multi.has(comparator);
                if (requiresValue && isMulti) {
                    const values = Array.isArray(condition.values)
                        ? condition.values.map((value) => String(value).trim()).filter(Boolean)
                        : [];
                    if (values.length === 0) {
                        errors.push('Provide at least one value.');
                    }
                    if (comparator === 'between' && values.length > 0 && values.length < 2) {
                        errors.push('Provide two values for the between comparator.');
                    }
                } else if (requiresValue && !isMulti) {
                    const value = (condition.value || '').trim();
                    if (!value) {
                        errors.push('Value is required.');
                    }
                }
                if (errors.length > 0) {
                    const message = errors.join(' ');
                    detailed[`condition_${condition.id}`] = message;
                    messages.push(`Condition '${field || 'unnamed'}': ${message}`);
                }
            });
        }

        if (Array.isArray(group.groups)) {
            group.groups.forEach((child) => {
                const childResult = validateConditionGroupStructure(child);
                Object.assign(detailed, childResult.detailed);
                messages.push(...childResult.messages);
            });
        }

        return { detailed, messages };
    }

    function validateAnalyzerEntries(entries, context = {}) {
        const detailed = {};
        const messages = [];
        let analyzerMessage = '';
        let thresholdMessage = '';
        let adminPortMessage = '';

        if (!Array.isArray(entries) || entries.length === 0) {
            analyzerMessage = 'Configure at least one analyzer binding.';
            messages.push(analyzerMessage);
            return { detailed, messages, analyzerMessage, thresholdMessage, adminPortMessage };
        }

        const keyCounts = {};
        entries.forEach((entry) => {
            const key = (entry.key || '').trim().toLowerCase();
            if (key) {
                keyCounts[key] = (keyCounts[key] || 0) + 1;
            }
        });

        entries.forEach((entry, index) => {
            const key = (entry.key || '').trim();
            const displayName = key || `Analyzer ${index + 1}`;
            if (!key) {
                const message = 'Analyzer key is required.';
                detailed[`analyzer_${entry.id}_key`] = message;
                messages.push(`${displayName}: ${message}`);
            } else if (!/^[-_a-zA-Z0-9]+$/.test(key)) {
                const message = 'Analyzer key must contain only letters, numbers, underscores or dashes.';
                detailed[`analyzer_${entry.id}_key`] = message;
                messages.push(`${displayName}: ${message}`);
            } else if (keyCounts[key.toLowerCase()] > 1) {
                const message = 'Analyzer key must be unique within the rule.';
                detailed[`analyzer_${entry.id}_key`] = message;
                messages.push(`${displayName}: ${message}`);
            }

            Object.entries(entry.severityOverrides || {}).forEach(([severity, value]) => {
                if (!value) {
                    return;
                }
                const normalized = String(value).toLowerCase();
                if (!severityOptionValues.includes(normalized)) {
                    const message = `Severity override for ${severity} must be a recognised severity.`;
                    detailed[`analyzer_${entry.id}_analyzer`] = message;
                    messages.push(`${displayName}: ${message}`);
                }
            });

            const thresholdResult = validateThresholdValues(entry.baselineThresholds, `analyzer_${entry.id}_thresholds`);
            if (thresholdResult.hasError) {
                Object.assign(detailed, thresholdResult.detailed);
                thresholdMessage = 'Review analyzer threshold values.';
                thresholdResult.messages.forEach((message) => {
                    messages.push(`${displayName}: ${message}`);
                });
            }

            Object.entries(entry.perRiskThresholds || {}).forEach(([riskKey, values]) => {
                const normalizedKey = (riskKey || '').trim();
                const riskLabel = normalizedKey || 'unnamed risk override';
                if (!normalizedKey) {
                    const message = 'Risk key is required for threshold override.';
                    detailed[`analyzer_${entry.id}_risk_${riskKey}_key`] = message;
                    messages.push(`${displayName}: ${message}`);
                }
                const result = validateThresholdValues(values, `analyzer_${entry.id}_risk_${riskKey}`);
                if (result.hasError) {
                    Object.assign(detailed, result.detailed);
                    thresholdMessage = 'Review analyzer threshold values.';
                    result.messages.forEach((message) => {
                        messages.push(`${displayName} (${riskLabel}): ${message}`);
                    });
                }
            });

            const baselinePortErrors = validateAdminPortList(entry.baselineAdminPorts || []);
            if (baselinePortErrors.length > 0) {
                detailed[`analyzer_${entry.id}_baseline_ports`] = baselinePortErrors.join(' ');
                adminPortMessage = 'Resolve administrative port validation issues.';
                messages.push(`${displayName}: ${baselinePortErrors.join(' ')}`);
            }

            Object.entries(entry.perRiskAdminPorts || {}).forEach(([riskKey, ports]) => {
                const normalizedKey = (riskKey || '').trim();
                const riskLabel = normalizedKey || 'unnamed risk override';
                if (!normalizedKey) {
                    const message = 'Risk key is required for port override.';
                    detailed[`analyzer_${entry.id}_port_risk_${riskKey}_key`] = message;
                    adminPortMessage = 'Resolve administrative port validation issues.';
                    messages.push(`${displayName}: ${message}`);
                }
                const portErrors = validateAdminPortList(Array.isArray(ports) ? ports : splitList(ports));
                if (portErrors.length > 0) {
                    detailed[`analyzer_${entry.id}_port_risk_${riskKey}`] = portErrors.join(' ');
                    adminPortMessage = 'Resolve administrative port validation issues.';
                    messages.push(`${displayName} (${riskLabel}): ${portErrors.join(' ')}`);
                }
            });
        });

        if (!entries.some((entry) => (entry.key || '').trim())) {
            analyzerMessage = 'Configure at least one analyzer binding.';
        } else if (!analyzerMessage && messages.some((message) => message.includes('Analyzer key'))) {
            analyzerMessage = 'Resolve analyzer key validation issues.';
        } else if (!analyzerMessage && messages.length > 0) {
            analyzerMessage = 'Review analyzer configuration.';
        }

        return {
            detailed,
            messages,
            analyzerMessage,
            thresholdMessage,
            adminPortMessage,
        };
    }

    function validateThresholdValues(thresholds, keyPrefix) {
        const detailed = {};
        const messages = [];
        let hasError = false;
        if (!thresholds || typeof thresholds !== 'object') {
            return { detailed, messages, hasError };
        }
        const normalized = {};
        const labels = {
            min_score: 'Minimum score',
            max_score: 'Maximum score',
            min_findings: 'Minimum findings',
            max_findings: 'Maximum findings',
        };
        Object.entries(labels).forEach(([key, label]) => {
            const raw = thresholds[key];
            if (raw === '' || raw === null || raw === undefined) {
                normalized[key] = null;
                return;
            }
            const numeric = toNumber(raw);
            if (numeric === null || numeric < 0) {
                const message = `${label} must be a number greater than or equal to zero.`;
                detailed[`${keyPrefix}_${key}`] = message;
                messages.push(message);
                hasError = true;
            } else {
                normalized[key] = numeric;
            }
        });

        if (
            normalized.min_score !== undefined &&
            normalized.min_score !== null &&
            normalized.max_score !== undefined &&
            normalized.max_score !== null &&
            normalized.min_score > normalized.max_score
        ) {
            const message = 'Minimum score cannot exceed maximum score.';
            detailed[`${keyPrefix}_min_score`] = message;
            detailed[`${keyPrefix}_max_score`] = message;
            messages.push(message);
            hasError = true;
        }

        if (
            normalized.min_findings !== undefined &&
            normalized.min_findings !== null &&
            normalized.max_findings !== undefined &&
            normalized.max_findings !== null &&
            normalized.min_findings > normalized.max_findings
        ) {
            const message = 'Minimum findings cannot exceed maximum findings.';
            detailed[`${keyPrefix}_min_findings`] = message;
            detailed[`${keyPrefix}_max_findings`] = message;
            messages.push(message);
            hasError = true;
        }

        return { detailed, messages, hasError };
    }

    function validateAdminPortList(values) {
        const errors = [];
        const seen = new Set();
        const duplicates = new Set();
        (Array.isArray(values) ? values : splitList(values)).forEach((value) => {
            const trimmed = String(value).trim();
            if (!trimmed) {
                return;
            }
            const numeric = Number(trimmed);
            if (!Number.isInteger(numeric) || numeric < 1 || numeric > 65535) {
                errors.push(`'${trimmed}' must be between 1 and 65535.`);
                return;
            }
            if (seen.has(numeric)) {
                duplicates.add(numeric);
            } else {
                seen.add(numeric);
            }
        });
        duplicates.forEach((value) => {
            errors.push(`Port ${value} is duplicated.`);
        });
        return errors;
    }

    function validatePolicy(policy) {
        const errors = {};
        const maxPrefix = toNumber(policy.max_prefix);
        const minPrefix = toNumber(policy.min_prefix);
        if (maxPrefix !== null && (maxPrefix < 0 || maxPrefix > 128)) {
            errors.max_prefix = 'Max prefix must be between 0 and 128.';
        }
        if (minPrefix !== null && (minPrefix < 0 || minPrefix > 128)) {
            errors.min_prefix = 'Min prefix must be between 0 and 128.';
        }
        if (maxPrefix !== null && minPrefix !== null && minPrefix > maxPrefix) {
            errors.general = 'Min prefix cannot exceed max prefix.';
        }

        const blockedErrors = validateCidrs(policy.blocked);
        if (blockedErrors.length > 0) {
            errors.blocked = blockedErrors.join(' ');
        }
        const exemptErrors = validateCidrs(policy.exempt);
        if (exemptErrors.length > 0) {
            errors.exempt = exemptErrors.join(' ');
        }
        return errors;
    }

    function validateCidrs(values) {
        const errors = [];
        values.forEach((value) => {
            const trimmed = value.trim();
            if (!trimmed) {
                return;
            }
            try {
                window.ipaddr.parseCIDR(trimmed);
            } catch (error) {
                errors.push(`'${trimmed}' is not a valid CIDR.`);
            }
        });
        return errors;
    }

    function prefixErrors(source, prefix) {
        const result = {};
        Object.entries(source).forEach(([key, value]) => {
            if (key === 'general') {
                result[`${prefix}_general`] = value;
            } else {
                result[`${prefix}_${key}`] = value;
            }
        });
        return result;
    }

    function applyImportedConfig(parsed) {
        if (!parsed || typeof parsed !== 'object') {
            throw new Error('Parsed configuration must be an object.');
        }
        const {
            risk_levels: riskLevelsRaw = {},
            cidr_limits: cidrLimitsRaw = {},
            port_groups: portGroupsRaw = {},
            rules: ruleLogicRaw = {},
            ...rest
        } = parsed;

        passthroughConfig = rest;
        configState.riskLevels = Object.entries(riskLevelsRaw || {}).map(([name, value]) => createRiskLevelFromYaml(name, value));
        configState.cidrLimitSets = Object.entries(cidrLimitsRaw || {}).map(([name, value]) => createCidrSetFromYaml(name, value));
        configState.portGroups = Object.entries(portGroupsRaw || {}).map(([name, value]) => createPortGroupFromYaml(name, value));
        configState.ruleLogic = Object.entries(ruleLogicRaw || {}).map(([name, value]) =>
            createRuleDefinitionFromYaml(name, value),
        );

        renderAll();
        runValidation();
    }

    function buildConfigSnapshot() {
        const snapshot = { ...passthroughConfig };

        const riskLevels = {};
        configState.riskLevels.forEach((level) => {
            const key = (level.name || '').trim();
            if (!key) {
                return;
            }
            riskLevels[key] = {
                label: (level.label || '').trim(),
                severity: level.severity,
                thresholds: {
                    min_score: toNumber(level.thresholds.min_score),
                    max_score: toNumber(level.thresholds.max_score),
                    min_findings: toNumber(level.thresholds.min_findings),
                    max_findings: toNumber(level.thresholds.max_findings),
                },
                rationale: {
                    summary: (level.rationale.summary || '').trim(),
                    details: (level.rationale.details || '').trim(),
                    references: level.rationale.references.filter(Boolean),
                },
            };
        });
        snapshot.risk_levels = riskLevels;

        const cidrSets = {};
        configState.cidrLimitSets.forEach((set) => {
            const key = (set.name || '').trim();
            if (!key) {
                return;
            }
            const cidrEntry = {
                default: convertPolicyForExport(set.defaultPolicy),
            };
            const analyzerMap = {};
            const vendorMap = {};
            const directionMap = {};
            const vendorDirectionMap = {};
            set.overrides.forEach((override) => {
                const policy = convertPolicyForExport(override.policy);
                if (override.scope === 'vendor_direction') {
                    const vendor = (override.vendor || '').trim().toLowerCase();
                    const direction = (override.direction || '').trim().toLowerCase();
                    if (!vendor || !direction) {
                        return;
                    }
                    if (!vendorDirectionMap[vendor]) {
                        vendorDirectionMap[vendor] = {};
                    }
                    vendorDirectionMap[vendor][direction] = policy;
                } else if (override.scope === 'vendor') {
                    const vendor = (override.key || '').trim().toLowerCase();
                    if (!vendor) {
                        return;
                    }
                    vendorMap[vendor] = policy;
                } else if (override.scope === 'direction') {
                    const direction = (override.key || '').trim().toLowerCase();
                    if (!direction) {
                        return;
                    }
                    directionMap[direction] = policy;
                } else {
                    const analyzer = (override.key || '').trim().toLowerCase();
                    if (!analyzer) {
                        return;
                    }
                    analyzerMap[analyzer] = policy;
                }
            });
            if (Object.keys(analyzerMap).length > 0) {
                cidrEntry.analyzers = analyzerMap;
            }
            if (Object.keys(vendorMap).length > 0) {
                cidrEntry.vendors = vendorMap;
            }
            if (Object.keys(directionMap).length > 0) {
                cidrEntry.directions = directionMap;
            }
            if (Object.keys(vendorDirectionMap).length > 0) {
                cidrEntry.vendor_direction_overrides = vendorDirectionMap;
            }
            cidrSets[key] = cidrEntry;
        });
        snapshot.cidr_limits = cidrSets;

        const portGroups = {};
        configState.portGroups.forEach((group) => {
            const key = (group.name || '').trim();
            if (!key) {
                return;
            }
            portGroups[key] = {
                description: (group.description || '').trim(),
                protocol: group.protocol,
                ranges: group.ranges.map((range) => {
                    const start = toNumber(range.start);
                    const end = toNumber(range.end ?? range.start);
                    return { start, end };
                }),
            };
        });
        snapshot.port_groups = portGroups;

        const rules = {};
        configState.ruleLogic.forEach((rule) => {
            const key = (rule.key || '').trim();
            if (!key) {
                return;
            }
            const ruleId = (rule.ruleId || '').trim() || key;
            const conditions = isPlainObject(rule.parsedConditions)
                ? cloneObject(rule.parsedConditions)
                : createDefaultRuleConditions();
            const analyzers = isPlainObject(rule.parsedAnalyzers)
                ? cloneObject(rule.parsedAnalyzers)
                : {};
            rules[key] = {
                id: ruleId,
                label: (rule.label || '').trim() || ruleId,
                description: (rule.description || '').trim(),
                conditions,
                analyzers,
            };
        });
        snapshot.rules = rules;

        return snapshot;
    }

    function convertPolicyForExport(policy) {
        return {
            max_prefix: toNumber(policy.max_prefix),
            min_prefix: toNumber(policy.min_prefix),
            blocked: policy.blocked.filter(Boolean),
            exempt: policy.exempt.filter(Boolean),
            description: (policy.description || '').trim(),
        };
    }

    function createRiskLevel() {
        return {
            id: generateId('risk'),
            name: '',
            label: '',
            severity: 'low',
            thresholds: {
                min_score: '',
                max_score: '',
                min_findings: '',
                max_findings: '',
            },
            rationale: {
                summary: '',
                details: '',
                references: [],
            },
        };
    }

    function createRiskLevelFromYaml(name, value) {
        const thresholds = value?.thresholds || {};
        const rationale = value?.rationale || {};
        return {
            id: generateId('risk'),
            name: name || '',
            label: value?.label || '',
            severity: (value?.severity || 'low').toLowerCase(),
            thresholds: {
                min_score: fromNumber(thresholds.min_score),
                max_score: fromNumber(thresholds.max_score),
                min_findings: fromNumber(thresholds.min_findings),
                max_findings: fromNumber(thresholds.max_findings),
            },
            rationale: {
                summary: rationale.summary || '',
                details: rationale.details || '',
                references: Array.isArray(rationale.references) ? rationale.references : splitList(rationale.references),
            },
        };
    }

    function createCidrSet() {
        return {
            id: generateId('cidr'),
            name: '',
            defaultPolicy: createPolicy(),
            overrides: [],
        };
    }

    function createCidrSetFromYaml(name, value) {
        const overrides = [];
        Object.entries(value?.analyzers || {}).forEach(([key, policy]) => {
            overrides.push({
                id: generateId('override'),
                scope: 'analyzer',
                key,
                vendor: '',
                direction: '',
                policy: createPolicyFromYaml(policy),
            });
        });
        Object.entries(value?.vendors || {}).forEach(([key, policy]) => {
            overrides.push({
                id: generateId('override'),
                scope: 'vendor',
                key,
                vendor: '',
                direction: '',
                policy: createPolicyFromYaml(policy),
            });
        });
        Object.entries(value?.directions || {}).forEach(([key, policy]) => {
            overrides.push({
                id: generateId('override'),
                scope: 'direction',
                key,
                vendor: '',
                direction: '',
                policy: createPolicyFromYaml(policy),
            });
        });
        Object.entries(value?.vendor_direction_overrides || {}).forEach(([vendor, directionMap]) => {
            Object.entries(directionMap || {}).forEach(([direction, policy]) => {
                overrides.push({
                    id: generateId('override'),
                    scope: 'vendor_direction',
                    key: '',
                    vendor,
                    direction,
                    policy: createPolicyFromYaml(policy),
                });
            });
        });
        return {
            id: generateId('cidr'),
            name: name || '',
            defaultPolicy: createPolicyFromYaml(value?.default),
            overrides,
        };
    }

    function createPolicy() {
        return {
            max_prefix: '',
            min_prefix: '',
            blocked: [],
            exempt: [],
            description: '',
        };
    }

    function createPolicyFromYaml(value) {
        const policy = createPolicy();
        if (value) {
            policy.max_prefix = fromNumber(value.max_prefix);
            policy.min_prefix = fromNumber(value.min_prefix);
            policy.blocked = Array.isArray(value.blocked) ? value.blocked : splitList(value.blocked);
            policy.exempt = Array.isArray(value.exempt) ? value.exempt : splitList(value.exempt);
            policy.description = value.description || '';
        }
        return policy;
    }

    function createCidrOverride() {
        return {
            id: generateId('override'),
            scope: 'analyzer',
            key: '',
            vendor: '',
            direction: '',
            policy: createPolicy(),
        };
    }

    function createPortGroup() {
        return {
            id: generateId('group'),
            name: '',
            description: '',
            protocol: 'any',
            ranges: [createRange()],
        };
    }

    function createPortGroupFromYaml(name, value) {
        const rangesRaw = value?.ranges || value?.entries || [];
        return {
            id: generateId('group'),
            name: name || '',
            description: value?.description || '',
            protocol: (value?.protocol || 'any').toLowerCase(),
            ranges: (rangesRaw || []).map((entry) => createRangeFromYaml(entry)),
        };
    }

    function createRuleDefinition() {
        const parsedConditions = createDefaultRuleConditions();
        const parsedAnalyzers = {};
        return {
            id: generateId('rule'),
            key: '',
            ruleId: '',
            label: '',
            description: '',
            conditionsText: DEFAULT_RULE_CONDITIONS_YAML,
            analyzersText: DEFAULT_ANALYZERS_YAML,
            parsedConditions,
            parsedAnalyzers,
            conditionTree: normalizeConditionGroup(parsedConditions),
            analyzerEntries: normalizeAnalyzerEntries(parsedAnalyzers),
            validationMessages: [],
        };
    }

    function createRuleDefinitionFromYaml(name, value) {
        const base = createRuleDefinition();
        const conditions = value && typeof value === 'object' ? value.conditions : undefined;
        const analyzers = value && typeof value === 'object' ? value.analyzers : undefined;
        return {
            ...base,
            key: name || '',
            ruleId: value?.id ? String(value.id) : String(name || ''),
            label: value?.label ? String(value.label) : '',
            description: value?.description ? String(value.description) : '',
            conditionsText: toYamlString(
                isPlainObject(conditions) ? conditions : createDefaultRuleConditions(),
                DEFAULT_RULE_CONDITIONS_YAML,
            ),
            analyzersText: toYamlString(isPlainObject(analyzers) ? analyzers : {}, DEFAULT_ANALYZERS_YAML),
            parsedConditions: isPlainObject(conditions) ? cloneObject(conditions) : createDefaultRuleConditions(),
            parsedAnalyzers: isPlainObject(analyzers) ? cloneObject(analyzers) : {},
            conditionTree: normalizeConditionGroup(isPlainObject(conditions) ? conditions : createDefaultRuleConditions()),
            analyzerEntries: normalizeAnalyzerEntries(isPlainObject(analyzers) ? analyzers : {}),
        };
    }

    function createRange() {
        return {
            id: generateId('range'),
            start: '',
            end: '',
        };
    }

    function createRangeFromYaml(entry) {
        if (Array.isArray(entry)) {
            return {
                id: generateId('range'),
                start: fromNumber(entry[0]),
                end: fromNumber(entry[1] ?? entry[0]),
            };
        }
        if (entry && typeof entry === 'object') {
            return {
                id: generateId('range'),
                start: fromNumber(entry.start),
                end: fromNumber(entry.end ?? entry.start),
            };
        }
        if (typeof entry === 'string') {
            const trimmed = entry.trim();
            if (!trimmed) {
                return createRange();
            }
            if (trimmed.includes('-')) {
                const [startText, endText] = trimmed.split('-', 2);
                return {
                    id: generateId('range'),
                    start: fromNumber(startText),
                    end: fromNumber(endText ?? startText),
                };
            }
            return {
                id: generateId('range'),
                start: fromNumber(trimmed),
                end: fromNumber(trimmed),
            };
        }
        const value = toNumber(entry);
        return {
            id: generateId('range'),
            start: fromNumber(value),
            end: fromNumber(value),
        };
    }

    function splitList(value) {
        if (!value) {
            return [];
        }
        if (Array.isArray(value)) {
            return value.map((item) => String(item).trim()).filter(Boolean);
        }
        return String(value)
            .split(/[,\n]/)
            .map((item) => item.trim())
            .filter(Boolean);
    }

    function parseYamlForValidation(text, options = {}) {
        const { allowEmpty = true, expectObject = false, defaultValue = null } = options;
        const raw = typeof text === 'string' ? text.trim() : '';
        if (!raw) {
            if (allowEmpty) {
                if (defaultValue !== null && defaultValue !== undefined) {
                    return { parsed: defaultValue, error: null };
                }
                if (expectObject) {
                    return { parsed: {}, error: null };
                }
                return { parsed: null, error: null };
            }
            return { parsed: null, error: 'Value is required.' };
        }
        try {
            const parsed = window.jsyaml.load(raw);
            if (expectObject && (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed))) {
                return { parsed: null, error: 'YAML must resolve to an object.' };
            }
            if (parsed === undefined || parsed === null) {
                if (defaultValue !== null && defaultValue !== undefined) {
                    return { parsed: defaultValue, error: null };
                }
                if (expectObject) {
                    return { parsed: {}, error: null };
                }
            }
            return { parsed: parsed ?? defaultValue ?? null, error: null };
        } catch (error) {
            return { parsed: null, error: `Invalid YAML: ${error.message}` };
        }
    }

    function createDefaultRuleConditions() {
        return {
            logic: 'all',
            conditions: [],
            groups: [],
        };
    }

    function isPlainObject(value) {
        return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
    }

    function cloneObject(value) {
        if (!isPlainObject(value)) {
            return {};
        }
        try {
            return JSON.parse(JSON.stringify(value));
        } catch (error) {
            console.error('Failed to clone object value for rule logic.', error);
            return { ...value };
        }
    }

    function toYamlString(value, fallback = '') {
        if (value === undefined || value === null) {
            return fallback;
        }
        try {
            if (!window.jsyaml?.dump) {
                return fallback;
            }
            const dumped = window.jsyaml.dump(value, { lineWidth: 120 });
            if (typeof dumped === 'string' && dumped.trim().length > 0) {
                return dumped.endsWith('\n') ? dumped : `${dumped}\n`;
            }
            return fallback;
        } catch (error) {
            console.error('Failed to convert value to YAML string.', error);
            return fallback;
        }
    }

    function toNumber(value) {
        if (value === null || value === undefined || value === '') {
            return null;
        }
        const numberValue = Number(value);
        return Number.isFinite(numberValue) ? numberValue : null;
    }

    function fromNumber(value) {
        if (value === null || value === undefined || value === '') {
            return '';
        }
        return String(value);
    }

    function generateId(prefix) {
        if (window.crypto?.randomUUID) {
            return `${prefix}-${window.crypto.randomUUID()}`;
        }
        return `${prefix}-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
    }

    function checkLocalStorageAvailability() {
        try {
            if (typeof window === 'undefined' || typeof window.localStorage === 'undefined') {
                return false;
            }
            const testKey = `${STORAGE_KEY}__test`;
            window.localStorage.setItem(testKey, '1');
            window.localStorage.removeItem(testKey);
            return true;
        } catch (error) {
            console.warn('Local storage is not available for admin console persistence.', error);
            return false;
        }
    }

    function restoreStateFromCache() {
        if (!storageAvailable) {
            return;
        }
        try {
            const raw = window.localStorage.getItem(STORAGE_KEY);
            if (!raw) {
                return;
            }
            const parsed = JSON.parse(raw);
            if (!parsed || typeof parsed !== 'object') {
                return;
            }
            const version = parsed.version ?? 1;
            if (version !== 1) {
                try {
                    window.localStorage.removeItem(STORAGE_KEY);
                } catch (removeError) {
                    console.error('Failed to clear incompatible cached state.', removeError);
                }
                return;
            }
            const storedState = parsed.configState && typeof parsed.configState === 'object' ? parsed.configState : {};
            const storedPassthrough = parsed.passthroughConfig;
            let sanitizedPassthrough = {};
            if (storedPassthrough && typeof storedPassthrough === 'object') {
                try {
                    sanitizedPassthrough = JSON.parse(JSON.stringify(storedPassthrough));
                } catch (cloneError) {
                    console.error('Failed to sanitize cached passthrough configuration.', cloneError);
                    sanitizedPassthrough = {};
                }
            }
            passthroughConfig = sanitizedPassthrough;
            configState.riskLevels = Array.isArray(storedState.riskLevels)
                ? storedState.riskLevels.map((entry) => rehydrateRiskLevel(entry))
                : [];
            configState.cidrLimitSets = Array.isArray(storedState.cidrLimitSets)
                ? storedState.cidrLimitSets.map((entry) => rehydrateCidrSet(entry))
                : [];
            configState.portGroups = Array.isArray(storedState.portGroups)
                ? storedState.portGroups.map((entry) => rehydratePortGroup(entry))
                : [];
            configState.ruleLogic = Array.isArray(storedState.ruleLogic)
                ? storedState.ruleLogic.map((entry) => rehydrateRuleDefinition(entry))
                : [];
        } catch (error) {
            console.error('Failed to restore cached admin state.', error);
            try {
                window.localStorage.removeItem(STORAGE_KEY);
            } catch (removeError) {
                console.error('Failed to clear invalid cached state.', removeError);
            }
        }
    }

    function persistState() {
        if (!storageAvailable) {
            return;
        }
        try {
            const passthroughHasData =
                passthroughConfig &&
                typeof passthroughConfig === 'object' &&
                Object.keys(passthroughConfig).length > 0;
            const hasData =
                configState.riskLevels.length > 0 ||
                configState.cidrLimitSets.length > 0 ||
                configState.portGroups.length > 0 ||
                configState.ruleLogic.length > 0 ||
                passthroughHasData;
            if (!hasData) {
                window.localStorage.removeItem(STORAGE_KEY);
                return;
            }
            const payload = {
                version: 1,
                configState: createSerializableConfigState(),
                passthroughConfig: clonePassthroughConfig(),
            };
            window.localStorage.setItem(STORAGE_KEY, JSON.stringify(payload));
        } catch (error) {
            console.error('Failed to persist admin console state.', error);
        }
    }

    function createSerializableConfigState() {
        return {
            riskLevels: configState.riskLevels.map((level) => serializeRiskLevel(level)),
            cidrLimitSets: configState.cidrLimitSets.map((set) => serializeCidrSet(set)),
            portGroups: configState.portGroups.map((group) => serializePortGroup(group)),
            ruleLogic: configState.ruleLogic.map((rule) => serializeRuleDefinition(rule)),
        };
    }

    function serializeRiskLevel(level) {
        const thresholdsSource = level && typeof level === 'object' && level.thresholds && typeof level.thresholds === 'object' ? level.thresholds : {};
        const thresholds = { ...thresholdsSource };
        Object.keys(thresholds).forEach((key) => {
            const value = thresholds[key];
            thresholds[key] = value === null || value === undefined ? '' : String(value);
        });
        const rationaleSource = level && typeof level === 'object' && level.rationale && typeof level.rationale === 'object' ? level.rationale : {};
        const references = Array.isArray(rationaleSource.references)
            ? rationaleSource.references.map((item) => String(item).trim()).filter(Boolean)
            : splitList(rationaleSource.references);
        const severityCandidate = typeof level?.severity === 'string' ? level.severity.toLowerCase() : 'low';
        const severity = severityOptions.some((option) => option.value === severityCandidate) ? severityCandidate : 'low';
        return {
            id: level?.id,
            name: level?.name ? String(level.name) : '',
            label: level?.label ? String(level.label) : '',
            severity,
            thresholds,
            rationale: {
                summary: rationaleSource.summary ? String(rationaleSource.summary) : '',
                details: rationaleSource.details ? String(rationaleSource.details) : '',
                references,
            },
        };
    }

    function serializeCidrSet(set) {
        if (!set || typeof set !== 'object') {
            const base = createCidrSet();
            return {
                id: base.id,
                name: base.name,
                defaultPolicy: serializePolicy(base.defaultPolicy),
                overrides: base.overrides,
            };
        }
        const overrides = Array.isArray(set.overrides)
            ? set.overrides.map((override) => {
                  const allowedScopes = ['analyzer', 'vendor', 'direction', 'vendor_direction'];
                  const scopeCandidate = typeof override?.scope === 'string' ? override.scope.toLowerCase() : 'analyzer';
                  const scope = allowedScopes.includes(scopeCandidate) ? scopeCandidate : 'analyzer';
                  return {
                      id: override?.id,
                      scope,
                      key: override?.key ? String(override.key) : '',
                      vendor: override?.vendor ? String(override.vendor) : '',
                      direction: override?.direction ? String(override.direction) : '',
                      policy: serializePolicy(override?.policy),
                  };
              })
            : [];
        return {
            id: set?.id,
            name: set?.name ? String(set.name) : '',
            defaultPolicy: serializePolicy(set.defaultPolicy),
            overrides,
        };
    }

    function serializePolicy(policy) {
        if (!policy || typeof policy !== 'object') {
            return createPolicy();
        }
        const blocked = Array.isArray(policy.blocked)
            ? policy.blocked.map((entry) => String(entry).trim()).filter(Boolean)
            : splitList(policy.blocked);
        const exempt = Array.isArray(policy.exempt)
            ? policy.exempt.map((entry) => String(entry).trim()).filter(Boolean)
            : splitList(policy.exempt);
        return {
            max_prefix: policy.max_prefix === null || policy.max_prefix === undefined ? '' : String(policy.max_prefix),
            min_prefix: policy.min_prefix === null || policy.min_prefix === undefined ? '' : String(policy.min_prefix),
            blocked,
            exempt,
            description: policy.description ? String(policy.description) : '',
        };
    }

    function serializePortGroup(group) {
        if (!group || typeof group !== 'object') {
            const base = createPortGroup();
            return {
                id: base.id,
                name: base.name,
                description: base.description,
                protocol: base.protocol,
                ranges: base.ranges,
            };
        }
        const allowedProtocols = ['any', 'tcp', 'udp'];
        const protocolCandidate = typeof group.protocol === 'string' ? group.protocol.toLowerCase() : 'any';
        const protocol = allowedProtocols.includes(protocolCandidate) ? protocolCandidate : 'any';
        const ranges = Array.isArray(group.ranges)
            ? group.ranges.map((range) => serializeRange(range))
            : [];
        return {
            id: group?.id,
            name: group?.name ? String(group.name) : '',
            description: group?.description ? String(group.description) : '',
            protocol,
            ranges,
        };
    }

    function serializeRuleDefinition(rule) {
        if (!rule || typeof rule !== 'object') {
            const base = createRuleDefinition();
            return {
                id: base.id,
                key: base.key,
                ruleId: base.ruleId,
                label: base.label,
                description: base.description,
                conditionsText: base.conditionsText,
                analyzersText: base.analyzersText,
            };
        }
        const conditionsText =
            typeof rule.conditionsText === 'string' && rule.conditionsText.trim().length > 0
                ? rule.conditionsText
                : DEFAULT_RULE_CONDITIONS_YAML;
        const analyzersText =
            typeof rule.analyzersText === 'string' && rule.analyzersText.trim().length > 0
                ? rule.analyzersText
                : DEFAULT_ANALYZERS_YAML;
        return {
            id: rule.id,
            key: rule.key ? String(rule.key) : '',
            ruleId: rule.ruleId ? String(rule.ruleId) : '',
            label: rule.label ? String(rule.label) : '',
            description: rule.description ? String(rule.description) : '',
            conditionsText,
            analyzersText,
            parsedConditions: isPlainObject(rule.parsedConditions)
                ? cloneObject(rule.parsedConditions)
                : createDefaultRuleConditions(),
            parsedAnalyzers: isPlainObject(rule.parsedAnalyzers) ? cloneObject(rule.parsedAnalyzers) : {},
            conditionTree: cloneConditionGroup(rule.conditionTree),
            analyzerEntries: Array.isArray(rule.analyzerEntries)
                ? rule.analyzerEntries.map((entry) => cloneAnalyzerEntry(entry))
                : [],
            validationMessages: Array.isArray(rule.validationMessages) ? [...rule.validationMessages] : [],
        };
    }

    function serializeRange(range) {
        if (!range || typeof range !== 'object') {
            const base = createRange();
            return {
                id: base.id,
                start: base.start,
                end: base.end,
            };
        }
        return {
            id: range.id,
            start: range.start === null || range.start === undefined ? '' : String(range.start),
            end: range.end === null || range.end === undefined ? '' : String(range.end),
        };
    }

    function rehydrateRiskLevel(raw) {
        const base = createRiskLevel();
        if (!raw || typeof raw !== 'object') {
            return base;
        }
        const thresholds = { ...base.thresholds };
        Object.keys(thresholds).forEach((key) => {
            const value = raw.thresholds?.[key];
            thresholds[key] = value === null || value === undefined ? '' : String(value);
        });
        const severityCandidate = typeof raw.severity === 'string' ? raw.severity.toLowerCase() : 'low';
        const severity = severityOptions.some((option) => option.value === severityCandidate) ? severityCandidate : 'low';
        const references = Array.isArray(raw.rationale?.references)
            ? raw.rationale.references.map((item) => String(item).trim()).filter(Boolean)
            : splitList(raw.rationale?.references);
        return {
            ...base,
            id: raw.id || base.id,
            name: raw.name ? String(raw.name) : '',
            label: raw.label ? String(raw.label) : '',
            severity,
            thresholds,
            rationale: {
                summary: raw.rationale?.summary ? String(raw.rationale.summary) : '',
                details: raw.rationale?.details ? String(raw.rationale.details) : '',
                references,
            },
        };
    }

    function rehydrateCidrSet(raw) {
        const base = createCidrSet();
        if (!raw || typeof raw !== 'object') {
            return base;
        }
        return {
            ...base,
            id: raw.id || base.id,
            name: raw.name ? String(raw.name) : '',
            defaultPolicy: rehydratePolicy(raw.defaultPolicy),
            overrides: Array.isArray(raw.overrides)
                ? raw.overrides.map((entry) => rehydrateCidrOverride(entry))
                : [],
        };
    }

    function rehydratePolicy(raw) {
        const base = createPolicy();
        if (!raw || typeof raw !== 'object') {
            return base;
        }
        return {
            ...base,
            max_prefix: raw.max_prefix === null || raw.max_prefix === undefined ? '' : String(raw.max_prefix),
            min_prefix: raw.min_prefix === null || raw.min_prefix === undefined ? '' : String(raw.min_prefix),
            blocked: Array.isArray(raw.blocked)
                ? raw.blocked.map((entry) => String(entry).trim()).filter(Boolean)
                : splitList(raw.blocked),
            exempt: Array.isArray(raw.exempt)
                ? raw.exempt.map((entry) => String(entry).trim()).filter(Boolean)
                : splitList(raw.exempt),
            description: raw.description ? String(raw.description) : '',
        };
    }

    function rehydrateCidrOverride(raw) {
        const base = createCidrOverride();
        if (!raw || typeof raw !== 'object') {
            return base;
        }
        const allowedScopes = ['analyzer', 'vendor', 'direction', 'vendor_direction'];
        const scopeCandidate = typeof raw.scope === 'string' ? raw.scope.toLowerCase() : base.scope;
        const scope = allowedScopes.includes(scopeCandidate) ? scopeCandidate : base.scope;
        return {
            ...base,
            id: raw.id || base.id,
            scope,
            key: raw.key ? String(raw.key) : '',
            vendor: raw.vendor ? String(raw.vendor) : '',
            direction: raw.direction ? String(raw.direction) : '',
            policy: rehydratePolicy(raw.policy),
        };
    }

    function rehydratePortGroup(raw) {
        const base = createPortGroup();
        if (!raw || typeof raw !== 'object') {
            return base;
        }
        const allowedProtocols = ['any', 'tcp', 'udp'];
        const protocolCandidate = typeof raw.protocol === 'string' ? raw.protocol.toLowerCase() : base.protocol;
        const protocol = allowedProtocols.includes(protocolCandidate) ? protocolCandidate : base.protocol;
        return {
            ...base,
            id: raw.id || base.id,
            name: raw.name ? String(raw.name) : '',
            description: raw.description ? String(raw.description) : '',
            protocol,
            ranges: Array.isArray(raw.ranges)
                ? raw.ranges.map((entry) => rehydrateRange(entry))
                : [],
        };
    }

    function rehydrateRange(raw) {
        const base = createRange();
        if (!raw || typeof raw !== 'object') {
            return base;
        }
        return {
            ...base,
            id: raw.id || base.id,
            start: raw.start === null || raw.start === undefined ? '' : String(raw.start),
            end: raw.end === null || raw.end === undefined ? '' : String(raw.end),
        };
    }

    function rehydrateRuleDefinition(raw) {
        const base = createRuleDefinition();
        if (!raw || typeof raw !== 'object') {
            return base;
        }
        const conditionsText =
            typeof raw.conditionsText === 'string' && raw.conditionsText.trim().length > 0
                ? raw.conditionsText
                : DEFAULT_RULE_CONDITIONS_YAML;
        const analyzersText =
            typeof raw.analyzersText === 'string' && raw.analyzersText.trim().length > 0
                ? raw.analyzersText
                : DEFAULT_ANALYZERS_YAML;
        const conditionsResult = parseYamlForValidation(conditionsText, {
            allowEmpty: false,
            expectObject: true,
            defaultValue: createDefaultRuleConditions(),
        });
        const analyzersResult = parseYamlForValidation(analyzersText, {
            allowEmpty: true,
            expectObject: true,
            defaultValue: {},
        });
        return {
            ...base,
            id: raw.id || base.id,
            key: raw.key ? String(raw.key) : '',
            ruleId: raw.ruleId ? String(raw.ruleId) : '',
            label: raw.label ? String(raw.label) : '',
            description: raw.description ? String(raw.description) : '',
            conditionsText,
            analyzersText,
            parsedConditions: conditionsResult.parsed ?? createDefaultRuleConditions(),
            parsedAnalyzers: analyzersResult.parsed ?? {},
            conditionTree: normalizeConditionGroup(conditionsResult.parsed ?? createDefaultRuleConditions()),
            analyzerEntries: normalizeAnalyzerEntries(analyzersResult.parsed ?? {}),
            validationMessages: Array.isArray(raw.validationMessages) ? raw.validationMessages : [],
        };
    }

    function clonePassthroughConfig() {
        if (!passthroughConfig || typeof passthroughConfig !== 'object') {
            return {};
        }
        try {
            return JSON.parse(JSON.stringify(passthroughConfig));
        } catch (error) {
            console.error('Failed to clone passthrough configuration for persistence.', error);
            return {};
        }
    }

    function createRuleConfigApi() {
        async function request(path, options = {}) {
            if (typeof fetch !== 'function') {
                throw new Error('Fetch API is not available in this environment.');
            }
            const { method = 'GET', token, body, signal } = options;
            const headers = { Accept: 'application/json' };
            if (body !== undefined) {
                headers['Content-Type'] = 'application/json';
            }
            if (typeof token === 'string' && token.trim().length > 0) {
                const trimmed = token.trim();
                headers.Authorization = trimmed.toLowerCase().startsWith('bearer ')
                    ? trimmed
                    : `Bearer ${trimmed}`;
            }
            const response = await fetch(path, {
                method,
                headers,
                body: body !== undefined ? JSON.stringify(body) : undefined,
                signal,
            });
            if (!response.ok) {
                const errorText = await response.text().catch(() => '');
                throw new Error(errorText || `Request to ${path} failed with status ${response.status}`);
            }
            if (response.status === 204) {
                return null;
            }
            const contentType = response.headers.get('content-type') || '';
            if (contentType.includes('application/json')) {
                return response.json();
            }
            return null;
        }

        return {
            fetchConfig(options = {}) {
                return request('/api/config/rules', options);
            },
            fetchHistory(options = {}) {
                const { limit = 20, token, signal } = options;
                const params = new URLSearchParams();
                if (limit !== undefined && limit !== null) {
                    params.set('limit', String(limit));
                }
                const query = params.toString();
                const path = `/api/config/rules/history${query ? `?${query}` : ''}`;
                return request(path, { token, signal });
            },
            patchConfig(changes, options = {}) {
                if (!changes || typeof changes !== 'object' || Object.keys(changes).length === 0) {
                    return Promise.reject(new Error('Changes payload must be a non-empty object.'));
                }
                const payload = { changes: { ...changes } };
                if (options.message && typeof options.message === 'string') {
                    payload.message = options.message;
                }
                return request('/api/config/rules', {
                    method: 'PATCH',
                    token: options.token,
                    signal: options.signal,
                    body: payload,
                });
            },
        };
    }

    function showToast(message, isError = false) {
        const existing = document.querySelector('.toast');
        if (existing) existing.remove();

        const toast = document.createElement('div');
        toast.className = isError ? 'toast toast-error' : 'toast toast-success';
        toast.innerHTML = sanitize(message);

        document.body.appendChild(toast);

        setTimeout(() => {
            toast.classList.add('show');
        }, 10);

        const duration = isError ? 5000 : 3000;
        setTimeout(() => {
            toast.classList.remove('show');
            setTimeout(() => {
                if (toast.parentElement) {
                    toast.remove();
                }
            }, 300);
        }, duration);
    }
})();
