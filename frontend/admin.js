(function () {
    const severityOptions = [
        { value: 'critical', label: 'Critical' },
        { value: 'high', label: 'High' },
        { value: 'medium', label: 'Medium' },
        { value: 'low', label: 'Low' },
        { value: 'informational', label: 'Informational' },
    ];

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
            const response = await ruleConfigApi.fetchConfig();
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
            }, { compact: true, placeholder: 'fortinet', errorKey: `${override.id}_vendor` }));
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
        container.innerHTML = '';
        configState.ruleLogic.forEach((rule) => {
            const card = document.createElement('article');
            card.className = 'config-card rule-logic-card';
            card.dataset.ruleId = rule.id;

            const header = document.createElement('div');
            header.className = 'card-header';
            const title = document.createElement('h3');
            const updateTitle = () => {
                const preferred = (rule.label || '').trim() || (rule.key || '').trim();
                title.textContent = preferred || 'New rule definition';
            };
            updateTitle();
            header.appendChild(title);

            const deleteBtn = document.createElement('button');
            deleteBtn.type = 'button';
            deleteBtn.className = 'icon-btn danger';
            deleteBtn.innerHTML = '<i class="fa-solid fa-trash"></i>';
            deleteBtn.title = 'Delete rule definition';
            deleteBtn.addEventListener('click', () => {
                configState.ruleLogic = configState.ruleLogic.filter((item) => item.id !== rule.id);
                renderRuleLogic();
                runValidation();
                showToast(`Removed rule definition '${(rule.label || rule.key || 'unnamed').trim() || 'unnamed'}'.`);
            });
            header.appendChild(deleteBtn);
            card.appendChild(header);

            const body = document.createElement('div');
            body.className = 'card-body';

            body.appendChild(
                createTextField('Rule Identifier', rule.key, (value) => {
                    rule.key = value;
                    updateTitle();
                    runValidation({ suppressErrorToast: true });
                }, {
                    placeholder: 'admin_port_exposed',
                    help: 'Unique key used in the rules YAML mapping.',
                    errorKey: 'key',
                }),
            );

            body.appendChild(
                createTextField('Rule ID', rule.ruleId, (value) => {
                    rule.ruleId = value;
                    runValidation({ suppressErrorToast: true });
                }, {
                    placeholder: 'admin_port_exposed',
                    help: 'Identifier persisted inside the rule definition. Defaults to the rule identifier when omitted.',
                    errorKey: 'ruleId',
                }),
            );

            body.appendChild(
                createTextField('Label', rule.label, (value) => {
                    rule.label = value;
                    updateTitle();
                    runValidation({ suppressErrorToast: true });
                }, {
                    placeholder: 'Administrative Port Exposure',
                    errorKey: 'label',
                }),
            );

            body.appendChild(
                createTextareaField('Description', rule.description, (value) => {
                    rule.description = value;
                    runValidation({ suppressErrorToast: true });
                }, {
                    rows: 3,
                    placeholder: 'Explain what the rule detects and how it should be interpreted.',
                }),
            );

            body.appendChild(
                createTextareaField('Conditions (YAML)', rule.conditionsText, (value) => {
                    rule.conditionsText = value;
                    runValidation({ suppressErrorToast: true });
                }, {
                    rows: 8,
                    placeholder: 'logic: all\nconditions: []\ngroups: []',
                    help: 'Structured condition tree describing how findings are generated.',
                    errorKey: 'conditions',
                    monospace: true,
                    spellcheck: false,
                }),
            );

            body.appendChild(
                createTextareaField('Analyzers (YAML)', rule.analyzersText, (value) => {
                    rule.analyzersText = value;
                    runValidation({ suppressErrorToast: true });
                }, {
                    rows: 8,
                    placeholder: 'analyzer_key:\n  enabled: true\n  notes: ...',
                    help: 'Analyzer-specific overrides including severity tiers and administrative port configuration.',
                    errorKey: 'analyzers',
                    monospace: true,
                    spellcheck: false,
                }),
            );

            body.appendChild(createFieldError('general'));

            card.appendChild(body);
            container.appendChild(card);
        });
    }

    function createTextField(labelText, value, onInput, options = {}) {
        const wrapper = document.createElement('label');
        wrapper.className = `form-field${options.compact ? ' compact' : ''}`;
        wrapper.innerHTML = `<span class="field-label">${labelText}</span>`;

        const input = document.createElement('input');
        input.type = 'text';
        input.value = value ?? '';
        if (options.placeholder) {
            input.placeholder = options.placeholder;
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
        wrapper.innerHTML = `<span class="field-label">${labelText}</span>`;

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
        wrapper.innerHTML = `<span class="field-label">${labelText}</span>`;

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
        wrapper.innerHTML = `<span class="field-label">${labelText}</span>`;

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
        legend.innerHTML = `<span>${title}</span><span class="fieldset-hint">Set prefix limits and CIDR allow/deny lists.</span>`;
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
        const identifierCounts = {};
        configState.ruleLogic.forEach((rule) => {
            const ruleErrors = {};
            const identifier = (rule.key || '').trim();
            if (!identifier) {
                ruleErrors.key = 'Rule identifier is required.';
            } else {
                const normalized = identifier.toLowerCase();
                identifierCounts[normalized] = (identifierCounts[normalized] || 0) + 1;
            }

            const ruleId = (rule.ruleId || '').trim() || identifier;
            if (!ruleId) {
                ruleErrors.ruleId = 'Rule ID is required.';
            }

            if (!(rule.label || '').trim()) {
                ruleErrors.label = 'Label is required.';
            }

            const conditionsResult = parseYamlForValidation(rule.conditionsText, {
                allowEmpty: false,
                expectObject: true,
            });
            if (conditionsResult.error) {
                ruleErrors.conditions = conditionsResult.error;
            }
            rule.parsedConditions = conditionsResult.parsed;

            const analyzersResult = parseYamlForValidation(rule.analyzersText, {
                allowEmpty: true,
                expectObject: true,
                defaultValue: {},
            });
            if (analyzersResult.error) {
                ruleErrors.analyzers = analyzersResult.error;
            }
            rule.parsedAnalyzers = analyzersResult.parsed;

            if (Object.keys(ruleErrors).length > 0) {
                errors[rule.id] = ruleErrors;
            }
        });

        Object.entries(identifierCounts).forEach(([identifier, count]) => {
            if (count > 1) {
                configState.ruleLogic.forEach((rule) => {
                    if ((rule.key || '').trim().toLowerCase() === identifier) {
                        if (!errors[rule.id]) {
                            errors[rule.id] = {};
                        }
                        errors[rule.id].key = 'Rule identifier must be unique.';
                    }
                });
            }
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
        return {
            id: generateId('rule'),
            key: '',
            ruleId: '',
            label: '',
            description: '',
            conditionsText: DEFAULT_RULE_CONDITIONS_YAML,
            analyzersText: DEFAULT_ANALYZERS_YAML,
            parsedConditions: createDefaultRuleConditions(),
            parsedAnalyzers: {},
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
        const toast = document.querySelector(selectors.toast);
        if (!toast) {
            return;
        }
        toast.textContent = message;
        toast.classList.toggle('error', isError);
        toast.classList.add('visible');
        setTimeout(() => {
            toast.classList.remove('visible');
        }, 4000);
    }
})();