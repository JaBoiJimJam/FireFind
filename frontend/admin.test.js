/**
 * @jest-environment node
 */

const fs = require('fs');
const path = require('path');
const { JSDOM } = require('jsdom');

const ADMIN_SCRIPT = fs.readFileSync(path.resolve(__dirname, 'admin.js'), 'utf8');
const STORAGE_KEY = 'firefind:admin-state:v1';

function createLocalStorageMock() {
    let store = {};
    return {
        getItem: jest.fn((key) => (key in store ? store[key] : null)),
        setItem: jest.fn((key, value) => {
            store[key] = String(value);
        }),
        removeItem: jest.fn((key) => {
            delete store[key];
        }),
        clear: jest.fn(() => {
            store = {};
        }),
    };
}

async function bootstrapAdminDom() {
    const dom = new JSDOM(
        `<!DOCTYPE html>
        <html>
          <body>
            <header></header>
            <main class="admin-main">
              <section class="admin-section">
                <button id="addRiskLevelBtn"></button>
                <button id="addCidrSetBtn"></button>
                <button id="addPortGroupBtn"></button>
                <button id="addRuleLogicBtn"></button>
                <button id="importYamlBtn"></button>
                <button id="exportYamlBtn"></button>
                <input id="yamlFileInput" />
                <div id="riskLevelsList"></div>
                <div id="cidrSetsList"></div>
                <div id="portGroupsList"></div>
                <div id="ruleLogicList"></div>
                <div id="validationSummary"></div>
              </section>
            </main>
            <div id="adminToast"></div>
          </body>
        </html>`,
        {
            url: 'http://localhost/admin.html',
            pretendToBeVisual: true,
            runScripts: 'outside-only',
        },
    );

    const { window } = dom;
    window.fetch = jest.fn().mockResolvedValue({
        ok: false,
        status: 401,
        text: async () => 'Unauthorized',
        headers: { get: () => 'application/json' },
    });
    window.jsyaml = {
        dump: jest.fn(() => ''),
        load: jest.fn(() => ({})),
    };
    window.ipaddr = { parseCIDR: jest.fn() };
    window.URL.createObjectURL = jest.fn(() => 'blob:mock');
    window.URL.revokeObjectURL = jest.fn();
    let counter = 0;
    window.crypto = {
        randomUUID: jest.fn(() => {
            counter += 1;
            return `uuid-${counter}`;
        }),
    };
    window.localStorage = createLocalStorageMock();
    window.requestAnimationFrame = (callback) => {
        callback();
        return 0;
    };
    window.setTimeout = (callback) => {
        callback();
        return 0;
    };

    window.eval(ADMIN_SCRIPT);
    window.document.dispatchEvent(new window.Event('DOMContentLoaded'));
    await new Promise((resolve) => window.setTimeout(resolve, 0));
    return { window, document: window.document };
}

function findInputByLabel(container, text) {
    const labels = Array.from(container.querySelectorAll('label.form-field'));
    const target = labels.find((label) => {
        const labelText = label.querySelector('.field-label');
        return labelText && labelText.textContent.trim() === text;
    });
    if (!target) {
        throw new Error(`Label '${text}' not found`);
    }
    return target.querySelector('input, textarea');
}

function clickButtonByText(container, text) {
    const button = Array.from(container.querySelectorAll('button')).find((element) =>
        element.textContent.trim().includes(text),
    );
    if (!button) {
        throw new Error(`Button containing '${text}' not found`);
    }
    button.click();
    return button;
}

describe('admin rule management', () => {
    test('renders an empty state before any rules are added', async () => {
        const { window, document } = await bootstrapAdminDom();
        const cards = document.querySelectorAll('.rule-logic-card');
        expect(cards.length).toBe(0);
        const emptyState = document.querySelector('.empty-state');
        expect(emptyState).not.toBeNull();
        expect(emptyState.textContent).toContain('No rule definitions configured yet');
    });

    test('supports creating, editing, and removing a rule definition', async () => {
        const { window, document } = await bootstrapAdminDom();
        const initialCards = Array.from(document.querySelectorAll('.rule-logic-card'));

        document.getElementById('addRuleLogicBtn').click();
        await Promise.resolve();

        const cards = Array.from(document.querySelectorAll('.rule-logic-card'));
        expect(cards.length).toBeGreaterThan(initialCards.length);
        const cardCountAfterAddition = cards.length;

        const newCard = cards[cards.length - 1];
        const targetRuleId = newCard.dataset.ruleId;
        newCard.querySelector('.rule-edit-btn').click();
        await Promise.resolve();

        const modal = document.querySelector('[data-component="rule-editor"]');
        const summary = modal.querySelector('[data-role="editor-validation-summary"]');
        expect(summary.textContent).toContain('Rule identifier is required');

        const identifierInput = findInputByLabel(modal, 'Rule identifier');
        identifierInput.value = 'admin_port_exposed';
        identifierInput.dispatchEvent(new window.Event('input', { bubbles: true }));

        const ruleIdInput = findInputByLabel(modal, 'Rule ID');
        ruleIdInput.value = 'admin_port_exposed';
        ruleIdInput.dispatchEvent(new window.Event('input', { bubbles: true }));

        const labelInput = findInputByLabel(modal, 'Label');
        labelInput.value = 'Administrative port exposure';
        labelInput.dispatchEvent(new window.Event('input', { bubbles: true }));

        clickButtonByText(modal, 'Add condition');
        const conditionRow = modal.querySelector('.condition-row');
        conditionRow.querySelector('.condition-field-input').value = 'action';
        conditionRow
            .querySelector('.condition-field-input')
            .dispatchEvent(new window.Event('input', { bubbles: true }));
        const valueInput = conditionRow.querySelector('.condition-value-wrapper input');
        valueInput.value = 'allow';
        valueInput.dispatchEvent(new window.Event('input', { bubbles: true }));

        const analyzerInput = findInputByLabel(modal, 'Analyzer key');
        analyzerInput.value = 'admin_port_exposed';
        analyzerInput.dispatchEvent(new window.Event('input', { bubbles: true }));

        expect(summary.textContent).toContain('Rule is valid.');

        modal.querySelector('button[type="submit"]').click();
        await Promise.resolve();

        const cardAfterSave = document.querySelector(`.rule-logic-card[data-rule-id="${targetRuleId}"]`);
        expect(cardAfterSave).not.toBeNull();

        cardAfterSave.querySelector('button[aria-label^="Delete "]').click();
        await Promise.resolve();

        const removedCard = document.querySelector(`.rule-logic-card[data-rule-id="${targetRuleId}"]`);
        expect(removedCard).toBeNull();
        const finalCount = document.querySelectorAll('.rule-logic-card').length;
        expect(finalCount).toBeLessThan(cardCountAfterAddition);
    });
});
