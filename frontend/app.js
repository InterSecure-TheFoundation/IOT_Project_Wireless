// ============================================================
// STATE
// filters: { field: ['val1', 'val2', ...] }  ← OR within field, AND between fields
// ============================================================
const DEFAULT_COLUMNS = ['ip', 'timestamp', 'method', 'path', 'http_version', 'status_code', 'bytes', 'user_agent', 'suspicious'];

const state = {
    mode:           'raw',
    visibleColumns: new Set(DEFAULT_COLUMNS),
    filters:        {},   // { ip: ['1.1.1.1', '2.2.2.2'], method: ['GET'] }
    logs:           [],
    total:          0,
    limit:          50,
    offset:         0,
    // Live updates are always on at page 1 (offset === 0).
    // When paginating (offset > 0), WS updates are paused automatically.
    // When filters are active, incoming WS logs are checked against matchesFilters().
};

// ============================================================
// WEBSOCKET
// ============================================================
const WS_PORT = 3001;
let socket;

function connectWebSocket() {
    socket = new WebSocket(`ws://${location.hostname}:${WS_PORT}`);

    socket.addEventListener('open', () => setWsStatus(true));

    socket.addEventListener('message', (event) => {
        // Pause live updates only when paginating (user is viewing a non-first page)
        if (state.offset > 0) return;

        let msg;
        try { msg = JSON.parse(event.data); } catch { return; }
        if (msg.type !== 'log') return;

        // If filters are active, only show logs that match them
        if (!matchesFilters(msg.data)) return;

        state.logs.unshift(msg.data);
        if (state.logs.length > state.limit) state.logs.pop();
        renderCurrentView(true);
    });

    socket.addEventListener('close', () => {
        setWsStatus(false);
        setTimeout(connectWebSocket, 3000);
    });

    socket.addEventListener('error', () => socket.close());
}

function setWsStatus(connected) {
    const badge = document.getElementById('ws-status');
    badge.textContent = '';
    const dot = document.createElement('span');
    dot.className = 'badge-dot';
    badge.appendChild(dot);
    badge.append(' ' + (connected ? 'Live' : 'Disconnected'));
    badge.className = connected ? 'badge connected' : 'badge disconnected';
}

// ============================================================
// API
// ============================================================
async function fetchLogs() {
    const params = new URLSearchParams({ limit: state.limit, offset: state.offset });

    // Send multi-value filters as comma-separated: ip=1.1.1.1,2.2.2.2
    for (const [field, values] of Object.entries(state.filters)) {
        if (values && values.length > 0) {
            params.set(field, values.join(','));
        }
    }

    const res  = await fetch(`/api/logs?${params}`);
    const data = await res.json();
    state.logs  = data.logs;
    state.total = data.total;
    updatePagination();
    renderCurrentView();
}

async function fetchFields() {
    const res  = await fetch('/api/logs/fields');
    const data = await res.json();
    buildFilterForm(data.fields);
    buildColumnSelector(data.fields);
}

// ============================================================
// RENDER
// ============================================================
function renderCurrentView(isNew = false) {
    const empty = state.logs.length === 0;
    document.getElementById('empty-state').classList.toggle('hidden', !empty);

    if (state.mode === 'raw') renderRawView(state.logs, isNew);
    else                      renderTableView(state.logs, isNew);
}

// --- Raw ---
function renderRawView(logs, isNew = false) {
    const container = document.getElementById('view-raw');

    if (isNew && logs.length > 0) {
        const line = createRawLine(logs[0], true);
        container.insertBefore(line, container.firstChild);
        while (container.children.length > state.limit) container.removeChild(container.lastChild);
        return;
    }

    container.innerHTML = '';
    const frag = document.createDocumentFragment();
    for (const log of logs) frag.appendChild(createRawLine(log, false));
    container.appendChild(frag);
}

function createRawLine(log, isNew) {
    const div = document.createElement('div');
    div.className   = isNew ? 'log-line new' : 'log-line';
    div.textContent = log.raw || reconstructRaw(log);
    return div;
}

function reconstructRaw(log) {
    return [log.ip||'-', `[${log.timestamp||'-'}]`,
        `"${log.method||'-'} ${log.path||'-'} ${log.http_version||'-'}"`,
        log.status_code??'-', log.bytes??'-', `"${log.user_agent||'-'}"`].join(' ');
}

// --- Table ---
function renderTableView(logs, isNew = false) {
    rebuildTableHeader();
    const body = document.getElementById('table-body');

    if (isNew && logs.length > 0) {
        body.insertBefore(createTableRow(logs[0], true), body.firstChild);
        while (body.children.length > state.limit) body.removeChild(body.lastChild);
        return;
    }

    body.innerHTML = '';
    const frag = document.createDocumentFragment();
    for (const log of logs) frag.appendChild(createTableRow(log, false));
    body.appendChild(frag);
}

function rebuildTableHeader() {
    const row = document.getElementById('table-header-row');
    row.innerHTML = '';
    for (const col of state.visibleColumns) {
        const th = document.createElement('th');
        th.textContent = col.replace(/_/g, ' ').toUpperCase();
        row.appendChild(th);
    }
}

function createTableRow(log, isNew) {
    const tr = document.createElement('tr');
    if (isNew) tr.className = 'new';

    for (const col of state.visibleColumns) {
        const td = document.createElement('td');
        td.title = String(log[col] ?? '');

        if (col === 'status_code' && log.status_code != null) {
            const pill = document.createElement('span');
            pill.textContent = log.status_code;
            pill.className   = 'status-pill ' + statusClass(log.status_code);
            td.appendChild(pill);
        } else if (col === 'suspicious') {
            const pill = document.createElement('span');
            const isSus = log.suspicious === 1 || log.suspicious === true;
            pill.textContent = isSus ? 'Suspicious' : 'Safe';
            pill.className   = isSus ? 'sus-pill sus-yes' : 'sus-pill sus-no';
            if (log.sus_reason) {
                pill.title = log.sus_reason.replace(/;\s*/g, '\n');
                td.title   = '';   // clear the outer td title so pill title takes over
            }
            td.appendChild(pill);
        } else {
            td.textContent = log[col] ?? '-';
        }

        tr.appendChild(td);
    }
    return tr;
}

function statusClass(code) {
    if (code >= 500) return 'status-5xx';
    if (code >= 400) return 'status-4xx';
    if (code >= 300) return 'status-3xx';
    return 'status-2xx';
}

// ============================================================
// TAG FILTER SYSTEM
// ============================================================
function buildFilterForm(fields) {
    const container = document.getElementById('filter-fields');
    container.innerHTML = '';

    for (const field of fields) {
        const wrapper = document.createElement('div');
        wrapper.className = 'filter-field';

        const label = document.createElement('label');
        label.textContent = field.replace(/_/g, ' ');

        const tagWrap = document.createElement('div');
        tagWrap.className   = 'tag-input-wrap';
        tagWrap.dataset.field = field;

        const textInput = document.createElement('input');
        textInput.type        = 'text';
        textInput.className   = 'tag-text-input';
        textInput.placeholder = `Type & press Enter`;
        textInput.autocomplete = 'off';

        textInput.addEventListener('keydown', (e) => {
            const val = textInput.value.trim();

            if ((e.key === 'Enter' || e.key === ',') && val) {
                e.preventDefault();
                addTag(field, val, tagWrap, textInput);
            }

            // Backspace on empty input removes last tag
            if (e.key === 'Backspace' && !textInput.value) {
                const tags = state.filters[field] || [];
                if (tags.length > 0) {
                    removeTag(field, tags[tags.length - 1], tagWrap);
                }
            }
        });

        // Click anywhere on the wrap → focus input
        tagWrap.addEventListener('click', () => textInput.focus());
        tagWrap.appendChild(textInput);

        const hint = document.createElement('span');
        hint.className   = 'filter-hint';
        hint.textContent = 'Enter or , to add • multiple values = OR';

        wrapper.appendChild(label);
        wrapper.appendChild(tagWrap);
        wrapper.appendChild(hint);
        container.appendChild(wrapper);
    }
}

function addTag(field, value, tagWrap, textInput) {
    if (!state.filters[field]) state.filters[field] = [];

    // Prevent duplicate
    if (state.filters[field].includes(value)) {
        textInput.value = '';
        return;
    }

    state.filters[field].push(value);
    textInput.value = '';

    // Insert pill before the text input
    const pill = createTagPill(field, value, tagWrap);
    tagWrap.insertBefore(pill, textInput);

    updateFilterCount();
}

function removeTag(field, value, tagWrap) {
    state.filters[field] = (state.filters[field] || []).filter(v => v !== value);
    if (state.filters[field].length === 0) delete state.filters[field];

    // Remove pill from DOM
    const pills = tagWrap.querySelectorAll('.tag-pill');
    for (const pill of pills) {
        if (pill.dataset.value === value) { pill.remove(); break; }
    }

    updateFilterCount();
}

function createTagPill(field, value, tagWrap) {
    const pill = document.createElement('span');
    pill.className   = 'tag-pill';
    pill.dataset.value = value;

    const text = document.createElement('span');
    text.textContent = value;

    const close = document.createElement('button');
    close.innerHTML = '×';
    close.title     = 'Remove';
    close.addEventListener('click', (e) => {
        e.stopPropagation();
        removeTag(field, value, tagWrap);
    });

    pill.appendChild(text);
    pill.appendChild(close);
    return pill;
}

function clearAllTags() {
    state.filters = {};
    // Clear all pills from DOM
    document.querySelectorAll('.tag-input-wrap').forEach(wrap => {
        wrap.querySelectorAll('.tag-pill').forEach(p => p.remove());
        const input = wrap.querySelector('.tag-text-input');
        if (input) input.value = '';
    });
    updateFilterCount();
}

function updateFilterCount() {
    const total = Object.values(state.filters).reduce((sum, arr) => sum + arr.length, 0);
    const badge = document.getElementById('filter-count');
    badge.textContent = total;
    badge.classList.toggle('hidden', total === 0);

    const btn = document.getElementById('btn-toggle-filters');
    btn.classList.toggle('active', total > 0);
}

function hasActiveFilters() {
    return Object.values(state.filters).some(arr => arr.length > 0);
}

// Mirror the backend filter logic on the frontend so live WS logs are filtered too.
// OR within a field's tags, AND between different fields.
// Numeric fields (status_code, bytes) use exact match; others use case-insensitive contains.
const NUMERIC_FILTER_FIELDS = new Set(['status_code', 'bytes', 'suspicious']);

function matchesFilters(log) {
    for (const [field, values] of Object.entries(state.filters)) {
        if (!values || values.length === 0) continue;

        const logValue = log[field];

        // Field missing from log → no match
        if (logValue == null) return false;

        const matchedAny = values.some((tag) => {
            if (NUMERIC_FILTER_FIELDS.has(field)) {
                return Number(logValue) === Number(tag);
            }
            // Case-insensitive contains (mirrors SQL LIKE %val%)
            return String(logValue).toLowerCase().includes(tag.toLowerCase());
        });

        if (!matchedAny) return false;
    }
    return true;
}

// ============================================================
// COLUMN SELECTOR
// ============================================================
function buildColumnSelector(fields) {
    const container = document.getElementById('column-checkboxes');
    container.innerHTML = '';

    const allCols = ['id', ...fields, 'raw'];
    for (const field of allCols) {
        const label    = document.createElement('label');
        const checkbox = document.createElement('input');
        checkbox.type    = 'checkbox';
        checkbox.value   = field;
        checkbox.checked = state.visibleColumns.has(field);

        checkbox.addEventListener('change', () => {
            if (checkbox.checked) state.visibleColumns.add(field);
            else                  state.visibleColumns.delete(field);
            if (state.mode === 'table') renderCurrentView();
        });

        label.appendChild(checkbox);
        label.append(` ${field}`);
        container.appendChild(label);
    }
}

// ============================================================
// PAGINATION
// ============================================================
function updatePagination() {
    const page  = Math.floor(state.offset / state.limit) + 1;
    const pages = Math.ceil(state.total / state.limit) || 1;
    document.getElementById('page-info').textContent =
        `Page ${page} of ${pages}  (${state.total.toLocaleString()} logs)`;
    document.getElementById('btn-prev').disabled = state.offset === 0;
    document.getElementById('btn-next').disabled = state.offset + state.limit >= state.total;
}

// ============================================================
// EVENTS
// ============================================================
function wireEvents() {
    // Mode
    document.getElementById('btn-raw').addEventListener('click',   () => switchMode('raw'));
    document.getElementById('btn-table').addEventListener('click', () => switchMode('table'));

    function switchMode(mode) {
        state.mode = mode;
        document.getElementById('btn-raw').classList.toggle('active',   mode === 'raw');
        document.getElementById('btn-table').classList.toggle('active', mode === 'table');
        document.getElementById('view-raw').classList.toggle('hidden',   mode !== 'raw');
        document.getElementById('view-table').classList.toggle('hidden', mode !== 'table');
        renderCurrentView();
    }

    // Panel toggles
    document.getElementById('btn-toggle-filters').addEventListener('click', () => {
        document.getElementById('filter-panel').classList.toggle('hidden');
    });
    document.getElementById('btn-toggle-columns').addEventListener('click', () => {
        document.getElementById('column-panel').classList.toggle('hidden');
    });

    // Apply filters — always reset to page 1, live updates stay on
    document.getElementById('btn-apply-filters').addEventListener('click', () => {
        state.offset = 0;
        fetchLogs();
    });

    // Clear all filters — reset to page 1
    document.getElementById('btn-clear-filters').addEventListener('click', () => {
        clearAllTags();
        state.offset = 0;
        fetchLogs();
    });

    // Pagination — live updates auto-pause when offset > 0 (handled in WS handler)
    document.getElementById('btn-prev').addEventListener('click', () => {
        if (state.offset === 0) return;
        state.offset = Math.max(0, state.offset - state.limit);
        fetchLogs();
    });
    document.getElementById('btn-next').addEventListener('click', () => {
        if (state.offset + state.limit >= state.total) return;
        state.offset += state.limit;
        fetchLogs();
    });
}

// ============================================================
// INIT
// ============================================================
(async function init() {
    wireEvents();
    await fetchFields();
    await fetchLogs();
    connectWebSocket();
})();
