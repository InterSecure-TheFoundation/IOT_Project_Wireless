const Database = require('better-sqlite3');
const config   = require('./config');

let db;

function getDb() {
    if (!db) {
        db = new Database(config.dbPath);
        db.pragma('journal_mode = WAL');
        db.pragma('synchronous = NORMAL');
        createSchema();
    }
    return db;
}

function createSchema() {
    db.exec(`
        CREATE TABLE IF NOT EXISTS logs (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            raw          TEXT NOT NULL,
            ip           TEXT,
            timestamp    TEXT,
            method       TEXT,
            path         TEXT,
            http_version TEXT,
            status_code  INTEGER,
            bytes        INTEGER,
            user_agent   TEXT,
            created_at   INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_logs_ip          ON logs(ip);
        CREATE INDEX IF NOT EXISTS idx_logs_status_code ON logs(status_code);
        CREATE INDEX IF NOT EXISTS idx_logs_method      ON logs(method);
        CREATE INDEX IF NOT EXISTS idx_logs_created_at  ON logs(created_at);
    `);
}

const ALLOWED_FILTERS = new Set([
    'ip', 'method', 'path', 'http_version', 'status_code', 'bytes', 'user_agent',
]);

const NUMERIC_FIELDS = new Set(['status_code', 'bytes']);

function insertLog(raw, parsed) {
    const stmt = getDb().prepare(`
        INSERT INTO logs (raw, ip, timestamp, method, path, http_version, status_code, bytes, user_agent, created_at)
        VALUES (@raw, @ip, @timestamp, @method, @path, @http_version, @status_code, @bytes, @user_agent, @created_at)
    `);
    return stmt.run({
        raw,
        ip:           parsed.ip           ?? null,
        timestamp:    parsed.timestamp    ?? null,
        method:       parsed.method       ?? null,
        path:         parsed.path         ?? null,
        http_version: parsed.http_version ?? null,
        status_code:  parsed.status_code  ?? null,
        bytes:        parsed.bytes        ?? null,
        user_agent:   parsed.user_agent   ?? null,
        created_at:   Date.now(),
    });
}

// filters: { field: 'val1,val2' }  → split into array → OR within field, AND between fields
function buildWhere(filters) {
    const conditions = [];
    const params     = {};

    for (const [field, rawValue] of Object.entries(filters)) {
        if (!ALLOWED_FILTERS.has(field) || !rawValue) continue;

        // Support comma-separated values: "GET,POST" → ['GET', 'POST']
        const values = String(rawValue).split(',').map(v => v.trim()).filter(Boolean);
        if (values.length === 0) continue;

        if (NUMERIC_FIELDS.has(field)) {
            // Exact match, OR between values → field IN (v0, v1, ...)
            const keys = values.map((_, i) => `@${field}_${i}`);
            conditions.push(`${field} IN (${keys.join(', ')})`);
            values.forEach((v, i) => { params[`${field}_${i}`] = Number(v); });
        } else {
            // LIKE match, OR between values → (field LIKE v0 OR field LIKE v1)
            const subConds = values.map((_, i) => `${field} LIKE @${field}_${i}`);
            conditions.push(`(${subConds.join(' OR ')})`);
            values.forEach((v, i) => { params[`${field}_${i}`] = `%${v}%`; });
        }
    }

    return {
        where: conditions.length ? `WHERE ${conditions.join(' AND ')}` : '',
        params,
    };
}

function queryLogs({ filters = {}, limit = 100, offset = 0 } = {}) {
    const { where, params } = buildWhere(filters);
    params.limit  = Math.min(limit, 500);
    params.offset = offset;
    return getDb().prepare(
        `SELECT * FROM logs ${where} ORDER BY created_at DESC LIMIT @limit OFFSET @offset`
    ).all(params);
}

function countLogs({ filters = {} } = {}) {
    const { where, params } = buildWhere(filters);
    return getDb().prepare(`SELECT COUNT(*) AS count FROM logs ${where}`).get(params).count;
}

module.exports = { getDb, insertLog, queryLogs, countLogs, ALLOWED_FILTERS };
