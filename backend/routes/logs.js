const express                          = require('express');
const { queryLogs, countLogs, ALLOWED_FILTERS } = require('../db');

const router = express.Router();

// GET /api/logs?ip=1.2.3.4&method=GET&status_code=200&limit=50&offset=0
router.get('/', (req, res) => {
    const { limit = '100', offset = '0', ...rawFilters } = req.query;

    // Whitelist filter fields — only pass known fields to the DB layer
    const filters = {};
    for (const field of ALLOWED_FILTERS) {
        if (rawFilters[field] != null && rawFilters[field] !== '') {
            filters[field] = rawFilters[field];
        }
    }

    const parsedLimit  = Math.min(parseInt(limit,  10) || 100, 500);
    const parsedOffset = parseInt(offset, 10) || 0;

    try {
        const logs  = queryLogs({ filters, limit: parsedLimit, offset: parsedOffset });
        const total = countLogs({ filters });
        res.json({ logs, total, limit: parsedLimit, offset: parsedOffset });
    } catch (err) {
        console.error('[API] Query error:', err);
        res.status(500).json({ error: 'Query failed' });
    }
});

// GET /api/logs/fields
// Returns the list of filterable fields so the frontend can build its UI dynamically.
// When ALLOWED_FILTERS in db.js is updated, this endpoint reflects the change automatically.
router.get('/fields', (req, res) => {
    res.json({ fields: [...ALLOWED_FILTERS] });
});

module.exports = router;
