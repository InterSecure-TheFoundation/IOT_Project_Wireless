const MONTHS = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];

// Pick a random item from a weighted array: [{ value, weight }, ...]
function weightedRandom(items) {
    const total = items.reduce((sum, item) => sum + item.weight, 0);
    let rand    = Math.random() * total;
    for (const item of items) {
        rand -= item.weight;
        if (rand <= 0) return item.value;
    }
    return items[items.length - 1].value;
}

// Pick a random element from a plain array
function randomFrom(arr) {
    return arr[Math.floor(Math.random() * arr.length)];
}

// Random integer between min and max (inclusive)
function randomInt(min, max) {
    return Math.floor(Math.random() * (max - min + 1)) + min;
}

// Format Date to Apache Combined Log timestamp: 20/Mar/2026:14:23:01 +0000
function formatTimestamp(date, timezone = '+0000') {
    const dd  = String(date.getUTCDate()).padStart(2, '0');
    const mon = MONTHS[date.getUTCMonth()];
    const yyyy = date.getUTCFullYear();
    const hh  = String(date.getUTCHours()).padStart(2, '0');
    const mm  = String(date.getUTCMinutes()).padStart(2, '0');
    const ss  = String(date.getUTCSeconds()).padStart(2, '0');
    return `${dd}/${mon}/${yyyy}:${hh}:${mm}:${ss} ${timezone}`;
}

// Build the generator with a reference to the mockup data
function createGenerator(mockup, timezone = '+0000') {
    function generateLogLine() {
        const ip          = randomFrom(mockup.ips);
        const timestamp   = formatTimestamp(new Date(), timezone);
        const method      = weightedRandom(mockup.methods);
        const path        = randomFrom(mockup.paths);
        const httpVersion = weightedRandom(mockup.httpVersions);
        const statusCode  = weightedRandom(mockup.statusCodes);
        const bytes       = randomInt(mockup.bytesRange.min, mockup.bytesRange.max);
        const referrer    = randomFrom(mockup.referrers);
        const userAgent   = randomFrom(mockup.userAgents);

        // Apache Combined Log Format:
        // IP - - [timestamp] "METHOD /path HTTP/x.x" STATUS BYTES "referrer" "UA"
        return `${ip} - - [${timestamp}] "${method} ${path} ${httpVersion}" ${statusCode} ${bytes} "${referrer}" "${userAgent}"`;
    }

    return { generateLogLine };
}

module.exports = { createGenerator };
