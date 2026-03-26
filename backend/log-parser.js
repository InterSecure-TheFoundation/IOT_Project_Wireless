// Apache Combined Log Format:
// IP - - [DD/Mon/YYYY:HH:MM:SS +ZZZZ] "METHOD /path HTTP/x.x" STATUS BYTES "referrer" "UA"
const LOG_REGEX = /^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+) (HTTP\/[\d.]+)" (\d{3}) (\d+|-) "([^"]*)" "([^"]*)"/;

function parseLogLine(raw) {
    const match = LOG_REGEX.exec(raw.trim());
    if (!match) return null;

    const [, ip, timestamp, method, path, http_version, status_code, bytes, , user_agent] = match;

    return {
        ip,
        timestamp,
        method,
        path,
        http_version,
        status_code: parseInt(status_code, 10),
        bytes:       bytes === '-' ? 0 : parseInt(bytes, 10),
        user_agent,
    };
}

// Canonical list of parsed fields — used by the filter and column systems.
// Add new field names here when extending the parser.
const PARSED_FIELDS = ['ip', 'timestamp', 'method', 'path', 'http_version', 'status_code', 'bytes', 'user_agent'];

module.exports = { parseLogLine, PARSED_FIELDS };
