const mqtt             = require('mqtt');
const config           = require('./config');
const { parseLogLine } = require('./log-parser');
const { insertLog }    = require('./db');
const { broadcast }    = require('./websocket-server');
const { analyze }      = require('./analyzer');

function startMqttSubscriber() {
    const clientOptions = {
        clientId: `honeypot-server-${Date.now()}`,
    };

    if (config.mqttUsername) {
        clientOptions.username = config.mqttUsername;
        clientOptions.password = config.mqttPassword;
    }

    const client = mqtt.connect(config.mqttBrokerUrl, clientOptions);

    client.on('connect', () => {
        console.log(`[MQTT] Connected to ${config.mqttBrokerUrl}`);
        client.subscribe(config.mqttTopic, { qos: 1 }, (err) => {
            if (err) console.error('[MQTT] Subscribe error:', err);
            else     console.log(`[MQTT] Subscribed to topic: ${config.mqttTopic}`);
        });
    });

    client.on('message', (topic, messageBuffer) => {
        const raw = messageBuffer.toString().trim();
        if (!raw) return;

        const parsed = parseLogLine(raw);

        if (!parsed) {
            // Store raw line even when unparseable — nothing is lost.
            console.warn('[MQTT] Could not parse log line:', raw.substring(0, 80));
            const info = insertLog(raw, {});
            broadcast({ type: 'log', data: { id: info.lastInsertRowid, raw, parsed: null, created_at: Date.now() } });
            return;
        }

        // All suspicious analysis is done by the backend analyzer
        const { suspicious, reasons } = analyze(parsed);

        parsed.suspicious = suspicious ? 1 : 0;
        parsed.sus_reason = reasons.length > 0 ? reasons.slice(0, 5).join('; ') : null;

        if (suspicious) {
            console.log(`[ANALYZER] SUSPICIOUS ip=${parsed.ip} path=${parsed.path} reasons=${parsed.sus_reason}`);
        }

        const info   = insertLog(raw, parsed);
        const record = { id: info.lastInsertRowid, raw, ...parsed, created_at: Date.now() };
        broadcast({ type: 'log', data: record });
    });

    client.on('error',     (err) => console.error('[MQTT] Error:', err.message));
    client.on('reconnect', ()    => console.log('[MQTT] Reconnecting...'));
    client.on('offline',   ()    => console.log('[MQTT] Offline'));
}

module.exports = { startMqttSubscriber };
