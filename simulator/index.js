const mqtt    = require('mqtt');
const path    = require('path');
const fs      = require('fs');

// Load config and mockup data — both relative to this file
const config  = JSON.parse(fs.readFileSync(path.join(__dirname, 'config.json'),          'utf8'));
const mockup  = JSON.parse(fs.readFileSync(path.join(__dirname, 'data', 'mockup.json'),  'utf8'));

const { createGenerator } = require('./generator');
const { generateLogLine } = createGenerator(mockup, config.simulation?.timezone || '+0000');

const { brokerUrl, topic, username, password, qos = 1 } = config.mqtt;
const { burstEveryMs = 3000, logsPerBurst = 3, delayBetweenLogsMs = 300 } = config.schedule;

console.log('===========================================');
console.log('  IoT Honeypot Simulator');
console.log('===========================================');
console.log(`  Broker   : ${brokerUrl}`);
console.log(`  Topic    : ${topic}`);
console.log(`  Burst    : ${logsPerBurst} log(s) every ${burstEveryMs}ms`);
console.log(`  Delay    : ${delayBetweenLogsMs}ms between logs in a burst`);
console.log('===========================================\n');

// MQTT connect
const clientOptions = { clientId: `simulator-${Date.now()}` };
if (username) { clientOptions.username = username; clientOptions.password = password; }

const client = mqtt.connect(brokerUrl, clientOptions);

client.on('connect', () => {
    console.log(`[MQTT] Connected to ${brokerUrl}\n`);

    // Send one burst immediately, then repeat
    sendBurst();
    setInterval(sendBurst, burstEveryMs);
});

client.on('error',     (err) => console.error('[MQTT] Error:', err.message));
client.on('reconnect', ()    => console.log('[MQTT] Reconnecting...'));
client.on('offline',   ()    => console.log('[MQTT] Offline'));

let burstCount = 0;

function sendBurst() {
    burstCount++;
    console.log(`--- Burst #${burstCount} (${logsPerBurst} log(s)) ---`);

    for (let i = 0; i < logsPerBurst; i++) {
        setTimeout(() => {
            const line = generateLogLine();
            client.publish(topic, line, { qos }, (err) => {
                if (err) {
                    console.error(`  [ERR] ${err.message}`);
                } else {
                    console.log(`  [OK]  ${line}`);
                }
            });
        }, i * delayBetweenLogsMs);
    }
}
