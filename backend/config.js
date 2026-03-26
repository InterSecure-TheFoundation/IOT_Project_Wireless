require('dotenv').config();

module.exports = {
    mqttBrokerUrl: process.env.MQTT_BROKER_URL || 'mqtt://localhost:1883',
    mqttTopic:     process.env.MQTT_TOPIC      || 'honeypot/logs',
    mqttUsername:  process.env.MQTT_USERNAME   || '',
    mqttPassword:  process.env.MQTT_PASSWORD   || '',
    dbPath:        process.env.DB_PATH         || './data/logs.db',
    httpPort:      parseInt(process.env.HTTP_PORT || '3000'),
    wsPort:        parseInt(process.env.WS_PORT   || '3001'),
};
