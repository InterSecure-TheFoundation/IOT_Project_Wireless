const express  = require('express');
const path     = require('path');
const config   = require('./config');

const { getDb }               = require('./db');
const { createWsServer }      = require('./websocket-server');
const { startMqttSubscriber } = require('./mqtt-subscriber');
const logsRouter              = require('./routes/logs');

// 1. Initialize database — creates schema if not already present
getDb();

// 2. Start WebSocket server
createWsServer();

// 3. Start MQTT subscriber — connects to broker and begins processing incoming logs
startMqttSubscriber();

// 4. Start Express HTTP server
const app = express();
app.use(express.json());

// Serve frontend static files
app.use(express.static(path.join(__dirname, '../frontend')));

// REST API
app.use('/api/logs', logsRouter);

// Catch-all: serve index.html (supports future client-side routing if needed)
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, '../frontend/index.html'));
});

app.listen(config.httpPort, () => {
    console.log(`[HTTP] Server running on http://localhost:${config.httpPort}`);
});
