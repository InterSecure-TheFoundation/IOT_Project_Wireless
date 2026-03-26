const { WebSocketServer, WebSocket } = require('ws');
const config = require('./config');

let wss;

function createWsServer() {
    wss = new WebSocketServer({ port: config.wsPort });

    wss.on('connection', (socket) => {
        console.log(`[WS] Client connected. Total: ${wss.clients.size}`);

        socket.on('close', () => {
            console.log(`[WS] Client disconnected. Total: ${wss.clients.size}`);
        });

        socket.on('error', (err) => {
            console.error('[WS] Socket error:', err.message);
        });
    });

    console.log(`[WS] Server listening on port ${config.wsPort}`);
    return wss;
}

function broadcast(data) {
    if (!wss) return;
    const message = JSON.stringify(data);
    for (const client of wss.clients) {
        if (client.readyState === WebSocket.OPEN) {
            client.send(message, (err) => {
                if (err) console.error('[WS] Send error:', err.message);
            });
        }
    }
}

module.exports = { createWsServer, broadcast };
