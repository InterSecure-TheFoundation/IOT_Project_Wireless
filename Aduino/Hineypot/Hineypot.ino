#include <M5Stack.h>
#include <WiFi.h>
#include <WebServer.h>
#include <PubSubClient.h>
#include <time.h>

const char* WIFI_SSID = "The foundation";
const char* WIFI_PASS = "Alpha12345";
const char* MQTT_BROKER = "10.30.84.56";
const uint16_t MQTT_PORT = 1883;
const char* MQTT_TOPIC = "honeypot/logs";
const char* MQTT_USER = "";
const char* MQTT_PASS = "";

const long GMT_OFFSET_SEC = 7 * 3600;   // Asia/Bangkok
const int DAYLIGHT_OFFSET_SEC = 0;

WebServer server(80);
WiFiClient wifiClient;
PubSubClient mqttClient(wifiClient);

const char* NTP_SERVER_1 = "pool.ntp.org";
const char* NTP_SERVER_2 = "time.google.com";

// ---------- Simple per-IP rate tracking ----------
struct IpStat {
  String ip;
  uint32_t count;
  unsigned long windowStart;
};

const int MAX_IPS = 20;
IpStat ipStats[MAX_IPS];

// ---------- Global counters ----------
volatile uint32_t totalRequests = 0;
String lastEvent = "Booting...";
String lastIP = "-";
String lastPath = "-";

// ---------- Fake pages ----------
const char LOGIN_PAGE[] PROGMEM = R"rawliteral(
<!doctype html>
<html>
<head>
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Device Login</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 40px; background:#f4f4f4; }
    .box { max-width: 320px; margin:auto; background:white; padding:20px; border-radius:12px; box-shadow:0 2px 10px rgba(0,0,0,.1); }
    input { width:100%; padding:10px; margin:8px 0; box-sizing:border-box; }
    button { width:100%; padding:10px; }
    .small { color:#777; font-size:12px; margin-top:10px; }
  </style>
</head>
<body>
  <div class="box">
    <h2>Embedded Device Login</h2>
    <form method="POST" action="/login">
      <input name="username" placeholder="Username">
      <input name="password" type="password" placeholder="Password">
      <button type="submit">Sign in</button>
    </form>
    <div class="small">Firmware Console</div>
  </div>
</body>
</html>
)rawliteral";

const char LOGIN_FAIL_PAGE[] PROGMEM = R"rawliteral(
<!doctype html>
<html>
<head>
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Device Login</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 40px; background:#f4f4f4; }
    .box { max-width: 320px; margin:auto; background:white; padding:20px; border-radius:12px; box-shadow:0 2px 10px rgba(0,0,0,.1); }
    input { width:100%; padding:10px; margin:8px 0; box-sizing:border-box; }
    button { width:100%; padding:10px; }
    .small { color:#777; font-size:12px; margin-top:10px; }
    .error { color:#c0392b; background:#fdecea; border:1px solid #e74c3c; padding:8px 10px; border-radius:6px; margin-bottom:10px; font-size:13px; }
  </style>
</head>
<body>
  <div class="box">
    <h2>Embedded Device Login</h2>
    <div class="error">Invalid credentials. Please try again.</div>
    <form method="POST" action="/login">
      <input name="username" placeholder="Username">
      <input name="password" type="password" placeholder="Password">
      <button type="submit">Sign in</button>
    </form>
    <div class="small">Firmware Console</div>
  </div>
</body>
</html>
)rawliteral";

const char FORBIDDEN_PAGE[] PROGMEM = "Forbidden";
const char NOT_FOUND_PAGE[] PROGMEM = "404 Not Found";

// ---------- Per-IP rate tracking ----------
int getIpIndex(const String& ip) {
  for (int i = 0; i < MAX_IPS; i++) {
    if (ipStats[i].ip == ip) return i;
  }
  for (int i = 0; i < MAX_IPS; i++) {
    if (ipStats[i].ip == "") {
      ipStats[i].ip = ip;
      ipStats[i].count = 0;
      ipStats[i].windowStart = millis();
      return i;
    }
  }
  return -1;
}

// Records request and emits a serial ALERT on rate bursts (>15 req / 10 s).
// Attack pattern detection is handled entirely by the backend analyzer.
void recordRequest(const String& ip) {
  int idx = getIpIndex(ip);
  if (idx < 0) return;

  unsigned long now = millis();
  if (now - ipStats[idx].windowStart > 10000) {
    ipStats[idx].count = 0;
    ipStats[idx].windowStart = now;
  }

  ipStats[idx].count++;

  if (ipStats[idx].count > 15) {
    Serial.printf("[ALERT] ip=%s rate burst > 15 req/10s\n", ip.c_str());
    ipStats[idx].count = 0;
    ipStats[idx].windowStart = now;
  }
}

// ---------- Display ----------
void drawStatus() {
  M5.Lcd.fillScreen(BLACK);
  M5.Lcd.setTextColor(GREEN, BLACK);
  M5.Lcd.setTextSize(2);
  M5.Lcd.setCursor(10, 10);
  M5.Lcd.println("M5 Honeypot");

  M5.Lcd.setTextSize(1);
  M5.Lcd.setCursor(10, 50);
  M5.Lcd.printf("IP: %s\n", WiFi.localIP().toString().c_str());
  M5.Lcd.printf("Requests: %lu\n", totalRequests);
  M5.Lcd.printf("Last IP: %s\n", lastIP.c_str());

  M5.Lcd.println("Last path:");
  M5.Lcd.println(lastPath);

  M5.Lcd.println("\nLast event:");
  M5.Lcd.println(lastEvent);
}

void logEvent(const String& level, const String& ip, const String& method, const String& uri, const String& detail) {
  Serial.printf("[%s] ip=%s method=%s uri=%s detail=%s\n",
                level.c_str(), ip.c_str(), method.c_str(), uri.c_str(), detail.c_str());
  lastIP = ip;
  lastPath = uri;
  lastEvent = level + ": " + detail;
  drawStatus();
}

// ---------- Timestamp / sanitize helpers ----------
String twoDigits(int value) {
  if (value < 10) return "0" + String(value);
  return String(value);
}

String monthShort(int monthIndex) {
  const char* months[] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun",
                          "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
  if (monthIndex < 0 || monthIndex > 11) return "Jan";
  return String(months[monthIndex]);
}

String formatLogTimestamp() {
  struct tm timeInfo;
  if (!getLocalTime(&timeInfo)) {
    return "01/Jan/1970:00:00:00 +0000";
  }
  return twoDigits(timeInfo.tm_mday) + "/" +
         monthShort(timeInfo.tm_mon) + "/" +
         String(timeInfo.tm_year + 1900) + ":" +
         twoDigits(timeInfo.tm_hour) + ":" +
         twoDigits(timeInfo.tm_min) + ":" +
         twoDigits(timeInfo.tm_sec) + " +0700";
}

String sanitizeLogField(String s) {
  s.replace("\"", "'");
  s.replace("\r", " ");
  s.replace("\n", " ");
  return s;
}

// ---------- MQTT ----------
void connectMqtt() {
  if (mqttClient.connected()) return;

  String clientId = "m5-honeypot-" + String((uint32_t)esp_random(), HEX);
  bool ok = (strlen(MQTT_USER) > 0)
    ? mqttClient.connect(clientId.c_str(), MQTT_USER, MQTT_PASS)
    : mqttClient.connect(clientId.c_str());

  if (ok) {
    Serial.printf("[MQTT] Connected to %s:%u\n", MQTT_BROKER, MQTT_PORT);
  } else {
    Serial.printf("[MQTT] Connect failed, rc=%d\n", mqttClient.state());
  }
}

// Publishes an Apache Combined Log Format line to MQTT.
// postBody is appended as body="..." for POST requests so the backend
// analyzer can inspect form field values (e.g. SQLi in username/password).
// Suspicious analysis is done entirely by the backend.
void publishAccessLog(const String& ip,
                      const String& method,
                      const String& uri,
                      int statusCode,
                      int responseBytes,
                      const String& postBody = "") {
  if (!mqttClient.connected()) connectMqtt();
  if (!mqttClient.connected()) return;

  String userAgent = server.hasHeader("User-Agent") ? server.header("User-Agent") : "-";
  String referrer  = server.hasHeader("Referer")    ? server.header("Referer")    : "-";

  String line = sanitizeLogField(ip) + " - - [" + formatLogTimestamp() + "] \"" +
                sanitizeLogField(method) + " " + sanitizeLogField(uri) +
                " HTTP/1.1\" " + String(statusCode) + " " + String(responseBytes) + " \"" +
                sanitizeLogField(referrer) + "\" \"" + sanitizeLogField(userAgent) + "\"";

  if (postBody.length() > 0) {
    line += " body=\"" + postBody + "\"";
  }

  if (!mqttClient.publish(MQTT_TOPIC, line.c_str(), false)) {
    Serial.println("[MQTT] Publish failed");
  }
}

// ---------- Request handlers ----------
void handleRoot() {
  String ip = server.client().remoteIP().toString();
  totalRequests++;
  logEvent("INFO", ip, "GET", server.uri(), "visit");
  recordRequest(ip);
  publishAccessLog(ip, "GET", server.uri(), 200, strlen(LOGIN_PAGE));
  server.send(200, "text/html", LOGIN_PAGE);
}

void handleLogin() {
  String ip   = server.client().remoteIP().toString();
  String user = server.hasArg("username") ? server.arg("username") : "";
  String pass = server.hasArg("password") ? server.arg("password") : "";
  totalRequests++;
  logEvent("INFO", ip, "POST", server.uri(),
           "login attempt user=" + user + " pass_len=" + String(pass.length()));
  recordRequest(ip);
  // Build sanitized body string so the backend analyzer can inspect field values
  String logBody = "username=" + sanitizeLogField(user) +
                   "&password=" + sanitizeLogField(pass);
  delay(800); // slight realism
  publishAccessLog(ip, "POST", server.uri(), 200, strlen(LOGIN_FAIL_PAGE), logBody);
  server.send(200, "text/html", LOGIN_FAIL_PAGE);
}

void handleNotFound() {
  String ip     = server.client().remoteIP().toString();
  String method = server.method() == HTTP_POST ? "POST" : "GET";
  String uri    = server.uri();
  totalRequests++;
  logEvent("WARN", ip, method, uri, "404 probe");
  recordRequest(ip);
  publishAccessLog(ip, method, uri, 404, strlen(NOT_FOUND_PAGE));
  server.send(404, "text/plain", NOT_FOUND_PAGE);
}

// ---------- WiFi / MQTT setup ----------
void connectWifi() {
  WiFi.mode(WIFI_STA);
  WiFi.begin(WIFI_SSID, WIFI_PASS);

  M5.Lcd.fillScreen(BLACK);
  M5.Lcd.setTextColor(WHITE, BLACK);
  M5.Lcd.setCursor(10, 10);
  M5.Lcd.setTextSize(2);
  M5.Lcd.println("Connecting WiFi...");

  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }
  Serial.println();
  Serial.print("Connected. IP: ");
  Serial.println(WiFi.localIP());

  configTime(GMT_OFFSET_SEC, DAYLIGHT_OFFSET_SEC, NTP_SERVER_1, NTP_SERVER_2);
}

void setupMqtt() {
  mqttClient.setBufferSize(1024);  // default 256 is too small for log lines with body field
  mqttClient.setServer(MQTT_BROKER, MQTT_PORT);
  connectMqtt();
}

// ---------- Arduino entry points ----------
void setup() {
  M5.begin();
  Serial.begin(115200);
  delay(200);

  connectWifi();
  setupMqtt();

  const char* headerKeys[] = {"User-Agent", "Referer"};
  server.collectHeaders(headerKeys, 2);

  server.on("/", HTTP_GET, handleRoot);
  server.on("/login", HTTP_POST, handleLogin);

  // Bait paths — backend analyzer will flag these as PROBE_CMS
  server.on("/admin", HTTP_GET, []() {
    String ip = server.client().remoteIP().toString();
    totalRequests++;
    logEvent("WARN", ip, "GET", "/admin", "bait path hit");
    recordRequest(ip);
    publishAccessLog(ip, "GET", "/admin", 403, strlen(FORBIDDEN_PAGE));
    server.send(403, "text/plain", FORBIDDEN_PAGE);
  });

  server.on("/phpmyadmin", HTTP_GET, []() {
    String ip = server.client().remoteIP().toString();
    totalRequests++;
    logEvent("WARN", ip, "GET", "/phpmyadmin", "bait path hit");
    recordRequest(ip);
    publishAccessLog(ip, "GET", "/phpmyadmin", 403, strlen(FORBIDDEN_PAGE));
    server.send(403, "text/plain", FORBIDDEN_PAGE);
  });

  server.onNotFound(handleNotFound);
  server.begin();

  lastEvent = "Server started";
  drawStatus();
  Serial.println("Honeypot server started.");
}

void loop() {
  M5.update();
  server.handleClient();

  if (!mqttClient.connected()) {
    static unsigned long lastRetry = 0;
    unsigned long now = millis();
    if (now - lastRetry > 5000) {
      lastRetry = now;
      connectMqtt();
    }
  }
  mqttClient.loop();

  // Button A: reset counters
  if (M5.BtnA.wasPressed()) {
    totalRequests = 0;
    for (int i = 0; i < MAX_IPS; i++) {
      ipStats[i].ip = "";
      ipStats[i].count = 0;
      ipStats[i].windowStart = 0;
    }
    lastEvent = "Counters cleared";
    drawStatus();
    Serial.println("[INFO] Counters cleared");
  }
}
