// sketch_jul27a.ino

#include <M5StickCPlus2.h>
#include <SPI.h>
#include <Wire.h>
#include <WiFi.h>
#include <WiFiUdp.h>
#include <WebServer.h>
#include <DNSServer.h>
#include <Preferences.h>
#include <LittleFS.h>
#include <esp_system.h>
#include <stdint.h>

#if __has_include(<esp_idf_version.h>)
#include <esp_idf_version.h>
#endif

#ifndef ESP_IDF_VERSION_MAJOR
#define ESP_IDF_VERSION_MAJOR 5
#endif

extern "C" {
#include "lwip/err.h"
#include "lwip/lwip_napt.h"
}

// Некоторые сборки ESP32 core компилируют lwIP БЕЗ поддержки NAPT
// (CONFIG_LWIP_IPV4_NAPT не включён при сборке core). В таком случае
// символы объявлены в заголовке, но отсутствуют в скомпилированной
// библиотеке - линковщик выдаёт "undefined reference". Помечаем их как
// weak: если реализации нет, линковщик подставит нулевой адрес вместо
// ошибки, а мы проверим это в рантайме и просто отключим функционал NAPT.
//
// ВАЖНО: сигнатуры должны ТОЧНО совпадать с объявлением в lwip_napt.h,
// иначе компилятор выдаст "conflicting declaration". В IDF v5.5
// ip_napt_enable() возвращает void, а не err_t.
#pragma weak ip_napt_init
#pragma weak ip_napt_enable

extern "C" err_t ip_napt_init(uint16_t max_nat, uint16_t max_port);
extern "C" void ip_napt_enable(uint32_t addr, int enable);

#ifndef WG_CONFIG_DEFINED
#define WG_CONFIG_DEFINED
struct WgConfig {
  String privateKey;
  String address;
  String dns;
  String peerPublicKey;
  String endpointHost;
  uint16_t endpointPort;
  String allowedIPs;
  int persistentKeepalive;
};
#endif

// ---- Функции из wg_manager.ino ----
void wgStorageInit();
void wgManagerBegin();
void wgRegisterWebHandlers();
bool wgIsActive();
IPAddress wgGetLocalIP();
String wgGetDnsServer();
String wgConfiguredName();

const char* AP_SSID = "M5-Setup";
const char* AP_PASS = "m5setup123";

IPAddress AP_IP(192, 168, 4, 1);
IPAddress AP_GW(192, 168, 4, 1);
IPAddress AP_MASK(255, 255, 255, 0);

WebServer server(80);
DNSServer dns;
Preferences prefs;
Preferences safePrefs;

WiFiUDP dnsUdp;
WiFiUDP dnsUp;

const int MAX_LOG = 60;
String logLines[MAX_LOG];
int logCount = 0;

int lastWifiStatus = -1;
unsigned long lastScreen = 0;

bool captiveDns = false;
bool dnsProxy = false;
bool dnsWaiting = false;
unsigned long dnsWaitStart = 0;

IPAddress dnsClientIp;
uint16_t dnsClientPort = 0;
uint8_t dnsBuf[512];

bool naptEnabled = false;
IPAddress currentNaptIp;
bool naptSupported = false;   // есть ли вообще NAPT в этой сборке core

// ---- Safe-mode флаги ----
bool g_naptOff = false;               // NAPT принудительно отключён (безопасный режим)
bool wgStartAttempted = false;
bool bootMarkedStable = false;
const int MAX_BOOT_FAILS = 3;

void addLog(const String& msg) {
  Serial.println(msg);

  if (logCount < MAX_LOG) {
    logLines[logCount] = msg;
    logCount++;
  } else {
    for (int i = 0; i < MAX_LOG - 1; i++) {
      logLines[i] = logLines[i + 1];
    }
    logLines[MAX_LOG - 1] = msg;
  }
}

static void naptCompatInit() {
  if (g_naptOff) {
    addLog("NAPT init SKIPPED (safe mode)");
    return;
  }

  naptSupported = (ip_napt_init != nullptr) && (ip_napt_enable != nullptr);

  if (!naptSupported) {
    addLog("NAPT NOT AVAILABLE: this core's lwIP was built without NAPT support");
    addLog("Internet sharing (NAT) will NOT work. WiFi/WireGuard/DNS still OK.");
    return;
  }

  err_t r = ip_napt_init(64, 32);
  addLog("NAPT init result: " + String((int)r));
}

String resetReasonText() {
  esp_reset_reason_t r = esp_reset_reason();

  switch (r) {
    case ESP_RST_POWERON:   return "Power-on";
    case ESP_RST_EXT:       return "External reset";
    case ESP_RST_SW:        return "Software restart";
    case ESP_RST_PANIC:     return "PANIC / CRASH!";
    case ESP_RST_INT_WDT:   return "Interrupt watchdog";
    case ESP_RST_TASK_WDT:  return "Task watchdog";
    case ESP_RST_WDT:       return "Other watchdog";
    case ESP_RST_DEEPSLEEP: return "Deep sleep wake";
    case ESP_RST_BROWNOUT:  return "Brownout (power!)";
    case ESP_RST_SDIO:      return "SDIO reset";
    default:                return "Unknown (" + String((int)r) + ")";
  }
}

String wifiStatusText(int status) {
  switch (status) {
    case WL_IDLE_STATUS:      return "IDLE";
    case WL_NO_SSID_AVAIL:    return "NO_SSID";
    case WL_SCAN_COMPLETED:   return "SCAN_DONE";
    case WL_CONNECTED:        return "CONNECTED";
    case WL_CONNECT_FAILED:   return "CONNECT_FAIL";
    case WL_CONNECTION_LOST:  return "LOST";
    case WL_DISCONNECTED:     return "DISCONNECTED";
    default:                  return "CODE_" + String(status);
  }
}

String boolText(bool value) {
  return value ? "ON" : "OFF";
}

String pageHead(bool refresh) {
  String h;
  h.reserve(1024);

  h += F("<!DOCTYPE html><html><head>");
  h += F("<meta charset='utf-8'>");
  h += F("<meta name='viewport' content='width=device-width, initial-scale=1'>");

  if (refresh) {
    h += F("<meta http-equiv='refresh' content='5'>");
  }

  h += F("<title>M5 Router</title>");
  h += F("<style>");
  h += F("body{font-family:sans-serif;margin:20px;background:#0b0f14;color:#dfe7ee}");
  h += F(".box{max-width:680px;margin:auto}");
  h += F("a{display:inline-block;margin:8px 0;color:#7fd4ff}");
  h += F("input,textarea{width:100%;padding:10px;margin:8px 0;background:#121a22;color:#fff;border:1px solid #2a3947;border-radius:6px;box-sizing:border-box}");
  h += F("button{width:100%;padding:12px;background:#1f6feb;color:#fff;border:0;border-radius:6px;margin-top:6px}");
  h += F("pre{background:#05080c;color:#7CFC9A;padding:10px;overflow:auto;border-radius:6px;max-height:400px}");
  h += F("h2{margin-top:0}");
  h += F(".cfg{border:1px solid #2a3947;border-radius:6px;padding:8px;margin:6px 0}");
  h += F(".warn{color:#ff6b6b;font-weight:bold}");
  h += F("</style></head><body><div class='box'>");

  return h;
}

String pageFooter() {
  return F("</div></body></html>");
}

void drawScreen() {
  M5.Lcd.fillScreen(BLACK);
  M5.Lcd.setCursor(0, 0);
  M5.Lcd.setTextColor(WHITE, BLACK);
  M5.Lcd.setTextSize(1);

  M5.Lcd.println("M5 Router");
  M5.Lcd.println("AP: " + String(AP_SSID));
  M5.Lcd.println("Clients: " + String(WiFi.softAPgetStationNum()));

  if (WiFi.status() == WL_CONNECTED) {
    M5.Lcd.println("STA: " + WiFi.SSID());
    M5.Lcd.println("IP: " + WiFi.localIP().toString());
  } else {
    M5.Lcd.println("STA: " + wifiStatusText(WiFi.status()));
  }

  if (!naptSupported) {
    M5.Lcd.println("NAPT: UNSUPPORTED");
  } else {
    M5.Lcd.println("NAPT: " + boolText(naptEnabled) + (g_naptOff ? " [SAFE]" : ""));
  }

  M5.Lcd.println("WG: " + boolText(wgIsActive()) + " " + wgConfiguredName());

  if (dnsProxy) {
    M5.Lcd.println("DNS: PROXY");
  } else if (captiveDns) {
    M5.Lcd.println("DNS: CAPTIVE");
  } else {
    M5.Lcd.println("DNS: OFF");
  }

  M5.Lcd.println("---LOG---");

  int start = 0;
  if (logCount > 5) start = logCount - 5;

  for (int i = start; i < logCount; i++) {
    M5.Lcd.println(logLines[i]);
  }
}

void startCaptiveDns() {
  if (!captiveDns) {
    dns.start(53, "*", AP_IP);
    captiveDns = true;
    addLog("Captive DNS started");
  }
}

void stopCaptiveDns() {
  if (captiveDns) {
    dns.stop();
    captiveDns = false;
    addLog("Captive DNS stopped");
  }
}

void startDnsProxy() {
  if (!dnsProxy) {
    dnsUdp.begin(53);
    dnsUp.begin(1053);
    dnsProxy = true;
    dnsWaiting = false;
    addLog("DNS proxy started");
  }
}

void stopDnsProxy() {
  if (dnsProxy) {
    dnsUdp.stop();
    dnsUp.stop();
    dnsProxy = false;
    dnsWaiting = false;
    addLog("DNS proxy stopped");
  }
}

void handleDnsProxy() {
  if (!dnsProxy) return;

  if (!dnsWaiting) {
    int len = dnsUdp.parsePacket();

    if (len > 0) {
      int n = dnsUdp.read(dnsBuf, sizeof(dnsBuf));

      if (n > 0) {
        dnsClientIp = dnsUdp.remoteIP();
        dnsClientPort = dnsUdp.remotePort();

        IPAddress up;
        String wgDns;

        if (wgIsActive()) {
          wgDns = wgGetDnsServer();
        }

        if (wgDns.length() == 0 || !up.fromString(wgDns.c_str())) {
          up = WiFi.dnsIP();

          if (up == IPAddress(0, 0, 0, 0)) {
            up = WiFi.gatewayIP();
          }

          if (up == IPAddress(0, 0, 0, 0)) {
            up = IPAddress(1, 1, 1, 1);
          }
        }

        dnsUp.beginPacket(up, 53);
        dnsUp.write(dnsBuf, n);
        dnsUp.endPacket();

        dnsWaiting = true;
        dnsWaitStart = millis();
      }
    }
  } else {
    int r = dnsUp.parsePacket();

    if (r > 0) {
      uint8_t resp[512];
      int rn = dnsUp.read(resp, sizeof(resp));

      if (rn > 0) {
        dnsUdp.beginPacket(dnsClientIp, dnsClientPort);
        dnsUdp.write(resp, rn);
        dnsUdp.endPacket();
      }

      dnsWaiting = false;
    } else if (millis() - dnsWaitStart > 1500) {
      dnsWaiting = false;
    }
  }
}

void handleRoot() {
  String page = pageHead(true);

  page += F("<h2>M5 Router Status</h2>");

  page += F("<p><b>Last reset:</b> ");
  page += resetReasonText();
  page += F("</p>");

  if (g_naptOff) {
    page += F("<p class='warn'>SAFE MODE: NAPT отключён автоматически из-за повторных перезагрузок. ");
    page += F("<a href='/napt/enable'>Включить NAPT снова</a></p>");
  }

  if (!naptSupported) {
    page += F("<p class='warn'>NAPT недоступен: эта сборка ESP32 core скомпилирована без поддержки NAT ");
    page += F("(lwIP без CONFIG_LWIP_IPV4_NAPT). Раздача интернета работать не будет, ");
    page += F("но AP/Wi-Fi/WireGuard/DNS функционируют нормально.</p>");
  }

  if (WiFi.getMode() == WIFI_AP_STA) {
    page += F("<p><b>Mode:</b> AP+STA</p>");
  } else if (WiFi.getMode() == WIFI_AP) {
    page += F("<p><b>Mode:</b> AP only</p>");
  } else {
    page += F("<p><b>Mode:</b> ");
    page += String((int)WiFi.getMode());
    page += F("</p>");
  }

  page += F("<p><b>AP SSID:</b> ");
  page += AP_SSID;
  page += F("</p>");

  page += F("<p><b>AP IP:</b> 192.168.4.1</p>");

  page += F("<p><b>AP clients:</b> ");
  page += WiFi.softAPgetStationNum();
  page += F("</p>");

  page += F("<p><b>NAPT:</b> ");

  if (!naptSupported) {
    page += F("unsupported");
  } else {
    page += boolText(naptEnabled);

    if (naptEnabled) {
      page += F(" (");
      page += currentNaptIp.toString();
      page += F(")");
    }
  }

  page += F("</p>");

  String wgName = wgConfiguredName();

  page += F("<p><b>WireGuard:</b> ");
  page += boolText(wgIsActive());

  if (wgName.length() > 0) {
    page += F(" [");
    page += wgName;
    page += F("]");
  }

  page += F("</p>");

  if (dnsProxy) {
    page += F("<p><b>DNS:</b> proxy</p>");
  } else if (captiveDns) {
    page += F("<p><b>DNS:</b> captive</p>");
  } else {
    page += F("<p><b>DNS:</b> off</p>");
  }

  if (WiFi.status() == WL_CONNECTED) {
    page += F("<p><b>STA SSID:</b> ");
    page += WiFi.SSID();
    page += F("</p>");

    page += F("<p><b>STA IP:</b> ");
    page += WiFi.localIP().toString();
    page += F("</p>");

    page += F("<p><b>Gateway:</b> ");
    page += WiFi.gatewayIP().toString();
    page += F("</p>");

    page += F("<p><b>DNS:</b> ");
    page += WiFi.dnsIP().toString();
    page += F("</p>");
  } else {
    page += F("<p><b>STA status:</b> ");
    page += wifiStatusText(WiFi.status());
    page += F("</p>");
  }

  page += F("<h3>Logs</h3><pre>");

  for (int i = 0; i < logCount; i++) {
    page += logLines[i];
    page += F("\n");
  }

  page += F("</pre>");

  page += F("<p><a href='/wifi'>Wi-Fi setup</a></p>");
  page += F("<p><a href='/wg'>WireGuard setup</a></p>");
  page += F("<p><a href='/reset'>Reset Wi-Fi config</a></p>");
  page += F("<p><a href='/reboot'>Reboot device</a></p>");

  page += pageFooter();

  server.send(200, "text/html", page);
}

void handleWifi() {
  String page = pageHead(false);

  page += F("<h2>Wi-Fi Setup</h2>");
  page += F("<form action='/save' method='GET'>");
  page += F("<label>Wi-Fi SSID</label>");
  page += F("<input name='ssid' required>");
  page += F("<label>Wi-Fi Password</label>");
  page += F("<input name='pass' type='password'>");
  page += F("<button type='submit'>Save & Reboot</button>");
  page += F("</form>");
  page += F("<p><a href='/'>Back</a></p>");

  page += pageFooter();

  server.send(200, "text/html", page);
}

void handleSave() {
  if (!server.hasArg("ssid")) {
    server.send(400, "text/plain", "No SSID");
    return;
  }

  String ssid = server.arg("ssid");
  String pass = server.arg("pass");

  prefs.begin("cfg", false);
  prefs.putString("ssid", ssid);
  prefs.putString("pass", pass);
  prefs.end();

  String page = pageHead(false);

  page += F("<h2>Saved</h2>");
  page += F("<p>Rebooting and connecting to:</p>");
  page += F("<p><b>");
  page += ssid;
  page += F("</b></p>");

  page += pageFooter();

  server.send(200, "text/html", page);

  delay(1500);
  ESP.restart();
}

void handleReset() {
  prefs.begin("cfg", false);
  prefs.clear();
  prefs.end();

  String page = pageHead(false);

  page += F("<h2>Config cleared</h2>");
  page += F("<p>Rebooting...</p>");

  page += pageFooter();

  server.send(200, "text/html", page);

  delay(1000);
  ESP.restart();
}

void handleReboot() {
  String page = pageHead(false);

  page += F("<h2>Rebooting...</h2>");

  page += pageFooter();

  server.send(200, "text/html", page);

  delay(800);
  ESP.restart();
}

void handleNaptEnable() {
  safePrefs.begin("safe", false);
  safePrefs.putBool("naptOff", false);
  safePrefs.putInt("fails", 0);
  safePrefs.end();

  String page = pageHead(false);

  page += F("<h2>NAPT re-enabled</h2>");
  page += F("<p>Rebooting...</p>");

  page += pageFooter();

  server.send(200, "text/html", page);

  delay(1000);
  ESP.restart();
}

void startWebServer() {
  server.on("/", handleRoot);
  server.on("/wifi", handleWifi);
  server.on("/save", handleSave);
  server.on("/reset", handleReset);
  server.on("/reboot", handleReboot);
  server.on("/napt/enable", handleNaptEnable);

  wgRegisterWebHandlers();

  server.onNotFound([]() {
    server.sendHeader("Location", "/", true);
    server.send(302, "text/plain", "");
  });

  server.begin();
}

void setup() {
  Serial.begin(115200);

  M5.begin();
  M5.Lcd.setRotation(1);
  M5.Lcd.fillScreen(BLACK);
  M5.Lcd.setTextColor(WHITE, BLACK);
  M5.Lcd.setTextSize(1);

  addLog("Boot OK");
  addLog("Reset reason: " + resetReasonText());

  // ---- Монтируем ФС один раз ----
  bool fsOK = LittleFS.begin(true);

  if (!fsOK) {
    addLog("LittleFS mount FAILED");
  } else {
    addLog("LittleFS OK");
    wgStorageInit();
  }

  // ---- Защита от бесконечного цикла падений ----
  safePrefs.begin("safe", false);
  int bootFails = safePrefs.getInt("fails", 0);
  bootFails++;
  safePrefs.putInt("fails", bootFails);
  bool naptDisabledFlag = safePrefs.getBool("naptOff", false);
  safePrefs.end();

  addLog("Boot attempt #" + String(bootFails));

  bool forceWgOff = false;

  if (bootFails >= MAX_BOOT_FAILS) {
    addLog("!!! Too many failed boots - entering SAFE MODE (WireGuard + NAPT disabled) !!!");

    forceWgOff = true;
    naptDisabledFlag = true;

    safePrefs.begin("safe", false);
    safePrefs.putInt("fails", 0);
    safePrefs.putBool("naptOff", true);
    safePrefs.end();
  }

  g_naptOff = naptDisabledFlag;

  if (g_naptOff) {
    addLog("NAPT is DISABLED (safe mode). Visit /napt/enable to re-enable.");
  }

  if (forceWgOff && fsOK) {
    // Файл может не существовать - remove() в этом случае просто ничего не делает
    LittleFS.remove("/wg_active.txt");
    addLog("WG active config cleared (safe mode)");
  }

  prefs.begin("cfg", false);
  String ssid = prefs.getString("ssid", "");
  String pass = prefs.getString("pass", "");
  prefs.end();

  WiFi.persistent(false);
  WiFi.setSleep(false);

  if (ssid.length() > 0) {
    WiFi.mode(WIFI_AP_STA);
    WiFi.softAPConfig(AP_IP, AP_GW, AP_MASK);
    WiFi.softAP(AP_SSID, AP_PASS);

    addLog("AP+STA started");
    addLog("Connecting STA: " + ssid);

    WiFi.begin(ssid.c_str(), pass.c_str());
  } else {
    WiFi.mode(WIFI_AP);
    WiFi.softAPConfig(AP_IP, AP_GW, AP_MASK);
    WiFi.softAP(AP_SSID, AP_PASS);

    addLog("No saved WiFi");
    addLog("AP only started");

    wgStartAttempted = true;
  }

  naptCompatInit();

  startCaptiveDns();
  startWebServer();

  addLog("HTTP started");
  addLog("WG will start after STA connects (if configured)");
}

void loop() {
  server.handleClient();

  int st = WiFi.status();

  if (st != lastWifiStatus) {
    addLog("WiFi state: " + wifiStatusText(st));

    if (st == WL_CONNECTED) {
      addLog("IP: " + WiFi.localIP().toString());
    }

    lastWifiStatus = st;
  }

  if (!wgStartAttempted && st == WL_CONNECTED) {
    wgStartAttempted = true;
    addLog("STA connected, starting WireGuard manager...");
    wgManagerBegin();
  }

  bool wgUp = wgIsActive();

  if (st == WL_CONNECTED) {
    if (!g_naptOff && naptSupported) {
      IPAddress natIp = wgUp ? wgGetLocalIP() : WiFi.localIP();

      if (!naptEnabled || natIp != currentNaptIp) {
        if (naptEnabled) {
          ip_napt_enable(currentNaptIp, 0);
        }

        ip_napt_enable(natIp, 1);
        currentNaptIp = natIp;
        naptEnabled = true;

        addLog(String("NAPT enabled on ") + (wgUp ? "WG " : "STA ") + natIp.toString());
      }
    } else if (naptEnabled && naptSupported) {
      ip_napt_enable(currentNaptIp, 0);
      naptEnabled = false;
      addLog("NAPT disabled (safe mode)");
    }

    stopCaptiveDns();
    startDnsProxy();
    handleDnsProxy();
  } else {
    if (naptEnabled && naptSupported) {
      ip_napt_enable(currentNaptIp, 0);
      naptEnabled = false;
      addLog("NAPT disabled");
    }

    stopDnsProxy();
    startCaptiveDns();
    dns.processNextRequest();
  }

  if (!bootMarkedStable && millis() > 20000) {
    bootMarkedStable = true;

    safePrefs.begin("safe", false);
    safePrefs.putInt("fails", 0);
    safePrefs.end();

    addLog("Boot considered stable, fail counter reset");
  }

  if (millis() - lastScreen > 1000) {
    lastScreen = millis();
    drawScreen();
  }
}