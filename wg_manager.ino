// wg_manager.ino
//
// Хранение конфигов WireGuard БЕЗ директорий (mkdir/opendir/openNextFile/exists
// не используются вовсе) — только open/read/write/close/remove, которые есть
// в любой реализации FS. Список конфигов ведётся в текстовом файле-манифесте.

#include <WiFi.h>
#include <WebServer.h>
#include <LittleFS.h>
#include <WireGuard-ESP32.h>

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

extern WebServer server;

void addLog(const String& msg);
String pageHead(bool refresh);
String pageFooter();

static WireGuard wg;
static bool wgRunning = false;
static IPAddress wgLocalIp;
static String wgDnsCfg;

static const char* WG_LIST_PATH = "/wg_list.txt";
static const char* WG_ACTIVE_PATH = "/wg_active.txt";

// ---- Пути к файлам конфигов (плоские, без подпапок) ----
static String wgConfigPath(const String& fname) {
  return "/wg_" + fname; // fname уже содержит ".conf", например "home.conf"
}

void wgStorageInit() {
  // Директории больше не нужны, функция оставлена для совместимости вызова.
}

// ---------------- Манифест списка конфигов ----------------

static String readManifestRaw() {
  File f = LittleFS.open(WG_LIST_PATH, "r");
  if (!f) {
    return "";
  }
  String s = f.readString();
  f.close();
  return s;
}

static void writeManifestRaw(const String& content) {
  File f = LittleFS.open(WG_LIST_PATH, "w");
  if (f) {
    f.print(content);
    f.close();
  }
}

static bool manifestContains(const String& fname) {
  String s = readManifestRaw();
  int start = 0;
  int len = s.length();

  while (start < len) {
    int nl = s.indexOf('\n', start);
    String line = (nl == -1) ? s.substring(start) : s.substring(start, nl);
    line.trim();

    if (line == fname) {
      return true;
    }

    if (nl == -1) break;
    start = nl + 1;
  }

  return false;
}

static void manifestAdd(const String& fname) {
  if (manifestContains(fname)) {
    return;
  }

  String s = readManifestRaw();
  if (s.length() > 0 && !s.endsWith("\n")) {
    s += "\n";
  }
  s += fname;
  s += "\n";
  writeManifestRaw(s);
}

static void manifestRemove(const String& fname) {
  String s = readManifestRaw();
  String result;
  int start = 0;
  int len = s.length();

  while (start < len) {
    int nl = s.indexOf('\n', start);
    String line = (nl == -1) ? s.substring(start) : s.substring(start, nl);
    line.trim();

    if (line.length() > 0 && line != fname) {
      result += line;
      result += "\n";
    }

    if (nl == -1) break;
    start = nl + 1;
  }

  writeManifestRaw(result);
}

// ---------------- Активный конфиг ----------------

String loadActiveConfigName() {
  File f = LittleFS.open(WG_ACTIVE_PATH, "r");

  if (!f) {
    return "";
  }

  String s = f.readString();
  f.close();
  s.trim();

  return s;
}

void setActiveConfigName(const String& name) {
  if (name.length() == 0) {
    LittleFS.remove(WG_ACTIVE_PATH); // безопасно, даже если файла нет
    return;
  }

  File f = LittleFS.open(WG_ACTIVE_PATH, "w");

  if (f) {
    f.print(name);
    f.close();
  }
}

String wgConfiguredName() {
  String n = loadActiveConfigName();

  if (n.endsWith(".conf")) {
    n = n.substring(0, n.length() - 5);
  }

  return n;
}

bool wgIsActive() {
  return wgRunning;
}

IPAddress wgGetLocalIP() {
  return wgLocalIp;
}

String wgGetDnsServer() {
  return wgDnsCfg;
}

// ---------------- Парсинг .conf ----------------

bool parseWgConfig(const String& content, WgConfig& out) {
  out.endpointPort = 51820;
  out.persistentKeepalive = 0;

  int section = 0;
  int start = 0;
  int len = content.length();

  while (start < len) {
    int nl = content.indexOf('\n', start);
    String line;

    if (nl == -1) {
      line = content.substring(start);
      start = len;
    } else {
      line = content.substring(start, nl);
      start = nl + 1;
    }

    line.trim();

    if (line.length() == 0 || line.startsWith("#") || line.startsWith(";")) {
      continue;
    }

    if (line.equalsIgnoreCase("[Interface]")) {
      section = 1;
      continue;
    }

    if (line.equalsIgnoreCase("[Peer]")) {
      section = 2;
      continue;
    }

    int eq = line.indexOf('=');

    if (eq < 0) {
      continue;
    }

    String key = line.substring(0, eq);
    key.trim();

    String val = line.substring(eq + 1);
    val.trim();

    if (section == 1) {
      if (key.equalsIgnoreCase("PrivateKey")) {
        out.privateKey = val;
      } else if (key.equalsIgnoreCase("Address")) {
        int comma = val.indexOf(',');
        out.address = (comma >= 0) ? val.substring(0, comma) : val;
        out.address.trim();
      } else if (key.equalsIgnoreCase("DNS")) {
        int comma = val.indexOf(',');
        out.dns = (comma >= 0) ? val.substring(0, comma) : val;
        out.dns.trim();
      }
    } else if (section == 2) {
      if (key.equalsIgnoreCase("PublicKey")) {
        out.peerPublicKey = val;
      } else if (key.equalsIgnoreCase("AllowedIPs")) {
        out.allowedIPs = val;
      } else if (key.equalsIgnoreCase("Endpoint")) {
        int c = val.lastIndexOf(':');

        if (c > 0) {
          out.endpointHost = val.substring(0, c);
          out.endpointPort = (uint16_t)val.substring(c + 1).toInt();
        } else {
          out.endpointHost = val;
        }
      } else if (key.equalsIgnoreCase("PersistentKeepalive")) {
        out.persistentKeepalive = val.toInt();
      }
    }
  }

  return out.privateKey.length() > 0 &&
         out.peerPublicKey.length() > 0 &&
         out.endpointHost.length() > 0 &&
         out.address.length() > 0;
}

void wgManagerBegin() {
  wgRunning = false;

  String active = loadActiveConfigName();

  if (active.length() == 0) {
    addLog("WG: disabled (no active config)");
    return;
  }

  String path = wgConfigPath(active);

  File f = LittleFS.open(path, "r");

  if (!f) {
    addLog("WG: cannot open " + active);
    return;
  }

  String content = f.readString();
  f.close();

  WgConfig cfg;

  if (!parseWgConfig(content, cfg)) {
    addLog("WG: parse error in " + active);
    return;
  }

  String ipOnly = cfg.address;
  int slash = ipOnly.indexOf('/');

  if (slash >= 0) {
    ipOnly = ipOnly.substring(0, slash);
  }

  IPAddress localIp;

  if (!localIp.fromString(ipOnly.c_str())) {
    addLog("WG: bad local address in " + active);
    return;
  }

  addLog("WG: starting tunnel " + active + " -> " + cfg.endpointHost + ":" + String(cfg.endpointPort));

  bool ok = wg.begin(
    localIp,
    cfg.privateKey.c_str(),
    cfg.endpointHost.c_str(),
    cfg.peerPublicKey.c_str(),
    cfg.endpointPort
  );

  if (ok) {
    wgRunning = true;
    wgLocalIp = localIp;
    wgDnsCfg = cfg.dns;
    addLog("WG: tunnel UP, local IP " + localIp.toString());
  } else {
    addLog("WG: begin() FAILED for " + active);
  }
}

static String sanitizeName(const String& in) {
  String safe;

  for (size_t i = 0; i < in.length(); i++) {
    char c = in[i];

    if (isalnum((unsigned char)c) || c == '_' || c == '-') {
      safe += c;
    }
  }

  if (safe.length() == 0) {
    safe = "config";
  }

  return safe;
}

void handleWgPage() {
  String page = pageHead(false);

  page += F("<h2>WireGuard configs</h2>");

  String active = loadActiveConfigName();
  String manifest = readManifestRaw();

  page += F("<form action='/wg/select' method='GET'>");

  bool any = false;
  int start = 0;
  int len = manifest.length();

  while (start < len) {
    int nl = manifest.indexOf('\n', start);
    String fname = (nl == -1) ? manifest.substring(start) : manifest.substring(start, nl);
    fname.trim();

    if (fname.length() > 0) {
      any = true;

      String disp = fname;
      if (disp.endsWith(".conf")) {
        disp = disp.substring(0, disp.length() - 5);
      }

      bool sel = (fname == active);

      page += F("<div class='cfg'><label><input type='radio' name='name' value='");
      page += fname;
      page += F("'");

      if (sel) {
        page += F(" checked");
      }

      page += F("> ");
      page += disp;

      if (sel) {
        page += F(" (active)");
      }

      page += F("</label> &nbsp; <a href='/wg/delete?name=");
      page += fname;
      page += F("'>[delete]</a></div>");
    }

    if (nl == -1) break;
    start = nl + 1;
  }

  if (!any) {
    page += F("<p>No saved configs.</p>");
  }

  page += F("<div class='cfg'><label><input type='radio' name='name' value=''");

  if (active.length() == 0) {
    page += F(" checked");
  }

  page += F("> Disable WireGuard</label></div>");
  page += F("<button type='submit'>Apply and reboot</button></form>");

  page += F("<h3>Add new config</h3>");
  page += F("<p>Paste standard WireGuard .conf content (wg-quick format).</p>");

  page += F("<form action='/wg/add' method='POST'>");
  page += F("<label>Config name</label>");
  page += F("<input name='cname' required placeholder='home'>");
  page += F("<label>Config content</label>");
  page += F("<textarea name='content' rows='12' placeholder='[Interface] PrivateKey=... Address=10.0.0.2/32 DNS=1.1.1.1 [Peer] PublicKey=... Endpoint=1.2.3.4:51820 AllowedIPs=0.0.0.0/0' required></textarea>");
  page += F("<button type='submit'>Save</button>");
  page += F("</form>");

  page += F("<p><a href='/'>Back</a></p>");

  page += pageFooter();

  server.send(200, "text/html", page);
}

void handleWgAdd() {
  if (!server.hasArg("cname") || !server.hasArg("content")) {
    server.send(400, "text/plain", "Missing fields");
    return;
  }

  String cname = server.arg("cname");
  String content = server.arg("content");

  cname.trim();

  if (cname.length() == 0) {
    server.send(400, "text/plain", "Empty name");
    return;
  }

  String safe = sanitizeName(cname);

  WgConfig test;

  if (!parseWgConfig(content, test)) {
    server.send(400, "text/plain", "Config parse error: check PrivateKey, Address, PublicKey, Endpoint");
    return;
  }

  String fname = safe + ".conf";
  String path = wgConfigPath(fname);

  File f = LittleFS.open(path, "w");

  if (!f) {
    server.send(500, "text/plain", "FS write error");
    return;
  }

  f.print(content);
  f.close();

  manifestAdd(fname);

  addLog("WG config saved: " + safe);

  String page = pageHead(false);

  page += F("<h2>Saved</h2>");
  page += F("<p>Config '");
  page += safe;
  page += F("' saved.</p>");

  page += F("<p><a href='/wg/select?name=");
  page += fname;
  page += F("'>Make active and reboot</a></p>");

  page += F("<p><a href='/wg'>Back</a></p>");

  page += pageFooter();

  server.send(200, "text/html", page);
}

void handleWgSelect() {
  String name;

  if (server.hasArg("name")) {
    name = server.arg("name");
  }

  if (name.length() == 0) {
    setActiveConfigName("");
    addLog("WG: disabled by user");
  } else {
    String path = wgConfigPath(name);

    File f = LittleFS.open(path, "r");

    if (!f) {
      server.send(404, "text/plain", "Config not found");
      return;
    }
    f.close();

    setActiveConfigName(name);
    addLog("WG: active set to " + name);
  }

  String page = pageHead(false);

  page += F("<h2>Applied</h2>");
  page += F("<p>Rebooting...</p>");

  page += pageFooter();

  server.send(200, "text/html", page);

  delay(1000);
  ESP.restart();
}

void handleWgDelete() {
  if (!server.hasArg("name")) {
    server.send(400, "text/plain", "No name");
    return;
  }

  String name = server.arg("name");
  String path = wgConfigPath(name);
  String active = loadActiveConfigName();

  bool wasActive = (active == name);

  bool removed = LittleFS.remove(path);
  if (removed) {
    addLog("WG config deleted: " + name);
  }

  manifestRemove(name);

  if (wasActive) {
    setActiveConfigName("");
    addLog("WG: disabled (active config removed)");
  }

  String page = pageHead(false);

  page += F("<h2>Deleted</h2>");

  if (wasActive) {
    page += F("<p>This was active config, rebooting...</p>");
    page += pageFooter();

    server.send(200, "text/html", page);

    delay(1000);
    ESP.restart();
  } else {
    page += F("<p><a href='/wg'>Back</a></p>");
    page += pageFooter();

    server.send(200, "text/html", page);
  }
}

void wgRegisterWebHandlers() {
  server.on("/wg", HTTP_GET, handleWgPage);
  server.on("/wg/add", HTTP_POST, handleWgAdd);
  server.on("/wg/select", HTTP_GET, handleWgSelect);
  server.on("/wg/delete", HTTP_GET, handleWgDelete);
}