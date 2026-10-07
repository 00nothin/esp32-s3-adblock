// S3 AdBlock — DNS sinkhole + TFT dashboard for ESP32-S3 N16R8.
// Blocklist = sorted 40-bit FNV-1a hashes in flash, binary-searched.
// Dashboard at http://s3adblock.local : per-client stats, system info,
// ban clients, add custom block domains. All control state persisted to flash.

#include <Arduino.h>
#include <WiFi.h>
#include <WiFiUdp.h>
#include <LittleFS.h>
#include <ESPmDNS.h>
#include <WebServer.h>
#include <Update.h>            // firmware OTA
#include <HTTPClient.h>        // remote blocklist fetch
#include <WiFiClientSecure.h>  // https fetch
#include <ArduinoOTA.h>        // network firmware flashing (pio run over wifi)
#include <DNSServer.h>         // captive-portal catch-all DNS
#include <Preferences.h>       // NVS store for provisioned WiFi creds

#ifndef DISPLAY_ENABLED
#define DISPLAY_ENABLED 0
#endif
#ifndef DISPLAY_TFT
#define DISPLAY_TFT 0
#endif
#ifndef BLOCKLIST_PSRAM
#define BLOCKLIST_PSRAM 0
#endif
#if BLOCKLIST_PSRAM
#include "esp_heap_caps.h"
#endif
#ifndef HOTSPOT_ENABLED
#define HOTSPOT_ENABLED 0
#endif
#ifndef DISPLAY_SDA
#define DISPLAY_SDA 5
#endif
#ifndef DISPLAY_SCL
#define DISPLAY_SCL 6
#endif
#ifndef DISPLAY_I2C_ADDR
#define DISPLAY_I2C_ADDR 0x3C
#endif
#ifndef DISPLAY_WIDTH
#define DISPLAY_WIDTH 128
#endif
#ifndef DISPLAY_HEIGHT
#define DISPLAY_HEIGHT 64
#endif
#ifndef SH1106
#define SH1106 1
#endif
#ifndef SSD1306
#define SSD1306 2
#endif
#ifndef DISPLAY_CONTROLLER
#define DISPLAY_CONTROLLER SH1106
#endif

#if DISPLAY_ENABLED && !DISPLAY_TFT
#include <Wire.h>
#include <U8g2lib.h>
#endif
#if HOTSPOT_ENABLED
#include "sdkconfig.h"
#include "esp_netif.h"
#include "esp_netif_net_stack.h"
#include "lwip/err.h"
#include "lwip/ip4_addr.h"
#include "lwip/lwip_napt.h"
#include "lwip/pbuf.h"
#include "lwip/netif.h"
#include "freertos/FreeRTOS.h"
#if !CONFIG_LWIP_IP_FORWARD || !CONFIG_LWIP_IPV4_NAPT
#error "The hotspot environment requires lwIP forwarding and IPv4 NAPT in sdkconfig."
#endif
#endif
#include "lwip/etharp.h"
#include "lwip/netif.h"
#include "secrets.h"   // WIFI_SSID / WIFI_PASS — used only as a FALLBACK if no creds
                       // have been provisioned via the captive portal (copy secrets.example.h)

// ---- config ----
#ifndef UPSTREAM_IP
#define UPSTREAM_IP 9, 9, 9, 9                    // Quad9
#endif
#ifndef UPSTREAM_PORT
#define UPSTREAM_PORT 53
#endif
static const IPAddress UPSTREAM(UPSTREAM_IP);
static const uint16_t DNS_PORT = 53;
static const char* BLOCKLIST_PATH = "/blocklist.bin";
static const int HASH_BYTES = 5;
static const uint64_t HASH_MASK = (1ULL << (HASH_BYTES * 8)) - 1;
static const int INDEX_ENTRIES = 4096;   // 20 KB first-level flash index
static const int CACHE_SIZE = 2048;      // must be power of 2
static const int MAX_RANGE = 256;        // max hashes per index bucket (fine up to ~1M hashes; flash holds far fewer)

// ---- globals ----
WiFiUDP dnsServer, upstreamCli;
WebServer web(80);
File blocklist;
uint32_t numHashes = 0, totalBlocked = 0, totalAllowed = 0;
uint8_t buf[1536];   // fits any non-fragmented UDP reply (EDNS answers can exceed 512)

// first-level flash index (sorted sample hashes) + small direct-mapped cache
static uint8_t blIndex[INDEX_ENTRIES][HASH_BYTES];
static uint8_t cacheKey[CACHE_SIZE][HASH_BYTES];
static uint8_t cacheRes[CACHE_SIZE];
static uint8_t cacheValid[CACHE_SIZE];
static uint8_t rangeBuf[MAX_RANGE * HASH_BYTES];
#if BLOCKLIST_PSRAM
static uint8_t* blocklistRam = nullptr;
#endif

struct Dev { uint32_t ip; uint8_t mac[6]; uint32_t blocked, allowed, lastSeen; bool banned; String label; };
static const int MAX_CLIENTS = 96;
Dev clients[MAX_CLIENTS]; int numClients = 0;

static const int MAX_CUSTOM = 200;
String customDom[MAX_CUSTOM]; uint64_t customHash[MAX_CUSTOM]; int numCustom = 0;

static const int MAX_BAN = 32;
uint32_t bannedIP[MAX_BAN]; int numBanned = 0;

#if CONFIG_IDF_TARGET_ESP32C3
static const int BOOT_PIN = 9;
#else
static const int BOOT_PIN = 0;
#endif

// remote blocklist auto-update
String updateUrl = "";              // URL of a prebuilt blocklist.bin (e.g. GitHub release asset)
uint32_t updateIntervalH = 24;      // hours between auto-fetches
uint32_t lastCheckMs = 0;
String updateStatus = "never";

// WiFi provisioning (captive portal)
Preferences prefs;
DNSServer   dnsPortal;
String      portalOpts;             // <option> list of scanned networks, built once at portal start
static const int MAX_WIFI_NETWORKS = 5;
struct WifiCredentials { String ssid; String pass; };
static WifiCredentials wifiNetworks[MAX_WIFI_NETWORKS];
static int numWifiNetworks = 0;
static int activeWifiNetwork = -1;
static uint32_t lastWifiAttemptMs = 0;
String      portalSSIDs[MAX_WIFI_NETWORKS];
String      portalError;
static volatile uint8_t lastWifiDisconnectReason = 0;

// blocking pause (Pi-hole-style "disable for a while")
bool     blockingOn = true;
uint32_t resumeAt   = 0;            // millis() to auto-resume; 0 = paused indefinitely / not paused
static bool showTrafficScreen = false;
static bool bootButtonPressed = false;
static bool bootButtonRaw = false;
static uint32_t bootButtonChangedAt = 0;

#if HOTSPOT_ENABLED
static portMUX_TYPE hotspotTrafficMux = portMUX_INITIALIZER_UNLOCKED;
static uint64_t hotspotBytesIn = 0;
static uint64_t hotspotBytesOut = 0;
static netif_input_fn hotspotInputOriginal = nullptr;
static netif_linkoutput_fn hotspotOutputOriginal = nullptr;

static err_t countHotspotInput(struct pbuf* packet, struct netif* interface) {
  if (packet) {
    portENTER_CRITICAL(&hotspotTrafficMux);
    hotspotBytesIn += packet->tot_len;
    portEXIT_CRITICAL(&hotspotTrafficMux);
  }
  return hotspotInputOriginal(packet, interface);
}

static err_t countHotspotOutput(struct netif* interface, struct pbuf* packet) {
  if (packet) {
    portENTER_CRITICAL(&hotspotTrafficMux);
    hotspotBytesOut += packet->tot_len;
    portEXIT_CRITICAL(&hotspotTrafficMux);
  }
  return hotspotOutputOriginal(interface, packet);
}

static bool monitorHotspotTraffic(esp_netif_t* apNetif) {
  struct netif* interface = static_cast<struct netif*>(esp_netif_get_netif_impl(apNetif));
  if (!interface || !interface->input || !interface->linkoutput) {
    Serial.println("[hotspot] unable to attach traffic counters to AP interface");
    return false;
  }
  hotspotInputOriginal = interface->input;
  hotspotOutputOriginal = interface->linkoutput;
  interface->input = countHotspotInput;
  interface->linkoutput = countHotspotOutput;
  return true;
}

static void getHotspotTraffic(uint64_t& bytesIn, uint64_t& bytesOut) {
  portENTER_CRITICAL(&hotspotTrafficMux);
  bytesIn = hotspotBytesIn;
  bytesOut = hotspotBytesOut;
  portEXIT_CRITICAL(&hotspotTrafficMux);
}
#endif

static void initializeBootButton() {
  pinMode(BOOT_PIN, INPUT_PULLUP);
  bootButtonRaw = digitalRead(BOOT_PIN) == LOW;
  bootButtonPressed = bootButtonRaw;
  bootButtonChangedAt = millis();
}

static void handleBootButton() {
  const uint32_t now = millis();
  const bool rawPressed = digitalRead(BOOT_PIN) == LOW;
  if (rawPressed != bootButtonRaw) {
    bootButtonRaw = rawPressed;
    bootButtonChangedAt = now;
  }
  if (now - bootButtonChangedAt >= 40 && rawPressed != bootButtonPressed) {
    bootButtonPressed = rawPressed;
    if (bootButtonPressed) showTrafficScreen = !showTrafficScreen;
  }
}

// ---------- hashing / matching ----------
static uint64_t fnv40(const char* s, size_t n) {
  uint64_t h = 0xcbf29ce484222325ULL;
  for (size_t i = 0; i < n; i++) { h ^= (uint8_t)s[i]; h *= 0x100000001b3ULL; }
  return h & HASH_MASK;
}
static inline uint64_t unpackHash(const uint8_t* b) {
  uint64_t v = 0;
  for (int k = 0; k < HASH_BYTES; k++) v |= (uint64_t)b[k] << (8 * k);
  return v;
}
static inline void packHash(uint64_t h, uint8_t* b) {
  for (int k = 0; k < HASH_BYTES; k++) { b[k] = (uint8_t)h; h >>= 8; }
}

static void buildFlashIndex() {
  memset(cacheValid, 0, sizeof(cacheValid));
#if BLOCKLIST_PSRAM
  free(blocklistRam);
  blocklistRam = nullptr;
#endif
  if (!blocklist || numHashes == 0) return;
#if BLOCKLIST_PSRAM
  const size_t bytes = (size_t)numHashes * HASH_BYTES;
  // Reserve external RAM for other allocations; never put the list in
  // internal RAM. Lists too large for PSRAM retain the flash backend.
  const uint32_t caps = MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT;
  if (psramFound() && heap_caps_get_free_size(caps) > bytes + 512 * 1024) {
    blocklistRam = static_cast<uint8_t*>(heap_caps_malloc(bytes, caps));
    if (blocklistRam) {
      blocklist.seek(0);
      size_t loaded = 0;
      while (loaded < bytes) {
        size_t chunk = bytes - loaded;
        if (chunk > 16384) chunk = 16384;
        const size_t got = blocklist.read(blocklistRam + loaded, chunk);
        if (got != chunk) break;
        loaded += got;
        delay(1);
      }
      if (loaded == bytes) {
        Serial.printf("[blocklist] %u hashes cached in PSRAM (%u bytes)\n", numHashes, (unsigned)bytes);
        return;
      }
      free(blocklistRam);
      blocklistRam = nullptr;
    }
  }
  Serial.println("[blocklist] using indexed flash lookup");
#endif
  for (int i = 0; i < INDEX_ENTRIES; i++) {
    uint32_t pos = (uint32_t)((uint64_t)i * (numHashes - 1) / (INDEX_ENTRIES - 1));
    blocklist.seek((uint32_t)pos * HASH_BYTES);
    blocklist.read(blIndex[i], HASH_BYTES);
  }
  for (int i = 0; i < CACHE_SIZE; i++) cacheValid[i] = 0;
}

static bool inFlash(uint64_t h) {
  if (numHashes == 0) return false;
#if BLOCKLIST_PSRAM
  if (blocklistRam) {
    uint32_t lo = 0, hi = numHashes;
    while (lo < hi) {
      const uint32_t mid = lo + (hi - lo) / 2;
      const uint64_t value = unpackHash(blocklistRam + (size_t)mid * HASH_BYTES);
      if (value == h) return true;
      if (value < h) lo = mid + 1;
      else hi = mid;
    }
    return false;
  }
#endif
  uint64_t first = unpackHash(blIndex[0]);
  uint64_t last  = unpackHash(blIndex[INDEX_ENTRIES - 1]);
  if (h < first || h > last) return false;

  int lo = 0, hi = INDEX_ENTRIES - 2, seg = 0;
  while (lo <= hi) {
    int mid = (lo + hi) >> 1;
    uint64_t midv = unpackHash(blIndex[mid]);
    if (midv < h) {
      seg = mid;
      lo = mid + 1;
    } else if (midv > h) {
      hi = mid - 1;
    } else {
      return true;
    }
  }

  uint32_t startPos = (uint32_t)((uint64_t)seg * (numHashes - 1) / (INDEX_ENTRIES - 1));
  uint32_t endPos   = (uint32_t)((uint64_t)(seg + 1) * (numHashes - 1) / (INDEX_ENTRIES - 1));
  if (endPos >= numHashes) endPos = numHashes - 1;
  uint32_t rangeCount = endPos - startPos + 1;
  // Large flash partitions can hold buckets larger than rangeBuf. Search
  // the entire interval instead of silently dropping its last entries.
  if (rangeCount > (uint32_t)MAX_RANGE) {
    uint32_t low = startPos, high = endPos + 1;
    uint8_t packed[HASH_BYTES];
    while (low < high) {
      const uint32_t mid = low + (high - low) / 2;
      if (!blocklist.seek(mid * HASH_BYTES) || blocklist.read(packed, HASH_BYTES) != HASH_BYTES) return false;
      const uint64_t value = unpackHash(packed);
      if (value == h) return true;
      if (value < h) low = mid + 1;
      else high = mid;
    }
    return false;
  }

  blocklist.seek((uint32_t)startPos * HASH_BYTES);
  if (blocklist.read(rangeBuf, rangeCount * HASH_BYTES) != rangeCount * HASH_BYTES) return false;

  for (uint32_t i = 0; i < rangeCount; i++) {
    uint64_t v = unpackHash(rangeBuf + i * HASH_BYTES);
    if (v == h) return true;
    if (v > h) break;
  }
  return false;
}

static bool inCustom(uint64_t h) { for (int i = 0; i < numCustom; i++) if (customHash[i] == h) return true; return false; }

// Only flash results are cached: the flash list only changes via reopenBlocklist(), which
// rebuilds the index and clears the cache. Custom domains change at runtime, so they're
// checked uncached (a short linear scan) to avoid serving stale answers.
static bool isBlockedHash(uint64_t h) {
  if (inCustom(h)) return true;
  uint32_t slot = h & (CACHE_SIZE - 1);
  if (cacheValid[slot]) {
    uint8_t want[HASH_BYTES]; packHash(h, want);
    bool same = true;
    for (int k = 0; k < HASH_BYTES; k++) if (cacheKey[slot][k] != want[k]) { same = false; break; }
    if (same) return cacheRes[slot] != 0;
  }
  bool res = inFlash(h);
  cacheValid[slot] = 1;
  cacheRes[slot] = res ? 1 : 0;
  packHash(h, cacheKey[slot]);
  return res;
}

static bool isBlocked(const char* domain) {
  const char* p = domain;
  while (p && *p) {
    uint64_t h = fnv40(p, strlen(p));
    if (isBlockedHash(h)) return true;
    const char* dot = strchr(p, '.'); if (!dot) break;
    const char* next = dot + 1; if (!strchr(next, '.')) break; p = next;
  }
  return false;
}

// ---------- persistence ----------
static void loadCustom() {
  numCustom = 0; File f = LittleFS.open("/custom.txt", "r"); if (!f) return;
  while (f.available() && numCustom < MAX_CUSTOM) {
    String l = f.readStringUntil('\n'); l.trim(); l.toLowerCase();
    if (l.length() && l.indexOf('.') > 0) { customDom[numCustom] = l; customHash[numCustom] = fnv40(l.c_str(), l.length()); numCustom++; }
  }
  f.close();
}
static void saveCustom() { File f = LittleFS.open("/custom.txt", "w"); if (!f) return; for (int i = 0; i < numCustom; i++) f.println(customDom[i]); f.close(); }
static bool addCustom(String d) {
  d.trim(); d.toLowerCase(); if (d.startsWith("www.")) d = d.substring(4);
  if (!d.length() || d.indexOf('.') < 0 || numCustom >= MAX_CUSTOM) return false;
  for (int i = 0; i < numCustom; i++) if (customDom[i] == d) return false;
  customDom[numCustom] = d; customHash[numCustom] = fnv40(d.c_str(), d.length()); numCustom++; saveCustom(); return true;
}
static void removeCustom(String d) {
  d.toLowerCase();
  for (int i = 0; i < numCustom; i++) if (customDom[i] == d) {
    for (int j = i; j < numCustom - 1; j++) { customDom[j] = customDom[j+1]; customHash[j] = customHash[j+1]; }
    numCustom--; saveCustom(); return;
  }
}
static bool isBannedIP(uint32_t ip) { for (int i = 0; i < numBanned; i++) if (bannedIP[i] == ip) return true; return false; }
static void loadBanned() {
  numBanned = 0; File f = LittleFS.open("/banned.txt", "r"); if (!f) return;
  while (f.available() && numBanned < MAX_BAN) { String l = f.readStringUntil('\n'); l.trim(); IPAddress ip; if (l.length() && ip.fromString(l)) bannedIP[numBanned++] = (uint32_t)ip; }
  f.close();
}
static void saveBanned() {
  numBanned = 0;
  for (int i = 0; i < numClients && numBanned < MAX_BAN; i++) if (clients[i].banned) bannedIP[numBanned++] = clients[i].ip;
  File f = LittleFS.open("/banned.txt", "w"); if (!f) return;
  for (int i = 0; i < numBanned; i++) { IPAddress ip(bannedIP[i]); f.println(ip.toString()); }
  f.close();
}

// ---------- client table ----------
static void getMac(uint32_t ip, uint8_t* mac) {
  memset(mac, 0, 6); ip4_addr_t ipa; ipa.addr = ip;
  struct eth_addr* eth = nullptr; const ip4_addr_t* ipret = nullptr;
  for (struct netif* nif = netif_list; nif; nif = nif->next)
    if (etharp_find_addr(nif, &ipa, &eth, &ipret) >= 0 && eth) { memcpy(mac, eth->addr, 6); return; }
}
static Dev* getClient(uint32_t ip) {
  for (int i = 0; i < numClients; i++) if (clients[i].ip == ip) { clients[i].lastSeen = millis(); return &clients[i]; }
  if (numClients < MAX_CLIENTS) {
    Dev* c = &clients[numClients++];
    c->ip = ip; c->blocked = c->allowed = 0; c->lastSeen = millis(); c->banned = isBannedIP(ip); c->label = "";
    getMac(ip, c->mac); return c;
  }
  return nullptr;
}

// ---------- DNS ----------
static size_t parseQuery(const uint8_t* pkt, int len, char* out, uint16_t* qtype, int* qend) {
  if (len < 13) return 0;
  int i = 12; size_t o = 0;
  while (i < len) { uint8_t l = pkt[i++]; if (l == 0) break; if (l & 0xC0) return 0;
    if (o + l + 1 >= 250 || i + l > len) return 0;
    if (o) out[o++] = '.';
    for (uint8_t k = 0; k < l; k++) out[o++] = tolower(pkt[i++]); }
  out[o] = 0; if (i + 4 > len) return 0; *qtype = (pkt[i] << 8) | pkt[i + 1]; *qend = i + 4;
  if (o > 4 && strncmp(out, "www.", 4) == 0) { memmove(out, out + 4, o - 3); o -= 4; }
  return o;
}
static int buildBlocked(int qend, uint16_t qtype) {
  buf[2] = 0x81; buf[3] = 0x80; buf[6] = 0; buf[7] = (qtype == 1) ? 1 : 0; buf[8] = 0; buf[9] = 0; buf[10] = 0; buf[11] = 0;
  if (qtype != 1) return qend;
  const uint8_t ans[] = {0xC0,0x0C, 0,1, 0,1, 0,0,1,0x2C, 0,4, 0,0,0,0};
  memcpy(buf + qend, ans, sizeof(ans)); return qend + sizeof(ans);
}
// Forward to upstream and wait for the reply that actually belongs to THIS query.
// Issue #10: after one timeout the late reply used to sit in the socket and get relayed
// to the next client (every answer shifted by one). Now: drain stale datagrams first,
// send with a fresh random txid, and only accept a reply whose txid, question section,
// and source address/port match. The client's own txid is restored on the way back.
static int forwardUpstream(int qlen, int qend) {
  upstreamCli.flush();                                   // release any half-read buffer
  while (upstreamCli.parsePacket() > 0) upstreamCli.flush();   // drop stale late replies
  const uint8_t cid0 = buf[0], cid1 = buf[1];
  const uint16_t wid = (uint16_t)esp_random();
  uint8_t q[260]; int ql = qend - 12;
  const bool haveQ = ql > 0 && ql <= (int)sizeof(q) && qend <= qlen;
  if (haveQ) memcpy(q, buf + 12, ql);
  buf[0] = wid >> 8; buf[1] = wid & 0xFF;
  upstreamCli.beginPacket(UPSTREAM, UPSTREAM_PORT); upstreamCli.write(buf, qlen); upstreamCli.endPacket();
  const uint32_t t0 = millis();
  while (millis() - t0 < 1000) {                         // deadline, not a retry count
    int sz = upstreamCli.parsePacket();
    if (sz <= 0) { delay(1); continue; }
    const bool fromUp = upstreamCli.remoteIP() == UPSTREAM && upstreamCli.remotePort() == UPSTREAM_PORT;
    int n = upstreamCli.read(buf, sizeof(buf));
    upstreamCli.flush();                                 // oversized datagram can't strand rx_buffer
    if (!fromUp || n < 12 || sz > (int)sizeof(buf)) continue;
    if (buf[0] != (wid >> 8) || buf[1] != (wid & 0xFF)) continue;
    if (haveQ && (n < 12 + ql || memcmp(buf + 12, q, ql) != 0)) continue;
    buf[0] = cid0; buf[1] = cid1;
    return n;
  }
  return 0;
}
// Drain a whole RX burst per call (capped, so web/OTA still get a turn) instead of
// one packet per loop iteration. Returns true if any query was handled this call.
static bool handleDns() {
  bool did = false;
  for (int budget = 0; budget < 16; budget++) {
    int sz = dnsServer.parsePacket(); if (sz <= 0) break;
    did = true;
    IPAddress cip = dnsServer.remoteIP(); uint16_t cport = dnsServer.remotePort();
    int qlen = dnsServer.read(buf, sizeof(buf)); if (qlen < 13) continue;
    char domain[256]; uint16_t qtype = 0; int qend = qlen;
    size_t dl = parseQuery(buf, qlen, domain, &qtype, &qend);
    Dev* c = getClient((uint32_t)cip);
    bool ban = c && c->banned;
    bool blocked = ban || (blockingOn && dl && numHashes && isBlocked(domain));
    int rlen;
    if (blocked) { rlen = buildBlocked(qend, qtype); totalBlocked++; if (c) c->blocked++; }
    else         { rlen = forwardUpstream(qlen, qend);     totalAllowed++; if (c) c->allowed++; }
    if (rlen > 0) { dnsServer.beginPacket(cip, cport); dnsServer.write(buf, rlen); dnsServer.endPacket(); }
  }
  return did;
}

#if DISPLAY_ENABLED && DISPLAY_TFT
#include "tft_dashboard.h"
#elif DISPLAY_ENABLED
static U8G2_SSD1306_72X40_ER_F_HW_I2C display(U8G2_R0, U8X8_PIN_NONE);

static void initDisplay() {
  Wire.begin(DISPLAY_SDA, DISPLAY_SCL);
  display.setI2CAddress(DISPLAY_I2C_ADDR << 1);
  display.setBusClock(100000);
  display.begin();
  display.setFont(u8g2_font_5x7_tf);
  display.clearBuffer();
  display.drawStr(0, 8, "S3 ADBLOCK");
  display.drawStr(0, 20, "STARTING");
  display.sendBuffer();
  Serial.printf("[display] SSD1306 72x40 ER ready on I2C %02x (SDA=%d, SCL=%d)\n", DISPLAY_I2C_ADDR, DISPLAY_SDA, DISPLAY_SCL);
}

#if HOTSPOT_ENABLED
// Sample continuously, even on the normal screen, so opening the traffic view
// shows the latest interval rather than an average since the last button press.
static uint64_t hotspotUploadBps = 0;
static uint64_t hotspotDownloadBps = 0;

static void updateHotspotSpeeds(uint32_t now) {
  static bool initialized = false;
  static uint32_t lastSampleMs = 0;
  static uint64_t previousIn = 0, previousOut = 0;
  const uint32_t elapsed = now - lastSampleMs;  // safe across millis() rollover
  if (initialized && elapsed < 1000UL) return;

  uint64_t bytesIn, bytesOut;
  getHotspotTraffic(bytesIn, bytesOut);
  if (initialized) {
    // AP input is upload from clients; AP output is download to clients.
    // Use the actual interval: DNS forwarding or updates can delay the loop.
    hotspotUploadBps = (bytesIn - previousIn) * 8000ULL / elapsed;
    hotspotDownloadBps = (bytesOut - previousOut) * 8000ULL / elapsed;
  }
  previousIn = bytesIn;
  previousOut = bytesOut;
  lastSampleMs = now;
  initialized = true;
}

static void formatTrafficSpeed(uint64_t bitsPerSecond, char* text, size_t size) {
  if (bitsPerSecond < 1000) {
    snprintf(text, size, "%llubps", (unsigned long long)bitsPerSecond);
    return;
  }
  const uint64_t unit = bitsPerSecond < 1000000ULL ? 1000ULL : 1000000ULL;
  snprintf(text, size, "%llu.%llu%s", (unsigned long long)(bitsPerSecond / unit),
           (unsigned long long)((bitsPerSecond % unit) * 10 / unit),
           unit == 1000 ? "kbps" : "Mbps");
}

static void formatTrafficBytes(uint64_t bytes, char* text, size_t size) {
  if (bytes < 1024) {
    snprintf(text, size, "%lluB", (unsigned long long)bytes);
    return;
  }
  const uint64_t unit = bytes < 1024ULL * 1024 ? 1024ULL :
                        bytes < 1024ULL * 1024 * 1024 ? 1024ULL * 1024 : 1024ULL * 1024 * 1024;
  const char* suffix = unit == 1024 ? "KB" : unit == 1024ULL * 1024 ? "MB" : "GB";
  const uint64_t whole = bytes / unit;
  const uint64_t tenth = (bytes % unit) * 10 / unit;
  snprintf(text, size, "%llu.%llu%s", (unsigned long long)whole,
           (unsigned long long)tenth, suffix);
}

static void drawTrafficScreen() {
  uint64_t bytesIn, bytesOut;
  getHotspotTraffic(bytesIn, bytesOut);
  char value[16], line[24];
  display.drawStr(0, 6, "HOTSPOT SPEED");
  formatTrafficSpeed(hotspotUploadBps, value, sizeof(value));
  snprintf(line, sizeof(line), "UP %s", value);
  display.drawStr(0, 15, line);
  formatTrafficSpeed(hotspotDownloadBps, value, sizeof(value));
  snprintf(line, sizeof(line), "DOWN %s", value);
  display.drawStr(0, 23, line);
  formatTrafficBytes(bytesIn + bytesOut, value, sizeof(value));
  snprintf(line, sizeof(line), "TOTAL %s", value);
  display.drawStr(0, 31, line);
  display.drawStr(0, 39, "BOOT: BACK");
}
#endif

static void updateDisplay() {
  static uint32_t lastFrameMs = 0;
  static bool lastTrafficScreen = false;
  const uint32_t now = millis();
#if HOTSPOT_ENABLED
  updateHotspotSpeeds(now);
#endif
  const uint32_t frameInterval = showTrafficScreen ? 1000UL : 2000UL;
  if (showTrafficScreen == lastTrafficScreen && now - lastFrameMs < frameInterval) return;
  lastTrafficScreen = showTrafficScreen;
  lastFrameMs = now;

  display.clearBuffer();
  display.setFont(u8g2_font_4x6_tf);
#if HOTSPOT_ENABLED
  if (showTrafficScreen) {
    drawTrafficScreen();
  } else
#endif
  if ((now / 6000UL) % 2 == 0) {
    display.drawStr(0, 6, "DNS BLOCKER");
    if (WiFi.status() == WL_CONNECTED) {
      IPAddress ip = WiFi.localIP();
      char ipLine1[16];
      char ipLine2[12];
      snprintf(ipLine1, sizeof(ipLine1), "IP %u.%u", ip[0], ip[1]);
      snprintf(ipLine2, sizeof(ipLine2), ".%u.%u", ip[2], ip[3]);
      display.drawStr(0, 15, ipLine1);
      display.drawStr(0, 22, ipLine2);
      display.drawStr(0, 29, numHashes ? "FILTER ON" : "NO LIST");
    } else {
      display.drawStr(0, 15, "WIFI WAIT");
      display.drawStr(0, 22, "PORTAL 192.168.4.1");
      display.drawStr(0, 29, "SET WIFI DNS");
    }
    char countText[20];
    snprintf(countText, sizeof(countText), "BLOCKED %lu", (unsigned long)totalBlocked);
    display.drawStr(0, 37, countText);
  } else {
    char line[24];
    display.drawStr(0, 6, "SYSTEM");
    snprintf(line, sizeof(line), "RSSI %d dBm", WiFi.RSSI());
    display.drawStr(0, 14, line);
    snprintf(line, sizeof(line), "DNS OK %lu", (unsigned long)totalAllowed);
    display.drawStr(0, 22, line);
    snprintf(line, sizeof(line), "DOMAINS %lu", (unsigned long)numHashes);
    display.drawStr(0, 30, line);
    snprintf(line, sizeof(line), "HEAP %luK", (unsigned long)(ESP.getFreeHeap() / 1024));
    display.drawStr(0, 38, line);
  }
  display.sendBuffer();
}
#else
static void initDisplay() {}
static void updateDisplay() {}
#endif

// ---------- web ----------
static String macStr(const uint8_t* m) { char s[18]; snprintf(s, sizeof(s), "%02x:%02x:%02x:%02x:%02x:%02x", m[0],m[1],m[2],m[3],m[4],m[5]); return String(s); }
static String jesc(const String& s) { String o; for (char ch : s) { if (ch == '"' || ch == '\\') o += '\\'; o += ch; } return o; }
// HTML text/attribute escaping for the setup portal. jesc() covers JSON (stats
// endpoint); the portal builds HTML, and its inputs — a scanned SSID, the
// submitted WiFi name — are attacker-controllable during provisioning (the
// portal AP is open, and a nearby attacker can also broadcast an SSID of their
// choosing). Without escaping both, a crafted SSID/name is reflected script
// into the setup page, the same class as the dashboard XSS fixed earlier.
static String htmlEscape(const String& s) {
  String o; o.reserve(s.length());
  for (char ch : s) {
    switch (ch) {
      case '&':  o += "&amp;";  break;
      case '<':  o += "&lt;";   break;
      case '>':  o += "&gt;";   break;
      case '"':  o += "&quot;"; break;
      case '\'': o += "&#39;";  break;
      default:   o += ch;
    }
  }
  return o;
}

#include "page.h"   // dashboard HTML (PROGMEM) — see issue #6

static void handleStats() {
  uint32_t up = millis() / 1000;
  char ut[24]; snprintf(ut, sizeof(ut), "%lud %luh %lum", (unsigned long)(up/86400),
                       (unsigned long)((up%86400)/3600), (unsigned long)((up%3600)/60));
  String j = "{\"ip\":\"" + WiFi.localIP().toString() + "\",\"blocked\":" + totalBlocked + ",\"allowed\":" + totalAllowed +
             ",\"domains\":" + numHashes + ",\"rssi\":" + WiFi.RSSI() + ",\"temp\":" + String(temperatureRead(), 1) +
             ",\"heap\":" + ESP.getFreeHeap() + ",\"uptime\":\"" + ut + "\"" +
             ",\"upurl\":\"" + jesc(updateUrl) + "\",\"upiv\":" + updateIntervalH + ",\"upstat\":\"" + jesc(updateStatus) + "\"" +
             ",\"blocking\":" + (blockingOn ? "true" : "false") +
             ",\"resumeIn\":" + (uint32_t)(!blockingOn && resumeAt ? (resumeAt - millis()) / 1000 : 0) +
             ",\"defcreds\":" + ((strcmp(WEB_PASS, "CHANGE_ME_WEB_PASSWORD") == 0 || strcmp(OTA_PASS, "CHANGE_ME_OTA_PASSWORD") == 0) ? "true" : "false") +
             ",\"clients\":[";
  for (int i = 0; i < numClients; i++) { Dev& c = clients[i]; IPAddress ip(c.ip);
    j += (i ? "," : ""); j += "{\"ip\":\"" + ip.toString() + "\",\"mac\":\"" + macStr(c.mac) + "\",\"blocked\":" + c.blocked + ",\"allowed\":" + c.allowed + ",\"banned\":" + (c.banned?"true":"false") + "}"; }
  j += "],\"custom\":[";
  for (int i = 0; i < numCustom; i++) { j += (i ? "," : ""); j += "\"" + jesc(customDom[i]) + "\""; }
  j += "]}";
  web.send(200, "application/json", j);
}
// Upstream shipped every state-changing/OTA endpoint with zero authentication —
// anyone on the LAN could reflash firmware or rewrite the blocklist. Gate them.
//
// Basic Auth alone isn't enough here: these are GET endpoints with side effects,
// and browsers auto-attach cached Basic Auth credentials to *any* request to an
// already-authenticated origin — including one triggered by a completely
// unrelated page the victim's browser visits later (e.g. <img src="http://
// s3adblock.local/forgetwifi">). That's CSRF, and it defeats the LAN-attacker
// threat model entirely: the attacker doesn't need network access, just to get
// the victim's browser to fire one request. A custom header can't be attached
// by a plain <img>/<form> CSRF vector (only same-origin fetch() can set it, and
// that's exactly what the dashboard's own JS does), so requiring one blocks the
// drive-by case without needing TLS, cookies, or a token endpoint.
static const char* CSRF_HEADER = "X-Requested-With";
static const char* CSRF_VALUE  = "s3-adblock";
static bool requireAuth() {
  if (web.header(CSRF_HEADER) != CSRF_VALUE) { web.send(403, "text/plain", "missing CSRF header"); return false; }
  if (web.authenticate(WEB_USER, WEB_PASS)) return true;
  web.requestAuthentication();
  return false;
}
static void handleBan() {
  if (!requireAuth()) return;
  IPAddress ip; if (ip.fromString(web.arg("ip"))) { Dev* c = getClient((uint32_t)ip); if (c) { c->banned = !c->banned; saveBanned(); } }
  web.send(200, "text/plain", "ok");
}

// ---------- blocklist swap (shared by upload + remote fetch) ----------
// The partition holds one list, so we free the old one before writing the new.
// While swapping, numHashes=0 -> device fail-opens (forwards, no blocking).
static void reopenBlocklist() {
  blocklist = LittleFS.open(BLOCKLIST_PATH, "r");
  numHashes = blocklist ? blocklist.size() / HASH_BYTES : 0;
  buildFlashIndex();
}
static void beginBlocklistSwap() {
#if BLOCKLIST_PSRAM
  free(blocklistRam);
  blocklistRam = nullptr;
#endif
  if (blocklist) blocklist.close();
  numHashes = 0;
  LittleFS.remove(BLOCKLIST_PATH);
  LittleFS.remove("/blocklist.new");
}
static bool commitNewBlocklist() {                  // /blocklist.new -> live (validated)
  File f = LittleFS.open("/blocklist.new", "r");
  size_t sz = f ? f.size() : 0; if (f) f.close();
  bool ok = sz > 0 && (sz % HASH_BYTES) == 0;       // sorted hash blob -> 5-byte multiple
  if (ok) LittleFS.rename("/blocklist.new", BLOCKLIST_PATH);
  else    LittleFS.remove("/blocklist.new");
  reopenBlocklist();
  return ok;
}

// ---------- OTA blocklist update (browser upload) ----------
static bool upOk = false;
static bool upAuthOk = false;
static File upFile;
static void handleUploadDone() {
  if (!upAuthOk) { web.requestAuthentication(); return; }
  web.send(upOk ? 200 : 500, "text/plain",
           upOk ? "ok" : "rejected: empty or size not a multiple of 5 (not a blocklist.bin?)");
}
static void handleUpload() {
  HTTPUpload& u = web.upload();
  switch (u.status) {
    case UPLOAD_FILE_START:
      upAuthOk = web.header(CSRF_HEADER) == CSRF_VALUE && web.authenticate(WEB_USER, WEB_PASS);
      if (!upAuthOk) { Serial.println("[ota] blocklist upload: auth/CSRF check failed"); break; }
      upOk = false; beginBlocklistSwap();
      upFile = LittleFS.open("/blocklist.new", "w");
      Serial.printf("[ota] receiving %s\n", u.filename.c_str());
      break;
    case UPLOAD_FILE_WRITE:
      if (upAuthOk && upFile) upFile.write(u.buf, u.currentSize);
      break;
    case UPLOAD_FILE_END:
      if (!upAuthOk) break;
      if (upFile) upFile.close();
      upOk = commitNewBlocklist();
      Serial.printf("[ota] %s -> %u domains\n", upOk ? "OK" : "REJECTED", numHashes);
      break;
    case UPLOAD_FILE_ABORTED:
      if (!upAuthOk) break;
      if (upFile) upFile.close();
      LittleFS.remove("/blocklist.new"); reopenBlocklist();
      Serial.println("[ota] aborted");
      break;
  }
}

// ---------- remote blocklist auto-update ----------
static void loadUpdateCfg() {
  File f = LittleFS.open("/update.cfg", "r"); if (!f) return;
  updateUrl = f.readStringUntil('\n'); updateUrl.trim();
  String iv = f.readStringUntil('\n'); iv.trim(); if (iv.length()) updateIntervalH = iv.toInt();
  f.close(); if (updateIntervalH < 1) updateIntervalH = 1;
}
static void saveUpdateCfg() {
  File f = LittleFS.open("/update.cfg", "w"); if (!f) return;
  f.println(updateUrl); f.println(updateIntervalH); f.close();
}
static bool fetchBlocklist(String url) {
  url.trim(); if (!url.length()) { updateStatus = "no url set"; return false; }
  Serial.printf("[remote] GET %s\n", url.c_str());
  WiFiClientSecure cs; cs.setInsecure();            // blocklist isn't secret -> skip cert pinning
  WiFiClient cl;
  HTTPClient http; http.setTimeout(20000);
  http.setFollowRedirects(HTTPC_STRICT_FOLLOW_REDIRECTS);  // GitHub release -> CDN redirect
  bool https = url.startsWith("https");
  if (!(https ? http.begin(cs, url) : http.begin(cl, url))) { updateStatus = "begin failed"; return false; }
  int code = http.GET();
  if (code != HTTP_CODE_OK) { http.end(); updateStatus = "HTTP " + String(code); Serial.printf("[remote] %s\n", updateStatus.c_str()); return false; }
  beginBlocklistSwap();
  File f = LittleFS.open("/blocklist.new", "w");
  if (!f) { http.end(); updateStatus = "fs open failed"; reopenBlocklist(); return false; }
  WiFiClient* stream = http.getStreamPtr();
  int len = http.getSize(); uint8_t b[1024]; size_t total = 0; uint32_t idle = millis();
  while (http.connected() && (len < 0 || (int)total < len)) {
    size_t avail = stream->available();
    if (avail) { int n = stream->readBytes(b, avail > sizeof(b) ? sizeof(b) : avail); if (n > 0) { f.write(b, n); total += n; idle = millis(); } }
    else { if (millis() - idle > 15000) break; delay(2); }
  }
  f.close(); http.end();
  bool ok = commitNewBlocklist();
  updateStatus = ok ? ("ok: " + String(numHashes) + " domains") : ("bad data (" + String(total) + "B)");
  Serial.printf("[remote] %s\n", updateStatus.c_str());
  return ok;
}

// ---------- firmware OTA (browser upload of firmware.bin -> reboot) ----------
static bool fwAuthOk = false;
static void handleFwUpdateDone() {
  if (!fwAuthOk) { web.requestAuthentication(); return; }
  bool ok = !Update.hasError();
  web.send(ok ? 200 : 500, "text/plain", ok ? "ok, rebooting" : "firmware update failed");
  if (ok) { delay(300); ESP.restart(); }
}
static void handleFwUpload() {
  HTTPUpload& u = web.upload();
  if (u.status == UPLOAD_FILE_START) {
    fwAuthOk = web.header(CSRF_HEADER) == CSRF_VALUE && web.authenticate(WEB_USER, WEB_PASS);
    if (!fwAuthOk) { Serial.println("[fw-ota] auth/CSRF check failed, rejecting flash"); return; }
    Serial.printf("[fw-ota] %s\n", u.filename.c_str());
    if (!Update.begin(UPDATE_SIZE_UNKNOWN)) Update.printError(Serial);
  } else if (u.status == UPLOAD_FILE_WRITE) {
    if (!fwAuthOk) return;
    if (Update.write(u.buf, u.currentSize) != u.currentSize) Update.printError(Serial);
  } else if (u.status == UPLOAD_FILE_END) {
    if (!fwAuthOk) return;
    if (Update.end(true)) Serial.printf("[fw-ota] %u bytes OK\n", u.totalSize);
    else Update.printError(Serial);
  } else if (u.status == UPLOAD_FILE_ABORTED) {
    if (!fwAuthOk) return;
    Update.abort(); Serial.println("[fw-ota] aborted");
  }
}

// ---------- WiFi provisioning (captive portal) ----------
// Try provisioned NVS creds first, then the compile-time secrets.h creds as a
// fallback (so the maintainer's own device + source builders keep working). If
// neither connects, fall through to the config portal.
static String wifiFailureMessage(uint8_t reason) {
  switch (reason) {
    case WIFI_REASON_NO_AP_FOUND:
      return "Network not found. Use a 2.4 GHz Wi-Fi network and check its name and signal.";
    case WIFI_REASON_AUTH_FAIL:
    case WIFI_REASON_AUTH_EXPIRE:
    case WIFI_REASON_4WAY_HANDSHAKE_TIMEOUT:
      return "Wi-Fi authentication failed. Check the password and router security settings.";
    default:
      return reason ? "Wi-Fi connection failed (reason " + String(reason) + "). Check the network and password."
                    : "Could not connect. Check the Wi-Fi name, password, and 2.4 GHz signal.";
  }
}

static bool saveWiFiSetupError(const String& message) {
  if (!prefs.begin("wifi", false)) {
    Serial.println("[setup] failed to open WiFi settings to save connection error");
    return false;
  }
  const String storedMessage = message.length() ? message : "OK";
  bool saved = prefs.putString("error", storedMessage) == storedMessage.length();
  prefs.end();
  if (!saved) Serial.println("[setup] failed to save WiFi connection error");
  return saved;
}

static bool loadWiFiNetworks() {
  numWifiNetworks = 0;
  if (!prefs.begin("wifi", true)) {
    Serial.println("[setup] failed to open saved WiFi settings");
    return false;
  }

  for (int i = 0; i < MAX_WIFI_NETWORKS; i++) {
    const String key = "ssid" + String(i);
    const String ssid = prefs.getString(key.c_str(), "");
    if (!ssid.length()) continue;
    wifiNetworks[numWifiNetworks].ssid = ssid;
    wifiNetworks[numWifiNetworks].pass = prefs.getString(("pass" + String(i)).c_str(), "");
    numWifiNetworks++;
  }

  if (!numWifiNetworks) {
    const String legacySSID = prefs.getString("ssid", "");
    if (legacySSID.length()) {
      wifiNetworks[0].ssid = legacySSID;
      wifiNetworks[0].pass = prefs.getString("pass", "");
      numWifiNetworks = 1;
    }
  }
  prefs.end();

  if (!numWifiNetworks && WIFI_SSID && *WIFI_SSID && strcmp(WIFI_SSID, "YOUR_WIFI_SSID") != 0) {
    wifiNetworks[0].ssid = WIFI_SSID;
    wifiNetworks[0].pass = WIFI_PASS;
    numWifiNetworks = 1;
  }
  return true;
}

static bool hasCreds() {
  return loadWiFiNetworks() && numWifiNetworks > 0;
}

static bool connectWiFi() {
  if (!loadWiFiNetworks() || !numWifiNetworks) return false;

  lastWifiDisconnectReason = 0;
  WiFi.mode(WIFI_STA); WiFi.setSleep(false);
  for (int i = 0; i < numWifiNetworks; i++) {
    activeWifiNetwork = i;
    Serial.printf("WiFi: trying saved network %d of %d: \"%s\"\n",
                  i + 1, numWifiNetworks, wifiNetworks[i].ssid.c_str());
    WiFi.disconnect(false, false);
    WiFi.begin(wifiNetworks[i].ssid.c_str(), wifiNetworks[i].pass.c_str());
    lastWifiAttemptMs = millis();

    const uint32_t attemptStarted = millis();
    while (WiFi.status() != WL_CONNECTED && millis() - attemptStarted < 12000UL) {
      delay(100);
    }
    if (WiFi.status() == WL_CONNECTED) {
      Serial.printf("[setup] connected using saved network %d\n", i + 1);
      lastWifiDisconnectReason = 0;
      saveWiFiSetupError("");
      return true;
    }
    lastWifiDisconnectReason = 0;
  }

  const uint8_t reason = lastWifiDisconnectReason;
  const String message = wifiFailureMessage(reason);
  Serial.printf("[setup] no saved network connected: %s\n", message.c_str());
  saveWiFiSetupError(message);
  return false;
}

static void maintainWiFiConnection() {
  if (WiFi.status() == WL_CONNECTED) return;
  if (!numWifiNetworks || millis() - lastWifiAttemptMs < 15000UL) return;

  activeWifiNetwork = (activeWifiNetwork + 1) % numWifiNetworks;
  WifiCredentials& network = wifiNetworks[activeWifiNetwork];
  Serial.printf("[wifi] reconnecting with saved network %d of %d: \"%s\"\n",
                activeWifiNetwork + 1, numWifiNetworks, network.ssid.c_str());
  lastWifiAttemptMs = millis();
  WiFi.begin(network.ssid.c_str(), network.pass.c_str());
}

#if HOTSPOT_ENABLED
static bool startAdblockHotspot() {
  const IPAddress apIP(192, 168, 4, 1);
  const IPAddress subnet(255, 255, 255, 0);
  if (!WiFi.mode(WIFI_AP_STA) || !WiFi.setAutoReconnect(true)) {
    Serial.println("[hotspot] failed to enable AP+STA mode");
    return false;
  }
  if (!WiFi.softAPConfig(apIP, apIP, subnet)) {
    Serial.println("[hotspot] failed to configure AP address");
    return false;
  }

  uint8_t mac[6];
  WiFi.macAddress(mac);
  char ssid[24];
  snprintf(ssid, sizeof(ssid), "S3-AdBlock-%02X%02X", mac[4], mac[5]);

  if (!WiFi.softAP(ssid, HOTSPOT_PASS)) {
    Serial.println("[hotspot] failed to start protected access point");
    return false;
  }

  esp_netif_t* apNetif = esp_netif_get_handle_from_ifkey("WIFI_AP_DEF");
  if (!apNetif) {
    Serial.println("[hotspot] AP network interface not available");
    return false;
  }
  if (!monitorHotspotTraffic(apNetif)) {
    WiFi.softAPdisconnect(true);
    return false;
  }

  esp_err_t err = esp_netif_dhcps_stop(apNetif);
  if (err != ESP_OK && err != ESP_ERR_ESP_NETIF_DHCP_ALREADY_STOPPED) {
    Serial.printf("[hotspot] failed to stop DHCP server: %s\n", esp_err_to_name(err));
    return false;
  }

  esp_netif_dns_info_t dnsInfo = {};
  dnsInfo.ip.type = ESP_IPADDR_TYPE_V4;
  dnsInfo.ip.u_addr.ip4.addr = ESP_IP4TOADDR(192, 168, 4, 1);
  err = esp_netif_set_dns_info(apNetif, ESP_NETIF_DNS_MAIN, &dnsInfo);
  if (err != ESP_OK) {
    Serial.printf("[hotspot] failed to advertise DNS server: %s\n", esp_err_to_name(err));
    return false;
  }
  err = esp_netif_dhcps_start(apNetif);
  if (err != ESP_OK) {
    Serial.printf("[hotspot] failed to restart DHCP server: %s\n", esp_err_to_name(err));
    return false;
  }

  ip4_addr_t naptAddress;
  IP4_ADDR(&naptAddress, 192, 168, 4, 1);
  ip_napt_enable(naptAddress.addr, 1);

  Serial.printf("[hotspot] SSID: %s\n", ssid);
  Serial.printf("[hotspot] password: %s\n", HOTSPOT_PASS);
  Serial.printf("[hotspot] gateway/DNS: %s; upstream: %s\n",
                apIP.toString().c_str(), WiFi.localIP().toString().c_str());
  return true;
}
#else
static bool startAdblockHotspot() { return true; }
#endif

static void handlePortalRoot() {
  String html =
    "<!doctype html><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>"
    "<title>S3 AdBlock setup</title>"
    "<body style='font:16px system-ui,sans-serif;max-width:420px;margin:36px auto;padding:0 16px;background:#0d1117;color:#c9d1d9'>"
    "<h2>&#128737; S3 AdBlock &mdash; WiFi setup</h2>"
    "<p style='color:#8b949e'>Add up to five 2.4 GHz networks in priority order. Enter each password; leave it blank only for open Wi-Fi.</p>";
  if (portalError.length())
    html += "<p style='padding:10px;border-radius:6px;background:#3b1d24;color:#ffb4ab'>" + htmlEscape(portalError) + "</p>";
  html += "<form method=POST action=/wifisave><datalist id=nets>" + portalOpts + "</datalist>";
  for (int i = 0; i < MAX_WIFI_NETWORKS; i++) {
    html += "<label>Wi-Fi network " + String(i + 1) + "</label>"
      "<input list=nets name='s" + String(i) + "' placeholder='Wi-Fi name' value='" +
      htmlEscape(portalSSIDs[i]) +
      "' style='width:100%;box-sizing:border-box;padding:11px;margin:6px 0;border-radius:6px;border:1px solid #30363d;background:#161b22;color:#c9d1d9'>"
      "<input name='p" + String(i) + "' type=password placeholder='Password (blank for open Wi-Fi)' "
      "style='width:100%;box-sizing:border-box;padding:11px;margin:6px 0 14px;border-radius:6px;border:1px solid #30363d;background:#161b22;color:#c9d1d9'>";
  }
  html += "<button style='width:100%;padding:12px;margin-top:8px;border-radius:6px;border:0;background:#3fb950;color:#000;font-weight:600;cursor:pointer'>Save networks</button></form></body>";
  web.send(200, "text/html", html);
}
static void handleWifiSave() {
  WifiCredentials submitted[MAX_WIFI_NETWORKS];
  int submittedCount = 0;
  for (int i = 0; i < MAX_WIFI_NETWORKS; i++) {
    String ss = web.arg("s" + String(i));
    String pw = web.arg("p" + String(i));
    if (!ss.length()) {
      if (pw.length()) {
        web.send(400, "text/plain", "Enter a Wi-Fi name for every password provided");
        return;
      }
      continue;
    }
    if (ss.length() > 32 || pw.length() > 63 || (pw.length() > 0 && pw.length() < 8)) {
      web.send(400, "text/plain", "Wi-Fi name must be at most 32 bytes; password must be blank or 8-63 bytes");
      return;
    }
    for (int j = 0; j < submittedCount; j++) {
      if (submitted[j].ssid == ss) {
        web.send(400, "text/plain", "Each Wi-Fi network name can only be entered once");
        return;
      }
    }
    submitted[submittedCount].ssid = ss;
    submitted[submittedCount].pass = pw;
    submittedCount++;
  }
  if (!submittedCount) {
    web.send(400, "text/plain", "Enter at least one Wi-Fi network");
    return;
  }
  if (!prefs.begin("wifi", false)) {
    web.send(500, "text/plain", "Could not open WiFi settings; check the device log");
    return;
  }
  bool saved = true;
  for (int i = 0; i < MAX_WIFI_NETWORKS && saved; i++) {
    String ssidKey = "ssid" + String(i);
    String passKey = "pass" + String(i);
    if (i < submittedCount) {
      saved = prefs.putString(ssidKey.c_str(), submitted[i].ssid) == submitted[i].ssid.length() &&
              prefs.getString(ssidKey.c_str(), "") == submitted[i].ssid;
      if (saved) {
        prefs.putString(passKey.c_str(), submitted[i].pass);
        saved = prefs.getString(passKey.c_str(), "") == submitted[i].pass;
      }
    } else {
      prefs.remove(ssidKey.c_str());
      prefs.remove(passKey.c_str());
    }
  }
  if (saved) {
    prefs.remove("ssid");
    prefs.remove("pass");
    saved = prefs.putString("error", "OK") == 2;
  }
  prefs.end();
  if (!saved) {
    web.send(500, "text/plain", "Could not save WiFi settings; check the device log");
    return;
  }
  web.send(200, "text/html", "<!doctype html><meta charset=utf-8><body style='font:16px system-ui;text-align:center;margin-top:60px'>"
                             "&#9989; Saved " + String(submittedCount) + " Wi-Fi network(s). Restarting; networks will be tried in order.<br><br>"
                             "Reconnect your phone to your normal WiFi, then find the box at <b>s3adblock.local</b>.</body>");
  delay(900); ESP.restart();
}
// Never returns — blocks in the portal loop until creds are saved (then reboots).
static void startConfigPortal() {
  int n = WiFi.scanNetworks();                 // scan while still in STA mode (no APSTA)
  portalOpts = "";
  for (int i = 0; i < n && i < 15; i++) portalOpts += "<option value='" + htmlEscape(WiFi.SSID(i)) + "'>";
  for (int i = 0; i < MAX_WIFI_NETWORKS; i++) portalSSIDs[i] = "";
  portalError = "";
  loadWiFiNetworks();
  for (int i = 0; i < numWifiNetworks; i++) portalSSIDs[i] = wifiNetworks[i].ssid;
  if (prefs.begin("wifi", true)) {
    portalError = prefs.getString("error", "");
    prefs.end();
    if (portalError == "OK") portalError = "";
  } else {
    Serial.println("[setup] failed to read WiFi settings for portal");
    portalError = "Could not read saved Wi-Fi settings. Check the device log.";
  }
  uint8_t mac[6]; WiFi.macAddress(mac);
  char ap[24]; snprintf(ap, sizeof(ap), "S3-AdBlock-%02X%02X", mac[4], mac[5]);
  WiFi.mode(WIFI_AP); WiFi.softAP(ap);
  IPAddress apIP = WiFi.softAPIP();
  dnsPortal.start(53, "*", apIP);              // catch-all -> phones pop the captive portal
  web.on("/", handlePortalRoot);
  web.on("/wifisave", HTTP_POST, handleWifiSave);
  web.onNotFound(handlePortalRoot);            // any captive-portal probe -> the form
  web.begin();
  Serial.printf("\n[setup] No WiFi. Join open network \"%s\" and a setup page pops up (or http://%s)\n",
                ap, apIP.toString().c_str());
  // A configured device that merely failed to join (router rebooting, weak signal) must not
  // get stuck here: if nobody is using the portal, reboot and retry WiFi every 3 minutes.
  const bool configured = hasCreds();
  uint32_t t0 = millis();
  while (true) {
    dnsPortal.processNextRequest(); web.handleClient(); handleBootButton(); updateDisplay(); delay(2);
    if (WiFi.softAPgetStationNum() > 0) t0 = millis();          // someone is setting it up
    if (configured && millis() - t0 > 180000UL) { Serial.println("[setup] retrying WiFi"); ESP.restart(); }
  }
}

void setup() {
  Serial.begin(115200); delay(300);
  Serial.println("\n[s3-adblock] booting");
  WiFi.onEvent([](WiFiEvent_t event, WiFiEventInfo_t info) {
    if (event == ARDUINO_EVENT_WIFI_STA_DISCONNECTED)
      lastWifiDisconnectReason = info.wifi_sta_disconnected.reason;
  }, ARDUINO_EVENT_WIFI_STA_DISCONNECTED);
  if (!LittleFS.begin(true)) Serial.println("LittleFS FAILED");
  initDisplay();
  blocklist = LittleFS.open(BLOCKLIST_PATH, "r");
  if (blocklist) {
    numHashes = blocklist.size() / HASH_BYTES;
    Serial.printf("blocklist: %u domains\n", numHashes);
    buildFlashIndex();
  }
  loadCustom(); loadBanned(); loadUpdateCfg();
  Serial.printf("custom: %d, banned: %d\n", numCustom, numBanned);

  // Hold BOOT at power-on to wipe saved WiFi and force the setup portal.
  initializeBootButton();
  if (digitalRead(BOOT_PIN) == LOW) { delay(60);
    if (digitalRead(BOOT_PIN) == LOW) { prefs.begin("wifi", false); prefs.clear(); prefs.end();
      Serial.println("[setup] BOOT held -> cleared saved WiFi"); } }

  if (!connectWiFi()) startConfigPortal();   // portal blocks + reboots on save; returns only when connected
  Serial.printf("WiFi up: %s\n", WiFi.localIP().toString().c_str());
  if (!startAdblockHotspot()) Serial.println("[hotspot] disabled; check configuration");
  updateDisplay();
  if (MDNS.begin("s3adblock")) { MDNS.addService("http", "tcp", 80); Serial.println("dashboard: http://s3adblock.local"); }

  if (strcmp(WEB_PASS, "CHANGE_ME_WEB_PASSWORD") == 0 || strcmp(OTA_PASS, "CHANGE_ME_OTA_PASSWORD") == 0)
    Serial.println("[WARN] secrets.h still has placeholder WEB_PASS/OTA_PASS — those are public "
                    "(they're in the repo's example file). Set real values before trusting this "
                    "device on a network you don't fully control.");

  dnsServer.begin(DNS_PORT); upstreamCli.begin(0);
  { const char* hdrs[] = { CSRF_HEADER }; web.collectHeaders(hdrs, 1); }  // needed for requireAuth()'s CSRF check
  web.on("/", []() { web.send_P(200, "text/html", PAGE); });
  web.on("/stats.json", handleStats);
  web.on("/ban", handleBan);
  web.on("/addblock", []() {
    if (!requireAuth()) return;
    bool added = addCustom(web.arg("d"));
    web.send(added ? 200 : 400, "text/plain",
             added ? "ok" : "Could not add domain: invalid name, duplicate rule, or 200-rule limit reached.");
  });
  web.on("/unblock", []() { if (!requireAuth()) return; removeCustom(web.arg("d")); web.send(200, "text/plain", "ok"); });
  web.on("/pause", []() {                    // /pause?s=300  (0 or absent = indefinite)
    if (!requireAuth()) return;
    long s = web.hasArg("s") ? web.arg("s").toInt() : 0;
    blockingOn = false; resumeAt = (s > 0) ? millis() + (uint32_t)s * 1000UL : 0;
    web.send(200, "text/plain", "paused");
  });
  web.on("/resume", []() { if (!requireAuth()) return; blockingOn = true; resumeAt = 0; web.send(200, "text/plain", "resumed"); });
  web.on("/forgetwifi", []() { if (!requireAuth()) return; web.send(200, "text/plain", "cleared — rebooting into setup portal");
    prefs.begin("wifi", false); prefs.clear(); prefs.end(); delay(500); ESP.restart(); });
  web.on("/upload", HTTP_POST, handleUploadDone, handleUpload);      // blocklist OTA (auth inside handleUpload)
  web.on("/update", HTTP_POST, handleFwUpdateDone, handleFwUpload);  // firmware OTA (auth inside handleFwUpload)
  web.on("/fetchnow", []() { if (!requireAuth()) return; fetchBlocklist(updateUrl); web.send(200, "text/plain", updateStatus); });
  web.on("/setupdate", []() {
    if (!requireAuth()) return;
    if (web.hasArg("u")) updateUrl = web.arg("u");
    if (web.hasArg("h")) { updateIntervalH = web.arg("h").toInt(); if (updateIntervalH < 1) updateIntervalH = 1; }
    saveUpdateCfg(); web.send(200, "text/plain", "ok");
  });
  web.begin();
  ArduinoOTA.setHostname("s3adblock");   // pio run -t upload --upload-port s3adblock.local
  ArduinoOTA.setPassword(OTA_PASS);      // network OTA was unauthenticated upstream
  ArduinoOTA.begin();
  Serial.println("DNS :53 + dashboard :80 + OTA up");
}

void loop() {
  ArduinoOTA.handle();
  web.handleClient();
  handleBootButton();
  maintainWiFiConnection();
  bool busy = handleDns();
  if (!blockingOn && resumeAt && (int32_t)(millis() - resumeAt) >= 0) { blockingOn = true; resumeAt = 0; }
  if (updateUrl.length()) {               // periodic remote blocklist auto-update
    uint32_t now = millis();
    if (lastCheckMs == 0) lastCheckMs = now;   // skip an immediate fetch on boot
    else if (now - lastCheckMs >= updateIntervalH * 3600000UL) { lastCheckMs = now; fetchBlocklist(updateUrl); }
  }
  updateDisplay();
  if (!busy) delay(1);   // sleep only when idle: full speed under load, cool when quiet
}
