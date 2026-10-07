#pragma once

#include <SPI.h>
#include <Adafruit_ILI9341.h>

// FSPI is the S3's general-purpose SPI controller, separate from flash/PSRAM.
static SPIClass tftSpi(FSPI);
static Adafruit_ILI9341 tft(&tftSpi, TFT_DC, TFT_CS, TFT_RST);
static char tftPrevious[11][32] = {};

// Only changed rows are transmitted: no full-screen redraw/framebuffer in
// the DNS loop. Twenty characters fit across the portrait panel at size 2.
static void tftRow(unsigned row, const char* text) {
  if (row >= 11 || strcmp(tftPrevious[row], text) == 0) return;
  snprintf(tftPrevious[row], sizeof(tftPrevious[row]), "%s", text);
  const int y = 43 + row * 24;
  tft.fillRect(0, y, 240, 22, ILI9341_BLACK);
  tft.setCursor(4, y + 3);
  tft.print(text);
}

static void initDisplay() {
  pinMode(TFT_CS, OUTPUT);
  digitalWrite(TFT_CS, HIGH);
  tftSpi.begin(TFT_SCLK, TFT_MISO, TFT_MOSI, TFT_CS);
  tft.begin(TFT_SPI_HZ);
  tft.setRotation(0);  // 240 x 320 portrait
  tft.fillScreen(ILI9341_BLACK);
  tft.setTextWrap(false);
  tft.setTextSize(2);
  tft.setTextColor(ILI9341_CYAN, ILI9341_BLACK);
  tft.setCursor(10, 10);
  tft.print("ESP32-S3 ADBLOCK");
  // Persistent colour swatches make wiring/colour-order testing easy.
  tft.fillRect(0, 34, 80, 4, ILI9341_RED);
  tft.fillRect(80, 34, 80, 4, ILI9341_GREEN);
  tft.fillRect(160, 34, 80, 4, ILI9341_BLUE);
  tft.setTextColor(ILI9341_WHITE, ILI9341_BLACK);
  tftRow(0, "Starting Wi-Fi...");
  tftRow(1, "ILI9341 240x320");
  tftRow(2, psramFound() ? "PSRAM detected" : "PSRAM unavailable");
  Serial.printf("[display] ILI9341 SPI %u Hz: CS=%d RST=%d DC=%d MOSI=%d SCK=%d MISO=%d\n",
                TFT_SPI_HZ, TFT_CS, TFT_RST, TFT_DC, TFT_MOSI, TFT_SCLK, TFT_MISO);
  Serial.printf("[memory] flash=%u MiB PSRAM=%u KiB\n", ESP.getFlashChipSize() / 1048576,
                ESP.getPsramSize() / 1024);
}

static void updateDisplay() {
  static uint32_t lastFrame = 0;
  static bool firstFrame = true, lastTraffic = false;
  const uint32_t now = millis();
  if (!firstFrame && lastTraffic == showTrafficScreen && now - lastFrame < 1000) return;
  firstFrame = false;
  lastFrame = now;
  lastTraffic = showTrafficScreen;
  char lines[11][32] = {};

#if HOTSPOT_ENABLED
  static bool sampled = false;
  static uint32_t sampledAt = 0;
  static uint64_t previousIn = 0, previousOut = 0;
  static double upKbps = 0, downKbps = 0;
  uint64_t bytesIn, bytesOut;
  getHotspotTraffic(bytesIn, bytesOut);
  const uint32_t elapsed = now - sampledAt;
  if (!sampled || elapsed >= 1000) {
    if (sampled) {
      upKbps = (bytesIn - previousIn) * 8.0 / elapsed;
      downKbps = (bytesOut - previousOut) * 8.0 / elapsed;
    }
    sampled = true;
    sampledAt = now;
    previousIn = bytesIn;
    previousOut = bytesOut;
  }
  if (showTrafficScreen) {
    snprintf(lines[0], sizeof(lines[0]), "HOTSPOT TRAFFIC");
    snprintf(lines[2], sizeof(lines[2]), "UP   %.1f kbps", upKbps);
    snprintf(lines[3], sizeof(lines[3]), "DOWN %.1f kbps", downKbps);
    snprintf(lines[5], sizeof(lines[5]), "Total %.2f MiB", (bytesIn + bytesOut) / 1048576.0);
    snprintf(lines[7], sizeof(lines[7]), "AP %s", WiFi.softAPIP().toString().c_str());
    snprintf(lines[8], sizeof(lines[8]), "Stations %u", WiFi.softAPgetStationNum());
    snprintf(lines[10], sizeof(lines[10]), "BOOT: dashboard");
  } else
#endif
  {
    const bool connected = WiFi.status() == WL_CONNECTED;
    snprintf(lines[0], sizeof(lines[0]), "%s", connected ? "Wi-Fi connected" : "Wi-Fi setup / wait");
    snprintf(lines[1], sizeof(lines[1]), "%s", connected ? WiFi.localIP().toString().c_str() : "Setup: 192.168.4.1");
    snprintf(lines[2], sizeof(lines[2]), "%s", !blockingOn ? "Filtering PAUSED" : numHashes ? "Filtering ON" : "No blocklist loaded");
    snprintf(lines[3], sizeof(lines[3]), "Blocked %lu", (unsigned long)totalBlocked);
    snprintf(lines[4], sizeof(lines[4]), "Allowed %lu", (unsigned long)totalAllowed);
    snprintf(lines[5], sizeof(lines[5]), "Domains %lu", (unsigned long)numHashes);
    snprintf(lines[6], sizeof(lines[6]), "RSSI %d dBm", connected ? WiFi.RSSI() : 0);
    snprintf(lines[7], sizeof(lines[7]), "Heap %lu KiB", (unsigned long)(ESP.getFreeHeap() / 1024));
#if BLOCKLIST_PSRAM
    snprintf(lines[8], sizeof(lines[8]), "List: %s", blocklistRam ? "PSRAM" : "flash");
#endif
#if HOTSPOT_ENABLED
    snprintf(lines[9], sizeof(lines[9]), "AP %s", WiFi.softAPIP().toString().c_str());
    snprintf(lines[10], sizeof(lines[10]), "BOOT: traffic");
#else
    snprintf(lines[9], sizeof(lines[9]), "Set router DNS to");
    snprintf(lines[10], sizeof(lines[10]), "the IP above");
#endif
  }
  for (unsigned row = 0; row < 11; ++row) tftRow(row, lines[row]);
}
