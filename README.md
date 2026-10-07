# ESP32-S3 N16R8 AdBlock + 2.8-inch SPI TFT

This is a fork of [ESP32-C3 AdBlock](https://github.com/00nothin/esp32-c3-adblock-main), adapted for the ESP32-S3 N16R8 and 2.8-inch SPI TFT.

## Hardware

Assumes an **ILI9341** 240 x 320 SPI display. Check the controller printed on the module/listing; screen size alone does not identify it. The firmware uses portrait orientation and a conservative 20 MHz SPI clock for expansion-board wiring.

| TFT signal | ESP32-S3 connection |
| --- | --- |
| CS | GPIO14 |
| RESET | GPIO21 |
| DC | GPIO47 |
| MOSI / SDI | GPIO45 |
| SCK / CLK | GPIO3 |
| MISO / SDO | GPIO46 |
| LED / backlight | 3.3 V (always on, no PWM pin) |
| GND | Common GND |

Supply the display's VCC according to its module specification. All SPI signals use 3.3 V logic. Touch and SD-card functions are not configured.

GPIO3, GPIO45 and GPIO46 are ESP32-S3 strapping pins: the expansion board/display must not force incorrect levels during reset. GPIO45 can select the flash supply voltage unless overridden by eFuses; GPIO46 affects download mode. If connecting the TFT prevents boot or flashing, disconnect it to isolate the issue and check the expansion-board pull resistors. Firmware cannot correct a strap sampled before it starts. See [Espressif's hardware checklist](https://docs.espressif.com/projects/esp-hardware-design-guidelines/en/latest/esp32s3/schematic-checklist.html).

## S3 changes

- 240 MHz dual-core ESP32-S3, 16 MiB quad-SPI flash and 8 MiB octal PSRAM (`qio_opi`).
- Two 3 MiB application slots retain firmware OTA; 9.9375 MiB LittleFS holds the blocklist and settings. Filesystem metadata consumes some of that space.
- Packed 40-bit blocklist hashes load into PSRAM if they fit while leaving at least 512 KiB free. Otherwise the original indexed flash backend is used. The startup log and TFT report which backend is active.
- 2,048-entry hash-result cache. Oversized flash-index buckets are searched fully instead of truncating them at 256 entries.
- TFT updates changed rows at most once per second, with no full-screen framebuffer in the DNS loop. Startup colour bars help test the display. BOOT toggles hotspot traffic stats.
- Existing Wi-Fi provisioning, dashboard, custom domains, blocklist updates, firmware OTA, and private hotspot retained.
- S3 identity: dashboard/OTA hostname `s3adblock.local`, AP name `S3-AdBlock-XXXX`, so it can coexist with your C3.

This does not change the original synchronous upstream DNS forwarding; throughput still depends on Wi-Fi and upstream response time. Performance has not been measured on hardware.

## Build and flash

Install [PlatformIO Core](https://docs.platformio.org/en/latest/core/installation/index.html) or the PlatformIO IDE extension, then open a terminal **in this folder**. Build the firmware with:

```sh
pio run -e s3_hotspot
```

Use `pio device list` to find the board's serial port. Then replace the example port below with the one shown on your system:

| Operating system | Example serial port |
| --- | --- |
| Windows | `COM3` |
| Linux | `/dev/ttyACM0` or `/dev/ttyUSB0` |
| macOS | `/dev/cu.usbmodem...` or `/dev/cu.usbserial...` |

Upload the firmware and filesystem, then open the serial monitor:

```sh
pio run -e s3_hotspot -t upload --upload-port PORT
pio run -e s3_hotspot -t uploadfs --upload-port PORT
pio device monitor -p PORT -b 115200
```

On Windows, replace `PORT` with the COM port, for example `COM3`. If `pio` is not on `PATH`, run PlatformIO Core's executable directly; a common Windows installation path is `%USERPROFILE%\.platformio\penv\Scripts\platformio.exe`. On Linux, your user may need permission to access the serial device (often by joining the `dialout` or `uucp` group, depending on the distribution); log out and back in after changing group membership.

The default `s3_hotspot` environment enables IPv4 NAT and the private Wi-Fi hotspot. `s3_tft` is an alternative for a DNS-only server on your existing LAN; set your router/client DNS to the S3 IP when using that environment. Keep the same environment for firmware and filesystem uploads.

Serial output uses native USB CDC. If your kit has separate USB and UART connectors, use the native USB connector for the serial monitor.

For a fresh configuration, copy `src/secrets.example.h` to `src/secrets.h` and set unique Wi-Fi, dashboard, and OTA credentials. `src/secrets.h` and generated build files are ignored by Git. Wi-Fi credentials can also be entered using the setup portal. Never publish actual credentials or previously built firmware binaries.

`uploadfs` replaces the S3 filesystem (including custom rules/configuration stored there). Use it for initial setup. Later, use the web dashboard to update only the blocklist. A first USB firmware + filesystem upload is needed for this 16 MiB partition layout; do not install it as an OTA update to the C3.

## Test on the board

1. Connect the TFT using the table, including common ground and LED to 3.3 V. Flash the S3 firmware and filesystem.
2. Expect a title and red/green/blue strip, followed by IP, filtering state and counters. If the panel stays white, verify ILI9341, reset/DC wiring and power. For noisy wiring, lower `TFT_SPI_HZ` in `platformio.ini` to `10000000` and rebuild.
3. Check the serial log for 16 MiB flash, 8192 KiB PSRAM and a loaded blocklist. It should use PSRAM for the copied list.
4. Connect using the Wi-Fi setup portal if needed. Then connect to the protected S3 hotspot with the configured `HOTSPOT_PASS` and visit `http://s3adblock.local` (or the TFT IP).
5. Query a domain you know is in the list and an allowed domain using the S3 as DNS; verify the blocked/allowed counters increase. Press BOOT while running to view hotspot traffic.

On the S3, holding BOOT during reset enters the ROM downloader. Release BOOT after flashing; do not hold it through reset when trying to run the application. Use the dashboard's forget-Wi-Fi action to return to setup.

## Local checks

```sh
pio run -e s3_hotspot
pio run -e s3_tft
pio run -e s3_hotspot -t buildfs
python -m unittest discover -s tools -p 'test_*.py' -v
```
