Import("env")

import os

framework_dir = env.PioPlatform().get_package_dir("framework-arduinoespressif32")
if not framework_dir:
    raise RuntimeError("The Arduino ESP32 framework package is required for s3_hotspot.")

sdk_dir = os.path.join(framework_dir, "tools", "sdk", env.BoardConfig().get("build.mcu"))
env.AppendUnique(
    CPPPATH=[os.path.join(sdk_dir, "include", "esp_littlefs", "include")],
    CPPDEFINES=["CONFIG_LITTLEFS_PAGE_SIZE=256"],
    LIBPATH=[os.path.join(sdk_dir, "lib")],
    LIBS=["esp_littlefs"],
)
