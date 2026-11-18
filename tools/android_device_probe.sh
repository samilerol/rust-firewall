#!/usr/bin/env bash
# Install the preview APK on a real phone over adb and collect health evidence.
# Works the same over USB, `adb connect host:5555` (Tailscale) or a self-hosted runner.
#
#   APK=app-debug.apk tools/android_device_probe.sh
#
# Environment:
#   APK            path to the debug APK (required)
#   ADB            adb binary (default: adb)
#   ADB_SERIAL     device serial or host:port when more than one device is attached
#   WATCH_SECONDS  how long to observe after launch (default 60); connect the VPN on the phone
#                  inside this window to capture live traffic behavior
#   OUT_DIR        where evidence files go (default /tmp/netscope-device)
#
# This collects evidence; it asserts only that exactly one authorized device is present and that
# the APK installs. It never changes phone settings beyond granting this app its own permissions.
set -euo pipefail

: "${APK:?set APK to the path of app-debug.apk}"
[[ -f "$APK" ]] || { echo "APK not found: $APK" >&2; exit 2; }
ADB_BIN="${ADB:-adb}"
WATCH="${WATCH_SECONDS:-60}"
OUT="${OUT_DIR:-/tmp/netscope-device}"
PKG=org.netscope.ngfw
mkdir -p "$OUT"

adb() {
    if [[ -n "${ADB_SERIAL:-}" ]]; then "$ADB_BIN" -s "$ADB_SERIAL" "$@"; else "$ADB_BIN" "$@"; fi
}
# Best effort: record the command's output and its exit status, never abort the probe.
note() {
    local file="$1"
    shift
    { echo "\$ $*"; "$@" 2>&1; echo "[exit $?]"; } >>"$OUT/$file" || true
}

"$ADB_BIN" devices -l | tee "$OUT/devices.txt"
count=$("$ADB_BIN" devices | awk 'NR>1 && $2=="device"' | wc -l)
if [[ -z "${ADB_SERIAL:-}" && "$count" -ne 1 ]]; then
    echo "Expected exactly one authorized device, found $count (set ADB_SERIAL, or fix 'unauthorized')." >&2
    exit 3
fi

echo "== device"
for prop in ro.product.manufacturer ro.product.model ro.build.version.release ro.build.version.sdk ro.product.cpu.abi; do
    printf '%s=%s\n' "$prop" "$(adb shell getprop "$prop" | tr -d '\r')" | tee -a "$OUT/device.txt"
done
note battery-before.txt adb shell dumpsys battery

echo "== install"
adb install -r -d "$APK" | tee "$OUT/install.txt"
grep -q Success "$OUT/install.txt"

echo "== permissions (this app's own; failures are recorded, not fatal)"
note permissions.txt adb shell pm grant "$PKG" android.permission.POST_NOTIFICATIONS
note permissions.txt adb shell pm grant "$PKG" android.permission.READ_PHONE_STATE
note permissions.txt adb shell appops set "$PKG" ACTIVATE_VPN allow

echo "== launch and observe for ${WATCH}s (connect the VPN on the phone now)"
adb logcat -c || true
adb shell am start -n "$PKG/.MainActivity" | tee "$OUT/launch.txt"
sleep "$WATCH"

echo "== evidence"
adb logcat -d -v threadtime >"$OUT/logcat-all.txt" || true
pid=$(adb shell pidof "$PKG" | tr -d '\r' || true)
echo "pid=${pid:-none}" | tee "$OUT/process.txt"
if [[ -n "$pid" ]]; then
    grep -E " ${pid} " "$OUT/logcat-all.txt" >"$OUT/logcat-app.txt" || true
fi
grep -iE "netscope|AndroidRuntime|FATAL|vpn" "$OUT/logcat-all.txt" >"$OUT/logcat-interesting.txt" || true
note meminfo.txt adb shell dumpsys meminfo "$PKG"
note cpuinfo.txt adb shell dumpsys cpuinfo
note connectivity-vpn.txt adb shell "dumpsys connectivity | grep -iE 'vpn|netscope'"
note interfaces.txt adb shell "ip -o addr show"
note routes.txt adb shell "ip route show table all"
note battery-after.txt adb shell dumpsys battery

echo "== summary"
{
    echo "device: $(grep -E 'ro.product.model' "$OUT/device.txt")"
    if [[ -n "$pid" ]]; then echo "app running: yes (pid $pid)"; else echo "app running: no"; fi
    echo "fatal crashes in log: $(grep -c 'FATAL EXCEPTION' "$OUT/logcat-all.txt" || true)"
    echo "vpn lines in connectivity dump: $(grep -ci vpn "$OUT/connectivity-vpn.txt" || true)"
    echo "battery level before/after: $(grep -m1 ' level:' "$OUT/battery-before.txt" | tr -d ' ') / $(grep -m1 ' level:' "$OUT/battery-after.txt" | tr -d ' ')"
} | tee "$OUT/summary.txt"
echo "evidence written to $OUT"
