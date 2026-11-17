#!/usr/bin/env bash
set -euo pipefail
sdk="$ANDROID_HOME"
sdkmanager="$sdk/cmdline-tools/latest/bin/sdkmanager"
export ANDROID_USER_HOME="$HOME/.android"
export ANDROID_AVD_HOME="$ANDROID_USER_HOME/avd"
mkdir -p "$ANDROID_AVD_HOME"
image='system-images;android-35;default;x86_64'
"$sdkmanager" platform-tools emulator "$image"
echo no | "$sdk/cmdline-tools/latest/bin/avdmanager" create avd --force --name netscope-preview --package "$image"
test -f "$ANDROID_AVD_HOME/netscope-preview.ini"
test -c /dev/kvm
sudo chmod a+rw /dev/kvm
"$sdk/emulator/emulator" -accel-check
adb="$sdk/platform-tools/adb"
"$adb" start-server
"$sdk/emulator/emulator" -avd netscope-preview -no-window -no-audio -no-boot-anim -no-snapshot -gpu swiftshader_indirect > /tmp/netscope-emulator.log 2>&1 &
emulator_pid=$!
trap 'kill "$emulator_pid" 2>/dev/null || true' EXIT
for _ in {1..120}; do
    if ! kill -0 "$emulator_pid" 2>/dev/null; then
        cat /tmp/netscope-emulator.log
        exit 1
    fi
    if "$adb" get-state 2>/dev/null | grep -qx device; then break; fi
    sleep 2
done
"$adb" get-state | grep -qx device
for _ in {1..120}; do
    if [[ "$("$adb" shell getprop sys.boot_completed | tr -d '\r')" == 1 ]]; then break; fi
    sleep 2
done
[[ "$("$adb" shell getprop sys.boot_completed | tr -d '\r')" == 1 ]]
"$adb" shell input keyevent 82
"$adb" install android/app/build/outputs/apk/debug/app-debug.apk
"$adb" install android/app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk
"$adb" shell pm grant org.netscope.ngfw android.permission.POST_NOTIFICATIONS
"$adb" shell appops set org.netscope.ngfw ACTIVATE_VPN allow
# Redirect only the preview resolver on this ephemeral runner to the local DNS fixture.
# The installed APK retains the same resolver and policy as the phone artifact.
sudo iptables -t nat -A OUTPUT -p udp -d 1.1.1.1/32 --dport 53 -j REDIRECT --to-ports 53
sudo iptables -t nat -A OUTPUT -p tcp -d 1.1.1.1/32 --dport 53 -j REDIRECT --to-ports 53
sudo python3 tools/android_smoke_endpoints.py >/tmp/netscope-emulator-endpoints.log 2>&1 &
echo_pid=$!
cleanup() {
    kill "$emulator_pid" 2>/dev/null || true
    sudo kill "$echo_pid" 2>/dev/null || true
    for protocol in udp tcp; do
        sudo iptables -t nat -D OUTPUT -p "$protocol" -d 1.1.1.1/32 --dport 53 -j REDIRECT --to-ports 53
    done
}
trap cleanup EXIT
for _ in {1..50}; do
    if grep -q NETSCOPE_ENDPOINTS_READY /tmp/netscope-emulator-endpoints.log; then break; fi
    sleep 0.1
done
grep -q NETSCOPE_ENDPOINTS_READY /tmp/netscope-emulator-endpoints.log || { cat /tmp/netscope-emulator-endpoints.log; exit 1; }
if ! timeout 120 "$adb" shell am instrument -w org.netscope.ngfw.test/org.netscope.ngfw.ForwardingSmoke | tee /tmp/netscope-forwarding-emulator.log ||
   ! grep -q 'NETSCOPE_FORWARDING_SMOKE_PASS' /tmp/netscope-forwarding-emulator.log; then
    "$adb" logcat -d -s AndroidRuntime ActivityManager Vpn ConnectivityService
    "$adb" shell dumpsys activity services org.netscope.ngfw
    exit 1
fi

"$adb" shell am start -W -n org.netscope.ngfw/.MainActivity
"$adb" shell uiautomator dump /sdcard/netscope-home.xml >/dev/null
"$adb" exec-out screencap -p >/tmp/netscope-home.png
