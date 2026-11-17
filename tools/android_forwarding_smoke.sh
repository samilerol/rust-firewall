#!/usr/bin/env bash
set -euo pipefail
sdk="$ANDROID_HOME"
sdkmanager="$sdk/cmdline-tools/latest/bin/sdkmanager"
image='system-images;android-35;default;x86_64'
"$sdkmanager" emulator "$image"
echo no | "$sdk/cmdline-tools/latest/bin/avdmanager" create avd --force --name netscope-preview --package "$image"
sudo chmod a+rw /dev/kvm
"$sdk/emulator/emulator" -avd netscope-preview -no-window -no-audio -no-boot-anim -no-snapshot -gpu swiftshader_indirect > /tmp/netscope-emulator.log 2>&1 &
emulator_pid=$!
trap 'kill "$emulator_pid" 2>/dev/null || true' EXIT
adb="$sdk/platform-tools/adb"
timeout 240 "$adb" wait-for-device
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
sudo python3 - <<'PY' &
import socketserver
import threading

class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(3)
        data = self.request.recv(1)
        if data:
            self.request.sendall(data)

with socketserver.ThreadingTCPServer(("127.0.0.1", 80), Echo) as web, \
     socketserver.ThreadingTCPServer(("127.0.0.1", 8080), Echo) as blocked:
    threading.Thread(target=web.serve_forever, daemon=True).start()
    blocked.serve_forever()
PY
echo_pid=$!
trap 'kill "$emulator_pid" 2>/dev/null || true; sudo kill "$echo_pid" 2>/dev/null || true' EXIT
timeout 90 "$adb" shell am instrument -w org.netscope.ngfw.test/org.netscope.ngfw.ForwardingSmoke | tee /tmp/netscope-forwarding-emulator.log
rg -q 'NETSCOPE_FORWARDING_SMOKE_PASS' /tmp/netscope-forwarding-emulator.log
