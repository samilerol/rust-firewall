#!/usr/bin/env python3
"""Guard the Android *diagnostic* VPN manifest against accidental exposure.

This is a source-level regression check, NOT proof of device-level blocking.
"""
from pathlib import Path
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
ANDROID = "{http://schemas.android.com/apk/res/android}"
manifest = ET.parse(ROOT / "android/app/src/main/AndroidManifest.xml").getroot()
application = manifest.find("application")
assert application is not None, "Missing Android application"
assert application.get(ANDROID + "allowBackup") == "false", "Backup must stay disabled"

services = application.findall("service")
assert len(services) == 1, "Unexpected service: review manifest policy"
service = services[0]
assert service.get(ANDROID + "name") == ".DiagnosticVpnService", "Unexpected VPN service"
assert service.get(ANDROID + "exported") == "false", "VPN service must not be exported"
assert service.get(ANDROID + "permission") == "android.permission.BIND_VPN_SERVICE"
assert service.get(ANDROID + "foregroundServiceType") == "specialUse"

actions = [a.get(ANDROID + "name") for a in service.findall("./intent-filter/action")]
assert actions == ["android.net.VpnService"], "Unexpected service intent filters"
always_on = service.findall("meta-data")
assert len(always_on) == 1
assert always_on[0].get(ANDROID + "name") == "android.net.VpnService.SUPPORTS_ALWAYS_ON"
assert always_on[0].get(ANDROID + "value") == "false", "Always-on not yet supported"

code = (ROOT / "android/app/src/main/java/org/netscope/ngfw/DiagnosticVpnService.java").read_text()
assert "No forwarding." in code, "Diagnostic user warning changed"
assert "NativeCore.inspect(buffer, count)" in code, "Diagnostic native path removed"
assert "input.read(buffer)" in code, "Diagnostic read loop changed"
assert "new Builder()" in code and ".establish()" in code
assert ".addRoute(\"0.0.0.0\", 0)" in code
assert ".addRoute(\"::\", 0)" in code
assert "START_NOT_STICKY" in code
assert "TunPacketWriter" not in code, "Diagnostic must not attach TUN egress writer"
assert "AutoCloseOutputStream" not in code, "Diagnostic cannot create TUN output"


print("Android diagnostic source safeguards: PASS (not a device or security audit)")
