# Real-phone checks from GitHub Actions (Tailscale + adb)

The "Android device over Tailscale" workflow (`.github/workflows/android-device.yml`) lets a GitHub-hosted runner reach **your own phone** over the internet and run `tools/android_device_probe.sh` against it: install the latest preview APK from CI, launch it, observe for a window, and upload evidence (device info, `logcat`, `dumpsys meminfo/cpuinfo/connectivity`, interfaces and routes, battery level before and after). The same script works locally over USB: `APK=app-debug.apk tools/android_device_probe.sh`.

It is **manual only** (`workflow_dispatch`); it never runs on pull requests. It collects evidence; it is not a pass/fail test of firewall behavior. The emulator smoke remains the automated behavioral test.

## How the phone becomes reachable

A phone on mobile data sits behind carrier NAT (an address like `100.64.x.x`), so a runner cannot connect to it directly. Both the phone and the runner join the same private Tailscale network (the runner as an ephemeral node, removed when the job ends), and the runner talks to the phone's `adbd` over TCP port 5555.

## One-time setup (you do this; Actions cannot)

1. **Phone**: install the Tailscale app, sign in with the account you will use for the tailnet, and note the phone's Tailscale IP (`100.x.y.z`).
2. **Enable adb over TCP** (once per phone reboot): connect the phone to your computer by USB with USB debugging on, accept the computer's key on the phone ("always allow"), then run `adb tcpip 5555`. You can unplug afterwards. Wireless debugging is *not* needed and requires Wi-Fi; this uses classic `adb tcpip`.
3. **Tailscale auth key**: in the Tailscale admin console create an auth key that is **ephemeral**, **reusable** and expires soon; add it as the repository secret `TS_AUTHKEY`.
4. **adb key**: the phone only accepts computers whose key it has authorized. Copy the key you authorized in step 2: `base64 -w0 ~/.android/adbkey` (macOS: `base64 -i ~/.android/adbkey | tr -d '\n'`) and store the output as the repository secret `ADB_KEY`.
5. **Repository variable** `PHONE_TAILSCALE_HOST` = the phone's Tailscale IP (an IP is more reliable than a MagicDNS name on the runner). Optional variable `PHONE_ADB_PORT` if you used a port other than 5555.
6. **Run it**: Actions, "Android device over Tailscale", Run workflow. Connect the VPN in the app on the phone during the observation window to capture live traffic behavior. The evidence is uploaded as `android-device-evidence` and summarized on the run page.

If a secret or variable is missing the first step fails with a message saying which one.

## Security: read this before enabling

- **`adb` is full control of the phone** (apps, data, screen). Prefer a spare or test phone. `ADB_KEY` is the credential that proves "this computer is trusted": anyone who can read the secret can control the phone while it is reachable on your tailnet. Anyone with write access to this repository can edit the workflow and exfiltrate repository secrets, so keep the repository's write access to people you trust.
- Keep the Tailscale ACL tight if the tailnet has other devices (allow only the CI node to reach the phone's port 5555) and use an ephemeral, short-lived auth key.
- `adb tcpip` listens on every interface of the phone, including Wi-Fi networks you join. Disable it when finished: `adb usb`, or reboot the phone.
- The workflow downloads the APK from CI artifacts and installs it with `adb install -r -d`; it grants only this app's own permissions and never changes other phone settings. `appops set ... ACTIVATE_VPN allow` may be refused by some Xiaomi/HyperOS builds; the result is recorded in `permissions.txt`.
- The Tailscale step uses `tailscale/github-action` pinned by commit SHA (v4.4.0). It is a third-party dependency of this repository's CI; update it deliberately.

## Limits (not verified)

- The setup was not run against a real phone when it was written: no phone or Tailscale account was available. The probe script was exercised against a fake `adb`, and the workflow YAML was only parsed. Expect to fix small things on the first real run (for example deriving `adbkey.pub` from `adbkey`, MagicDNS, MIUI permission prompts).
- Mobile-data traffic costs (the APK is tens of MB) and the connection drops if the phone sleeps or reboots.
- Only adb is carried: `fastboot`/bootloader operations are not possible this way.
- Evidence is a point-in-time observation, not a battery or performance benchmark; battery level before/after is a coarse hint.
