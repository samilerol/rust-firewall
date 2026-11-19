#!/usr/bin/env bash
# One-time setup for the "Android device over Tailscale" workflow, run on YOUR computer with the
# phone connected by USB (see docs/ANDROID_DEVICE_CI.md). It:
#   1. checks adb/gh/base64 and that exactly one phone is authorized over USB,
#   2. turns on adb over TCP (adb tcpip 5555),
#   3. stores the secrets ADB_KEY and TS_AUTHKEY and the variable PHONE_TAILSCALE_HOST in the repo
#      through the GitHub CLI (secret values go over stdin and are never printed),
#   4. optionally starts the workflow.
#
# You still do by hand: install Tailscale on the phone and sign in, tap "Allow USB debugging" on the
# phone, and create an ephemeral reusable auth key in the Tailscale admin console.
#
#   tools/setup_device_ci.sh                      # interactive
#   PHONE_TAILSCALE_HOST=100.101.102.103 TS_AUTHKEY=tskey-... tools/setup_device_ci.sh --run
#
# Environment: REPO (default: the current repo's owner/name via gh), ADB, ADB_SERIAL,
#              PHONE_TAILSCALE_HOST, TS_AUTHKEY, ADB_KEY_FILE (default ~/.android/adbkey),
#              ADB_PORT (default 5555).
set -euo pipefail

RUN=0
[[ "${1:-}" == "--run" ]] && RUN=1

ADB_BIN="${ADB:-adb}"
# Resolve to a path now: the wrapper function below is also called adb and must not recurse into itself.
ADB_BIN="$(command -v "$ADB_BIN" || true)"
[[ -n "$ADB_BIN" ]] || { echo "Missing tool: adb (install Android platform-tools)" >&2; exit 2; }
PORT="${ADB_PORT:-5555}"
KEY_FILE="${ADB_KEY_FILE:-$HOME/.android/adbkey}"

need() { command -v "$1" >/dev/null 2>&1 || { echo "Missing tool: $1 ($2)" >&2; exit 2; }; }
need "$ADB_BIN" "install Android platform-tools"
need gh "install the GitHub CLI and run 'gh auth login'"
need base64 "coreutils"

gh auth status >/dev/null 2>&1 || { echo "gh is not logged in: run 'gh auth login' first." >&2; exit 2; }
REPO="${REPO:-$(gh repo view --json nameWithOwner --jq .nameWithOwner 2>/dev/null || true)}"
[[ -n "$REPO" ]] || { echo "Could not determine the repository; set REPO=owner/name." >&2; exit 2; }
echo "Repository: $REPO"

adb() {
    if [[ -n "${ADB_SERIAL:-}" ]]; then "$ADB_BIN" -s "$ADB_SERIAL" "$@"; else "$ADB_BIN" "$@"; fi
}

echo "== phone over USB"
"$ADB_BIN" devices -l
authorized=$("$ADB_BIN" devices | awk 'NR>1 && $2=="device"' | wc -l)
if "$ADB_BIN" devices | awk 'NR>1 && $2=="unauthorized"' | grep -q .; then
    echo "The phone says 'unauthorized': unlock it and tap 'Allow USB debugging' (tick 'Always allow')." >&2
    exit 3
fi
if [[ -z "${ADB_SERIAL:-}" && "$authorized" -ne 1 ]]; then
    echo "Expected exactly one authorized phone, found $authorized (set ADB_SERIAL if several)." >&2
    exit 3
fi

[[ -f "$KEY_FILE" ]] || { echo "adb key not found at $KEY_FILE (connect the phone once with adb so it is created)." >&2; exit 4; }

PHONE="${PHONE_TAILSCALE_HOST:-}"
if [[ -z "$PHONE" ]]; then
    read -r -p "Phone's Tailscale IP (100.x.y.z, shown in the Tailscale app): " PHONE
fi
# Tailscale addresses are in 100.64.0.0/10 (100.64.* through 100.127.*).
if ! [[ "$PHONE" =~ ^100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
    echo "'$PHONE' does not look like a Tailscale IP (100.64.0.0 - 100.127.255.255)." >&2
    exit 5
fi

KEY="${TS_AUTHKEY:-}"
if [[ -z "$KEY" ]]; then
    read -r -s -p "Tailscale auth key (ephemeral + reusable; input hidden): " KEY
    echo
fi
[[ "$KEY" == tskey-* ]] || { echo "That does not look like a Tailscale auth key (expected 'tskey-...')." >&2; exit 5; }

echo "== adb over TCP on port $PORT"
adb tcpip "$PORT"
echo "(Unplugging is now safe. After testing, switch it off again with: adb usb)"

echo "== repository secrets and variable"
# Values travel over stdin so they never appear in the process list or the terminal.
base64 <"$KEY_FILE" | tr -d '\n' | gh secret set ADB_KEY --repo "$REPO"
printf '%s' "$KEY" | gh secret set TS_AUTHKEY --repo "$REPO"
gh variable set PHONE_TAILSCALE_HOST --repo "$REPO" --body "$PHONE"
[[ "$PORT" == 5555 ]] || gh variable set PHONE_ADB_PORT --repo "$REPO" --body "$PORT"
echo "Stored: secret ADB_KEY, secret TS_AUTHKEY, variable PHONE_TAILSCALE_HOST=$PHONE"

if [[ "$RUN" == 1 ]]; then
    echo "== starting the workflow"
    gh workflow run android-device.yml --repo "$REPO" --field watch_seconds=90
    echo "Open the Actions tab and connect the VPN in the app on the phone within the 90 s window."
else
    echo "Done. Start it with:  gh workflow run android-device.yml --repo $REPO --field watch_seconds=90"
fi
