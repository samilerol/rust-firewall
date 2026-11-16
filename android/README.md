# NetScope diagnostic VPN

Development-only Android app. **Starting it discards routed traffic; it has no forwarding.** Explicit VPN consent and a traffic-blocking warning precede startup. Stop through the app or foreground notification. It does not support always-on operation or claim protection while stopped.

See ../docs/ANDROID_INTEGRATION.md for build steps, FD/JNI ownership, limitations and device-test gates. CI builds debug APKs for arm64-v8a and x86_64, with the Rust libraries inside the APK. Download from the Android diagnostic build job's artifact only after successful CI; artifacts expire in seven days. Installing/starting on a device has not been tested by this development environment.
