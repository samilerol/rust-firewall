package org.netscope.ngfw;

import java.util.Locale;

/** The recognizer can request only an exact, named UI action. */
enum VoiceCommand {
    REPORT, APPS, STATUS, CONNECT, DISCONNECT, UNKNOWN;

    static VoiceCommand parse(String speech) {
        if (speech == null || speech.length() > 80) return UNKNOWN;
        String normalized = speech.trim().replaceFirst("[.!?]+$", "").trim()
            .replaceAll("\\s+", " ").toLowerCase(Locale.ROOT).replace("i\u0307", "i");
        return switch (normalized) {
            case "rapor", "trafik raporu", "report", "traffic report" -> REPORT;
            case "uygulamalar", "uygulamaları göster", "apps", "show apps" -> APPS;
            case "durum", "vpn durumu", "status", "vpn status" -> STATUS;
            case "bağlan", "connect" -> CONNECT;
            case "bağlantıyı kes", "bağlantiyi kes", "disconnect" -> DISCONNECT;
            default -> UNKNOWN;
        };
    }
}
