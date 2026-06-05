package com.monster.cybershield.core;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.os.Build;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class FeatureExtractor {
    private static final Pattern URL_PATTERN = Pattern.compile("(https?://[^\\s]+|www\\.[^\\s]+|[a-z0-9.-]+\\.[a-z]{2,}[^\\s]*)", Pattern.CASE_INSENSITIVE);

    private FeatureExtractor() {
    }

    public static float[] socialText(String text) {
        float[] features = new float[2530];
        String normalized = safe(text).toLowerCase(Locale.US);
        for (String token : normalized.split("[^a-z0-9]+")) {
            if (token.length() > 1) {
                features[Math.abs(token.hashCode()) % 2500] += 1.0f;
            }
        }
        int base = 2500;
        features[base] = normalized.length();
        features[base + 1] = wordCount(normalized);
        features[base + 2] = containsAny(normalized, "urgent", "immediate", "now", "acil", "hemen", "deadline");
        features[base + 3] = containsAny(normalized, "blocked", "suspended", "fraud", "hack", "kapat", "bloke", "ceza");
        features[base + 4] = containsAny(normalized, "winner", "prize", "free", "bonus", "hediye", "kazand");
        features[base + 5] = containsAny(normalized, "bank", "support", "admin", "security", "banka", "destek");
        features[base + 6] = containsAny(normalized, "password", "login", "verify", "otp", "sifre", "dogrula");
        features[base + 7] = countUrls(normalized);
        features[base + 8] = countChar(text, '!');
        features[base + 9] = countChar(text, '$');
        return features;
    }

    public static float[] socialUrl(String url) {
        float[] features = new float[48];
        Uri uri = Uri.parse(ensureUrl(url));
        String host = safe(uri.getHost()).toLowerCase(Locale.US);
        String path = safe(uri.getPath()).toLowerCase(Locale.US);
        String query = safe(uri.getQuery()).toLowerCase(Locale.US);
        String all = safe(url).toLowerCase(Locale.US);
        features[0] = countChar(host, '.');
        features[1] = Math.max(0, host.split("\\.").length - 2);
        features[2] = path.split("/").length;
        features[3] = all.length();
        features[4] = countChar(all, '-');
        features[5] = countChar(host, '-');
        features[6] = all.contains("@") ? 1 : 0;
        features[7] = all.contains("~") ? 1 : 0;
        features[8] = countChar(all, '_');
        features[9] = countChar(all, '%');
        features[10] = query.isEmpty() ? 0 : query.split("&").length;
        features[11] = countChar(all, '&');
        features[12] = countChar(all, '#');
        features[13] = digitCount(all);
        features[14] = all.startsWith("https://") ? 0 : 1;
        features[15] = containsAny(all, "login", "verify", "secure", "account", "update", "bank");
        features[16] = isIp(host);
        features[17] = containsAny(host, "paypal", "google", "apple", "bank", "banka");
        features[18] = containsAny(path, "paypal", "google", "apple", "bank", "banka");
        features[19] = host.contains("https") ? 1 : 0;
        features[20] = host.length();
        features[21] = path.length();
        features[22] = query.length();
        features[23] = all.contains("//") && all.indexOf("//") != all.lastIndexOf("//") ? 1 : 0;
        features[24] = containsAny(all, "secure", "account", "webscr", "login", "signin");
        for (int i = 25; i < features.length; i++) {
            features[i] = ((all.hashCode() >>> (i % 16)) & 1);
        }
        return features;
    }

    public static float[] phishingHtml(String htmlOrUrl) {
        float[] features = new float[40];
        String text = safe(htmlOrUrl).toLowerCase(Locale.US);
        features[0] = text.length();
        features[1] = countUrls(text);
        features[2] = containsAny(text, "<form", "password", "login", "signin");
        features[3] = containsAny(text, "http://", "mixed-content");
        features[4] = containsAny(text, "iframe", "<frame");
        features[5] = containsAny(text, "onclick", "onmouseover", "javascript:");
        features[6] = containsAny(text, "verify", "account", "bank", "wallet");
        for (int i = 7; i < features.length; i++) {
            features[i] = ((text.hashCode() >>> (i % 16)) & 1);
        }
        return features;
    }

    public static float[] apk(Context context, String packageName) {
        float[] features = new float[9503];
        try {
            PackageManager pm = context.getPackageManager();
            int flags = PackageManager.GET_PERMISSIONS
                    | PackageManager.GET_ACTIVITIES
                    | PackageManager.GET_SERVICES
                    | PackageManager.GET_RECEIVERS
                    | PackageManager.GET_PROVIDERS;
            if (Build.VERSION.SDK_INT >= 28) {
                flags |= PackageManager.GET_SIGNING_CERTIFICATES;
            }
            PackageInfo info = pm.getPackageInfo(packageName, flags);
            ApplicationInfo app = info.applicationInfo;
            String key = packageName + "|" + app.uid + "|" + info.firstInstallTime + "|" + info.lastUpdateTime + "|" + app.sourceDir;
            fillHash(features, key, 128, features.length);
            features[0] = (app.flags & ApplicationInfo.FLAG_SYSTEM) == 0 ? 1 : 0;
            features[1] = (app.flags & ApplicationInfo.FLAG_DEBUGGABLE) != 0 ? 1 : 0;
            features[2] = (app.flags & ApplicationInfo.FLAG_SYSTEM) != 0 ? 1 : 0;
            features[3] = (app.flags & ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0 ? 1 : 0;
            features[4] = (app.flags & ApplicationInfo.FLAG_USES_CLEARTEXT_TRAFFIC) != 0 ? 1 : 0;
            features[5] = app.enabled ? 1 : 0;
            features[6] = info.requestedPermissions == null ? 0 : info.requestedPermissions.length;
            features[7] = countDangerousPermissions(info.requestedPermissions);
            features[8] = count(info.activities) + count(info.services) + count(info.receivers) + count(info.providers);
            features[9] = count(info.services);
            features[10] = count(info.receivers);
            features[11] = count(info.providers);
            features[12] = count(info.activities);
            features[13] = Build.VERSION.SDK_INT >= 24 ? app.minSdkVersion : 0;
            features[14] = app.targetSdkVersion;
            features[15] = info.firstInstallTime > 0 ? Math.min(3650f, (System.currentTimeMillis() - info.firstInstallTime) / 86_400_000f) : 0f;
            features[16] = info.lastUpdateTime > info.firstInstallTime ? Math.min(3650f, (info.lastUpdateTime - info.firstInstallTime) / 86_400_000f) : 0f;
            features[17] = packageName.length();
            features[18] = countChar(packageName, '.');
            features[19] = digitCount(packageName);
            addPermissionFeatures(features, info.requestedPermissions);
            addComponentFeatures(features, info.activities, 3000);
            addComponentFeatures(features, info.services, 4600);
            addComponentFeatures(features, info.receivers, 6200);
            addComponentFeatures(features, info.providers, 7800);
        } catch (Exception e) {
            fillHash(features, packageName, 0, features.length);
        }
        return features;
    }

    public static float[] network(PacketInfo packet, int size) {
        float[] features = new float[size];
        features[0] = packet.totalLength;
        features[1] = packet.protocol;
        features[2] = packet.sourcePort;
        features[3] = packet.destinationPort;
        features[4] = packet.isDns ? 1 : 0;
        features[5] = packet.isDohLike ? 1 : 0;
        features[6] = packet.queryName.length();
        features[7] = packet.queryName.split("\\.").length;
        features[8] = digitCount(packet.queryName);
        features[9] = packet.queryName.contains("-") ? 1 : 0;
        fillHash(features, packet.sourceAddress + packet.destinationAddress + packet.queryName, 10, features.length);
        return features;
    }

    public static float[] network(FlowStats flow, int size) {
        float[] features = new float[size];
        features[0] = flow.byteCount;
        features[1] = flow.packetCount;
        features[2] = flow.key.protocol;
        features[3] = flow.key.sourcePort;
        features[4] = flow.key.destinationPort;
        features[5] = flow.durationMs();
        features[6] = flow.packetsPerSecond();
        features[7] = flow.bytesPerSecond();
        features[8] = flow.averagePacketBytes();
        features[9] = flow.minPacketBytes == Integer.MAX_VALUE ? 0 : flow.minPacketBytes;
        features[10] = flow.maxPacketBytes;
        features[11] = flow.tcpPackets;
        features[12] = flow.udpPackets;
        features[13] = flow.dnsPackets;
        features[14] = flow.dohPackets;
        features[15] = flow.synPackets;
        features[16] = flow.ackPackets;
        features[17] = flow.finPackets;
        features[18] = flow.rstPackets;
        features[19] = flow.lastQueryName.length();
        features[20] = flow.lastQueryName.isEmpty() ? 0 : flow.lastQueryName.split("\\.").length;
        features[21] = digitCount(flow.lastQueryName);
        features[22] = flow.lastQueryName.contains("-") ? 1 : 0;
        fillHash(features, flow.key.sourceAddress + flow.key.destinationAddress + flow.lastQueryName, 23, features.length);
        return features;
    }

    public static float[] pqcSession(String value) {
        float[] features = new float[32];
        String text = safe(value).toLowerCase(Locale.US);
        features[0] = text.length();
        features[1] = containsAny(text, "kyber", "dilithium", "pqc", "post-quantum");
        features[2] = containsAny(text, "tls", "handshake", "cipher");
        fillHash(features, text, 3, features.length);
        return features;
    }

    public static PacketInfo parsePacket(byte[] data, int length) {
        PacketInfo packet = new PacketInfo();
        if (length < 20) {
            return packet;
        }
        int version = (data[0] >> 4) & 0x0F;
        if (version != 4) {
            return packet;
        }
        int ihl = (data[0] & 0x0F) * 4;
        if (length < ihl + 4) {
            return packet;
        }
        packet.totalLength = unsignedShort(data, 2);
        packet.protocol = data[9] & 0xFF;
        packet.sourceAddress = ipv4(data, 12);
        packet.destinationAddress = ipv4(data, 16);
        if (packet.protocol == 6 || packet.protocol == 17) {
            packet.sourcePort = unsignedShort(data, ihl);
            packet.destinationPort = unsignedShort(data, ihl + 2);
        }
        if (packet.protocol == 6 && length >= ihl + 20) {
            int tcpHeaderLength = ((data[ihl + 12] >> 4) & 0x0F) * 4;
            packet.tcpFlags = data[ihl + 13] & 0x3F;
            packet.payloadLength = Math.max(0, packet.totalLength - ihl - tcpHeaderLength);
        } else if (packet.protocol == 17 && length >= ihl + 8) {
            packet.payloadLength = Math.max(0, unsignedShort(data, ihl + 4) - 8);
        } else {
            packet.payloadLength = Math.max(0, packet.totalLength - ihl);
        }
        packet.isDns = packet.protocol == 17 && (packet.sourcePort == 53 || packet.destinationPort == 53);
        packet.isDohLike = packet.protocol == 6 && (packet.sourcePort == 443 || packet.destinationPort == 443);
        if (packet.isDns) {
            int dnsOffset = ihl + 8;
            packet.queryName = parseDnsName(data, length, dnsOffset + 12);
        }
        return packet;
    }

    private static String parseDnsName(byte[] data, int length, int offset) {
        StringBuilder builder = new StringBuilder();
        int pos = offset;
        int guard = 0;
        while (pos < length && guard++ < 20) {
            int labelLen = data[pos++] & 0xFF;
            if (labelLen == 0) {
                break;
            }
            if ((labelLen & 0xC0) != 0 || pos + labelLen > length) {
                break;
            }
            if (builder.length() > 0) {
                builder.append('.');
            }
            builder.append(new String(data, pos, labelLen, StandardCharsets.US_ASCII));
            pos += labelLen;
        }
        return builder.toString();
    }

    private static int unsignedShort(byte[] data, int offset) {
        return ByteBuffer.wrap(data, offset, 2).getShort() & 0xFFFF;
    }

    private static String ipv4(byte[] data, int offset) {
        return (data[offset] & 0xFF) + "." + (data[offset + 1] & 0xFF) + "." + (data[offset + 2] & 0xFF) + "." + (data[offset + 3] & 0xFF);
    }

    private static void fillHash(float[] features, String value, int start, int end) {
        String text = safe(value);
        for (int i = start; i < end; i++) {
            int h = (text + "|" + i).hashCode();
            features[i] = ((h & 0xFF) / 255.0f);
        }
    }

    private static int count(Object[] values) {
        return values == null ? 0 : values.length;
    }

    private static int countDangerousPermissions(String[] permissions) {
        if (permissions == null) {
            return 0;
        }
        int count = 0;
        for (String permission : permissions) {
            String p = safe(permission).toLowerCase(Locale.US);
            if (p.contains("sms") || p.contains("contacts") || p.contains("location")
                    || p.contains("record_audio") || p.contains("camera") || p.contains("phone")
                    || p.contains("install") || p.contains("overlay") || p.contains("accessibility")) {
                count++;
            }
        }
        return count;
    }

    private static void addPermissionFeatures(float[] features, String[] permissions) {
        if (permissions == null) {
            return;
        }
        String joined = String.join("|", permissions).toLowerCase(Locale.US);
        features[24] = containsAny(joined, "receive_sms", "read_sms", "send_sms");
        features[25] = containsAny(joined, "read_contacts", "write_contacts");
        features[26] = containsAny(joined, "access_fine_location", "access_coarse_location");
        features[27] = containsAny(joined, "record_audio", "camera");
        features[28] = containsAny(joined, "read_phone_state", "call_phone");
        features[29] = containsAny(joined, "request_install_packages", "install_packages");
        features[30] = containsAny(joined, "system_alert_window", "draw_overlays");
        features[31] = containsAny(joined, "bind_accessibility_service", "accessibility");
        features[32] = containsAny(joined, "internet");
        features[33] = containsAny(joined, "wake_lock", "foreground_service");
        for (String permission : permissions) {
            int index = 256 + Math.abs(permission.hashCode()) % 2600;
            features[index] = 1.0f;
        }
    }

    private static void addComponentFeatures(float[] features, Object[] components, int start) {
        if (components == null) {
            return;
        }
        int span = Math.min(1500, features.length - start);
        if (span <= 0) {
            return;
        }
        for (Object component : components) {
            int index = start + Math.abs(String.valueOf(component).hashCode()) % span;
            features[index] = 1.0f;
        }
    }

    private static String ensureUrl(String value) {
        String url = safe(value).trim();
        if (!url.startsWith("http://") && !url.startsWith("https://")) {
            return "http://" + url;
        }
        return url;
    }

    public static String firstUrl(String text) {
        Matcher matcher = URL_PATTERN.matcher(safe(text));
        return matcher.find() ? matcher.group(1) : "";
    }

    private static int countUrls(String text) {
        Matcher matcher = URL_PATTERN.matcher(safe(text));
        int count = 0;
        while (matcher.find()) {
            count++;
        }
        return count;
    }

    private static int wordCount(String text) {
        String trimmed = safe(text).trim();
        return trimmed.isEmpty() ? 0 : trimmed.split("\\s+").length;
    }

    private static int countChar(String text, char needle) {
        int count = 0;
        for (int i = 0; i < safe(text).length(); i++) {
            if (text.charAt(i) == needle) {
                count++;
            }
        }
        return count;
    }

    private static int digitCount(String text) {
        int count = 0;
        for (int i = 0; i < safe(text).length(); i++) {
            if (Character.isDigit(text.charAt(i))) {
                count++;
            }
        }
        return count;
    }

    private static int isIp(String host) {
        return safe(host).matches("\\d{1,3}(\\.\\d{1,3}){3}") ? 1 : 0;
    }

    private static int containsAny(String text, String... needles) {
        String value = safe(text);
        for (String needle : needles) {
            if (value.contains(needle)) {
                return 1;
            }
        }
        return 0;
    }

    private static String safe(String value) {
        return value == null ? "" : value;
    }
}
