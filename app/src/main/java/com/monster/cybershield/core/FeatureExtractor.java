package com.monster.cybershield.core;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.os.Build;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.io.File;
import java.io.InputStream;
import java.util.Locale;
import java.util.Enumeration;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
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

    public static float[] stealthPhisher2025(String htmlOrUrl) {
        float[] features = new float[59];
        String raw = safe(htmlOrUrl).trim();
        String text = raw.toLowerCase(Locale.US);
        Uri uri = Uri.parse(ensureUrl(raw));
        String host = safe(uri.getHost()).toLowerCase(Locale.US);
        String path = safe(uri.getPath()).toLowerCase(Locale.US);
        String query = safe(uri.getQuery()).toLowerCase(Locale.US);
        String fragment = safe(uri.getFragment()).toLowerCase(Locale.US);
        String url = raw.isEmpty() ? "" : ensureUrl(raw);
        String tld = tld(host);
        int len = url.length();
        int letters = letterCount(url);
        int digits = digitCount(url);
        int otherSpecial = otherSpecialCount(url);
        int boolCount = 0;

        features[0] = len;
        features[1] = urlComplexity(url);
        features[2] = len == 0 ? 0 : (float) uniqueCharCount(url) / len;
        features[3] = host.length();
        features[4] = isIp(host);
        features[5] = tld.length();
        features[6] = letters;
        features[7] = len == 0 ? 0 : (float) letters / len;
        features[8] = digits;
        features[9] = len == 0 ? 0 : (float) digits / len;
        features[10] = countChar(url, '=');
        features[11] = countChar(url, '?');
        features[12] = countChar(url, '&');
        features[13] = otherSpecial;
        features[14] = len == 0 ? 0 : (float) otherSpecial / len;
        features[15] = countChar(url, '#');
        features[16] = Math.max(0, host.split("\\.").length - 2);
        features[17] = path.length() > 1 ? 1 : 0;
        features[18] = path.length();
        features[19] = query.length();
        features[20] = fragment.length();
        features[21] = url.contains("#") ? 1 : 0;
        features[22] = url.startsWith("https://") ? 1 : 0;
        features[23] = 0;
        features[24] = lineCount(raw);
        features[25] = longestLineLength(raw);
        features[26] = containsAny(text, "<title", "</title>") == 1 || !host.isEmpty() ? 1 : 0;
        features[27] = containsAny(text, "favicon", "shortcut icon", "apple-touch-icon") == 1 || url.startsWith("https://") ? 1 : 0;
        features[28] = containsAny(text, "robots", "noindex", "nofollow");
        features[29] = containsAny(text, "viewport", "responsive", "@media", "bootstrap");
        features[30] = containsAny(text, "redirect", "window.location", "http-equiv=\"refresh\"", "bit.ly", "tinyurl", "qrco.de", "t.co", "is.gd", "shorturl");
        features[31] = containsAny(text, "self.location", "location.href");
        features[32] = containsAny(text, "description", "og:description", "twitter:description");
        features[33] = containsAny(text, "popup", "window.open", "modal");
        features[34] = containsAny(text, "<iframe", " iframe");
        features[35] = containsAny(text, "<form") == 1 && containsAny(text, "action=\"http", "action='http") == 1 ? 1 : 0;
        features[36] = containsAny(text, "facebook", "twitter", "instagram", "linkedin", "youtube", "x.com");
        features[37] = containsAny(text, "submit", "type=\"submit", "type='submit");
        features[38] = containsAny(text, "type=\"hidden", "type='hidden", "display:none", "visibility:hidden");
        features[39] = containsAny(text, "password", "passwd", "pwd", "otp", "2fa");
        features[40] = containsAny(text, "bank", "banka", "iban", "swift", "account", "hesap");
        features[41] = containsAny(text, "payment", "pay", "card", "visa", "mastercard", "billing", "invoice", "odeme");
        features[42] = containsAny(text, "crypto", "wallet", "bitcoin", "ethereum", "usdt", "metamask", "seed phrase");
        features[43] = containsAny(text, "copyright", "(c)", "all rights reserved");
        features[44] = countOccurrences(text, "<img");
        features[45] = countOccurrences(text, ".css") + countOccurrences(text, "stylesheet");
        features[46] = countOccurrences(text, ".js") + countOccurrences(text, "<script");
        features[47] = countOccurrences(text, "href=\"/") + countOccurrences(text, "href='/");
        features[48] = countOccurrences(text, "href=\"#") + countOccurrences(text, "href=\"\"") + countOccurrences(text, "href=''");
        features[49] = countOccurrences(text, "href=\"http") + countOccurrences(text, "href='http");
        features[50] = countOccurrences(text, "popup") + countOccurrences(text, "window.open");
        features[51] = countOccurrences(text, "<iframe");
        for (int i = 22; i <= 43; i++) {
            boolCount += features[i] > 0 ? 1 : 0;
        }
        features[52] = boolCount;
        features[53] = shannonEntropy(url);
        features[54] = fractalApprox(url);
        features[55] = kolmogorovApprox(url);
        features[56] = countRegex(text, "\\b[0-9a-f]{16,}\\b");
        features[57] = countRegex(text, "\\b[A-Za-z0-9+/]{24,}={0,2}\\b");
        features[58] = phishingLikeliness(text, host, url);
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
            features[20] = app.sourceDir == null ? 0 : new File(app.sourceDir).length() / 1024.0f;
            features[21] = info.signatures == null ? 0 : info.signatures.length;
            features[22] = info.versionCode;
            features[23] = app.nativeLibraryDir == null ? 0 : new File(app.nativeLibraryDir).exists() ? 1 : 0;
            addPermissionFeatures(features, info.requestedPermissions);
            addSourceApkFeatures(features, app.sourceDir);
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
        packet.ipHeaderLength = ihl;
        int flagsAndFragment = unsignedShort(data, 6);
        packet.ipFlags = (flagsAndFragment >> 13) & 0x07;
        packet.fragmentOffset = flagsAndFragment & 0x1FFF;
        packet.ttl = data[8] & 0xFF;
        packet.protocol = data[9] & 0xFF;
        packet.sourceAddress = ipv4(data, 12);
        packet.destinationAddress = ipv4(data, 16);
        if (packet.protocol == 6 || packet.protocol == 17) {
            packet.sourcePort = unsignedShort(data, ihl);
            packet.destinationPort = unsignedShort(data, ihl + 2);
        }
        if (packet.protocol == 6 && length >= ihl + 20) {
            int tcpHeaderLength = ((data[ihl + 12] >> 4) & 0x0F) * 4;
            packet.transportHeaderLength = tcpHeaderLength;
            packet.tcpFlags = data[ihl + 13] & 0xFF;
            packet.tcpWindowSize = unsignedShort(data, ihl + 14);
            packet.payloadLength = Math.max(0, packet.totalLength - ihl - tcpHeaderLength);
        } else if (packet.protocol == 17 && length >= ihl + 8) {
            packet.transportHeaderLength = 8;
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

    private static void addSourceApkFeatures(float[] features, String sourceDir) {
        if (sourceDir == null || sourceDir.isEmpty()) {
            return;
        }
        File apkFile = new File(sourceDir);
        if (!apkFile.isFile()) {
            return;
        }
        int dexCount = 0;
        int nativeLibCount = 0;
        int assetCount = 0;
        int resCount = 0;
        int certCount = 0;
        int entryCount = 0;
        int suspiciousNameCount = 0;
        long compressedBytes = 0;
        long uncompressedBytes = 0;
        try (ZipFile zip = new ZipFile(apkFile)) {
            Enumeration<? extends ZipEntry> entries = zip.entries();
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                entryCount++;
                String name = entry.getName().toLowerCase(Locale.US);
                compressedBytes += Math.max(0L, entry.getCompressedSize());
                uncompressedBytes += Math.max(0L, entry.getSize());
                if (name.endsWith(".dex")) dexCount++;
                if (name.startsWith("lib/") && name.endsWith(".so")) nativeLibCount++;
                if (name.startsWith("assets/")) assetCount++;
                if (name.startsWith("res/")) resCount++;
                if (name.startsWith("meta-inf/") && (name.endsWith(".rsa") || name.endsWith(".dsa") || name.endsWith(".ec"))) certCount++;
                if (containsAny(name, "frida", "xposed", "substrate", "payload", "dropper", "sms", "bank", "crypto", "keylog", "root", "su") == 1) {
                    suspiciousNameCount++;
                }
                int index = 900 + Math.abs(name.hashCode()) % 1800;
                features[index] = 1.0f;
                if (entry.getSize() > 0) {
                    features[2700 + Math.abs((name + "|" + entry.getSize()).hashCode()) % 300] += 1.0f;
                }
            }
            features[40] = entryCount;
            features[41] = dexCount;
            features[42] = nativeLibCount;
            features[43] = assetCount;
            features[44] = resCount;
            features[45] = certCount;
            features[46] = suspiciousNameCount;
            features[47] = compressedBytes / 1024.0f;
            features[48] = uncompressedBytes / 1024.0f;
            features[49] = compressedBytes <= 0 ? 0 : (float) uncompressedBytes / Math.max(1L, compressedBytes);
            addDexStringSignals(features, zip);
        } catch (Exception ignored) {
            fillHash(features, apkFile.getAbsolutePath() + "|" + apkFile.length(), 900, 1200);
        }
    }

    private static void addDexStringSignals(float[] features, ZipFile zip) {
        int scannedBytes = 0;
        byte[] buffer = new byte[4096];
        try {
            Enumeration<? extends ZipEntry> entries = zip.entries();
            while (entries.hasMoreElements() && scannedBytes < 512 * 1024) {
                ZipEntry entry = entries.nextElement();
                String name = entry.getName().toLowerCase(Locale.US);
                if (!name.endsWith(".dex") && !name.endsWith(".xml") && !name.endsWith(".json") && !name.endsWith(".txt")) {
                    continue;
                }
                try (InputStream input = zip.getInputStream(entry)) {
                    int read;
                    while ((read = input.read(buffer)) != -1 && scannedBytes < 512 * 1024) {
                        scannedBytes += read;
                        String chunk = new String(buffer, 0, read, StandardCharsets.ISO_8859_1).toLowerCase(Locale.US);
                        if (containsAny(chunk, "sendtextmessage", "telephonymanager", "deviceadminreceiver", "accessibilityservice") == 1) features[50] = 1;
                        if (containsAny(chunk, "dexclassloader", "pathclassloader", "loadlibrary", "runtime.exec", "processbuilder") == 1) features[51] = 1;
                        if (containsAny(chunk, "getexternalstorage", "read_sms", "receive_sms", "contactscontract") == 1) features[52] = 1;
                        if (containsAny(chunk, "http://", "socket", "urlconnection", "okhttp", "retrofit") == 1) features[53] = 1;
                        if (containsAny(chunk, "su", "/system/bin/sh", "/system/xbin", "magisk", "busybox") == 1) features[54] = 1;
                        if (containsAny(chunk, "bitcoin", "wallet", "seed", "mnemonic", "metamask") == 1) features[55] = 1;
                        if (containsAny(chunk, "bank", "iban", "card", "otp", "password") == 1) features[56] = 1;
                        features[1200 + Math.abs(chunk.hashCode()) % 1400] += 0.1f;
                    }
                } catch (Exception ignored) {
                }
            }
            features[57] = scannedBytes / 1024.0f;
        } catch (Exception ignored) {
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
        String value = safe(text);
        for (int i = 0; i < value.length(); i++) {
            if (value.charAt(i) == needle) {
                count++;
            }
        }
        return count;
    }

    private static int digitCount(String text) {
        int count = 0;
        String value = safe(text);
        for (int i = 0; i < value.length(); i++) {
            if (Character.isDigit(value.charAt(i))) {
                count++;
            }
        }
        return count;
    }

    private static int letterCount(String text) {
        int count = 0;
        String value = safe(text);
        for (int i = 0; i < value.length(); i++) {
            if (Character.isLetter(value.charAt(i))) {
                count++;
            }
        }
        return count;
    }

    private static int uniqueCharCount(String text) {
        boolean[] seen = new boolean[128];
        int count = 0;
        String value = safe(text);
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            int index = c < 128 ? c : 0;
            if (!seen[index]) {
                seen[index] = true;
                count++;
            }
        }
        return count;
    }

    private static int otherSpecialCount(String text) {
        int count = 0;
        String value = safe(text);
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (!Character.isLetterOrDigit(c) && c != ':' && c != '/' && c != '.') {
                count++;
            }
        }
        return count;
    }

    private static float urlComplexity(String url) {
        String value = safe(url);
        if (value.isEmpty()) {
            return 0f;
        }
        return uniqueCharCount(value)
                + otherSpecialCount(value) * 1.25f
                + digitCount(value) * 0.35f
                + countChar(value, '-') * 0.75f
                + countChar(value, '_') * 0.75f;
    }

    private static int lineCount(String text) {
        String value = safe(text);
        if (value.isEmpty()) {
            return 0;
        }
        return value.split("\\r?\\n", -1).length;
    }

    private static int longestLineLength(String text) {
        int longest = 0;
        for (String line : safe(text).split("\\r?\\n", -1)) {
            longest = Math.max(longest, line.length());
        }
        return longest;
    }

    private static int countOccurrences(String text, String needle) {
        String value = safe(text);
        if (needle.isEmpty()) {
            return 0;
        }
        int count = 0;
        int index = 0;
        while ((index = value.indexOf(needle, index)) >= 0) {
            count++;
            index += needle.length();
        }
        return count;
    }

    private static int countRegex(String text, String regex) {
        Matcher matcher = Pattern.compile(regex).matcher(safe(text));
        int count = 0;
        while (matcher.find()) {
            count++;
        }
        return count;
    }

    private static float shannonEntropy(String text) {
        String value = safe(text);
        if (value.isEmpty()) {
            return 0f;
        }
        int[] counts = new int[256];
        for (int i = 0; i < value.length(); i++) {
            counts[value.charAt(i) & 0xFF]++;
        }
        double entropy = 0.0;
        for (int count : counts) {
            if (count > 0) {
                double p = (double) count / value.length();
                entropy -= p * (Math.log(p) / Math.log(2.0));
            }
        }
        return (float) entropy;
    }

    private static float fractalApprox(String text) {
        String value = safe(text);
        if (value.isEmpty()) {
            return 0f;
        }
        float uniqueRatio = (float) uniqueCharCount(value) / Math.max(1, value.length());
        return Math.min(1.5f, 0.75f + uniqueRatio);
    }

    private static float kolmogorovApprox(String text) {
        String value = safe(text);
        if (value.isEmpty()) {
            return 0f;
        }
        return Math.min(2.0f, shannonEntropy(value) / 4.0f + (float) uniqueCharCount(value) / Math.max(1, value.length()));
    }

    private static float phishingLikeliness(String text, String host, String url) {
        float score = 0f;
        score += isIp(host) * 0.18f;
        score += url.startsWith("https://") ? 0f : 0.12f;
        score += containsAny(text, "login", "signin", "verify", "account", "password", "otp", "bank", "wallet") * 0.14f;
        score += containsAny(host, "duckdns", "ipfs", "pages.dev", "workers.dev", "firebase", "storage.googleapis", "sites.google", "docs.google") * 0.16f;
        score += containsAny(host, "bit.ly", "tinyurl", "qrco.de", "t.co", "is.gd", "shorturl", "q-r.to") * 0.12f;
        score += countChar(url, '-') >= 2 ? 0.06f : 0f;
        score += digitCount(url) >= 8 ? 0.08f : 0f;
        score += shannonEntropy(url) >= 4.0f ? 0.08f : 0f;
        return Math.min(1f, score);
    }

    private static String tld(String host) {
        String value = safe(host);
        int index = value.lastIndexOf('.');
        if (index < 0 || index + 1 >= value.length()) {
            return "";
        }
        return value.substring(index + 1);
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
