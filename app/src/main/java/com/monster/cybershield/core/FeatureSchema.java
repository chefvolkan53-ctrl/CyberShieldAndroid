package com.monster.cybershield.core;

import android.content.Context;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

public final class FeatureSchema {
    private final List<String> columns;
    private final float[] mean;
    private final float[] scale;

    private FeatureSchema(List<String> columns, float[] mean, float[] scale) {
        this.columns = columns;
        this.mean = mean;
        this.scale = scale;
    }

    public static FeatureSchema load(Context context, String assetName, int fallbackSize) {
        try {
            JSONObject json = new JSONObject(readAsset(context, "metadata/" + assetName));
            JSONArray array = firstArray(json, "feature_columns", "feature_names", "feature_order", "features");
            ArrayList<String> columns = new ArrayList<>();
            if (array != null) {
                for (int i = 0; i < array.length(); i++) {
                    columns.add(array.optString(i));
                }
            }
            while (columns.size() < fallbackSize) {
                columns.add("feature_" + columns.size());
            }
            return new FeatureSchema(columns, readFloatArray(json.optJSONArray("scaler_mean"), fallbackSize), readFloatArray(json.optJSONArray("scaler_scale"), fallbackSize));
        } catch (Exception e) {
            ArrayList<String> columns = new ArrayList<>();
            for (int i = 0; i < fallbackSize; i++) {
                columns.add("feature_" + i);
            }
            return new FeatureSchema(columns, null, null);
        }
    }

    public float[] packet(PacketInfo packet, int size) {
        float[] values = new float[size];
        for (int i = 0; i < size && i < columns.size(); i++) {
            values[i] = valueForPacket(columns.get(i), packet);
        }
        fillRemaining(values, packet.sourceAddress + packet.destinationAddress + packet.queryName);
        return scale(values);
    }

    public float[] flow(FlowStats flow, int size) {
        float[] values = new float[size];
        for (int i = 0; i < size && i < columns.size(); i++) {
            values[i] = valueForFlow(columns.get(i), flow);
        }
        fillRemaining(values, flow.key.sourceAddress + flow.key.destinationAddress + flow.lastQueryName);
        return scale(values);
    }

    public float[] url(String url, int size) {
        float[] raw = FeatureExtractor.socialUrl(url);
        float[] values = new float[size];
        for (int i = 0; i < values.length; i++) {
            values[i] = i < raw.length ? raw[i] : ((url.hashCode() >>> (i % 16)) & 1);
        }
        return scale(values);
    }

    public float[] pqc(String value, int size) {
        float[] raw = FeatureExtractor.pqcSession(value);
        float[] values = new float[size];
        for (int i = 0; i < values.length; i++) {
            values[i] = i < raw.length ? raw[i] : ((value.hashCode() >>> (i % 16)) & 1);
        }
        return scale(values);
    }

    private float valueForPacket(String column, PacketInfo packet) {
        String c = column == null ? "" : column.toLowerCase(Locale.US);
        if (c.contains("src") && c.contains("port")) return packet.sourcePort;
        if ((c.contains("dst") || c.contains("dest")) && c.contains("port")) return packet.destinationPort;
        if (c.contains("protocol") || c.equals("proto")) return packet.protocol;
        if (c.contains("packet") && (c.contains("len") || c.contains("size"))) return packet.totalLength;
        if (c.contains("length") || c.contains("bytes")) return packet.totalLength;
        if (c.contains("dns")) return packet.isDns ? 1 : 0;
        if (c.contains("doh") || c.contains("https")) return packet.isDohLike ? 1 : 0;
        if (c.contains("query") && c.contains("len")) return packet.queryName.length();
        if (c.contains("domain") && c.contains("level")) return packet.queryName.isEmpty() ? 0 : packet.queryName.split("\\.").length;
        if (c.contains("digit") || c.contains("numeric")) return digitCount(packet.queryName);
        if (c.contains("hyphen") || c.contains("dash")) return packet.queryName.contains("-") ? 1 : 0;
        if (c.contains("entropy")) return entropy(packet.queryName);
        return 0f;
    }

    private float valueForFlow(String column, FlowStats flow) {
        String c = column == null ? "" : column.toLowerCase(Locale.US);
        if (c.contains("src") && c.contains("port")) return flow.key.sourcePort;
        if ((c.contains("dst") || c.contains("dest")) && c.contains("port")) return flow.key.destinationPort;
        if (c.contains("protocol") || c.equals("proto")) return flow.key.protocol;
        if (c.contains("duration") || c.contains("dur")) return flow.durationMs();
        if (c.contains("packet") && (c.contains("count") || c.contains("cnt") || c.contains("tot"))) return flow.packetCount;
        if (c.contains("pkt") && (c.contains("count") || c.contains("cnt"))) return flow.packetCount;
        if (c.contains("byte") || c.contains("octet")) return flow.byteCount;
        if (c.contains("rate") && c.contains("packet")) return flow.packetsPerSecond();
        if (c.contains("rate") && c.contains("byte")) return flow.bytesPerSecond();
        if (c.contains("pps")) return flow.packetsPerSecond();
        if (c.contains("bps")) return flow.bytesPerSecond();
        if (c.contains("mean") || c.contains("avg")) return flow.averagePacketBytes();
        if (c.contains("min")) return flow.minPacketBytes == Integer.MAX_VALUE ? 0 : flow.minPacketBytes;
        if (c.contains("max")) return flow.maxPacketBytes;
        if (c.contains("tcp")) return flow.tcpPackets;
        if (c.contains("udp")) return flow.udpPackets;
        if (c.contains("dns")) return flow.dnsPackets;
        if (c.contains("doh") || c.contains("https")) return flow.dohPackets;
        if (c.contains("syn")) return flow.synPackets;
        if (c.contains("ack")) return flow.ackPackets;
        if (c.contains("fin")) return flow.finPackets;
        if (c.contains("rst") || c.contains("reset")) return flow.rstPackets;
        if (c.contains("query") && c.contains("len")) return flow.lastQueryName.length();
        if (c.contains("domain") && c.contains("level")) return flow.lastQueryName.isEmpty() ? 0 : flow.lastQueryName.split("\\.").length;
        if (c.contains("digit") || c.contains("numeric")) return digitCount(flow.lastQueryName);
        if (c.contains("hyphen") || c.contains("dash")) return flow.lastQueryName.contains("-") ? 1 : 0;
        if (c.contains("entropy")) return entropy(flow.lastQueryName);
        return 0f;
    }

    private float[] scale(float[] values) {
        if (mean == null || scale == null) {
            return values;
        }
        for (int i = 0; i < values.length && i < mean.length && i < scale.length; i++) {
            float denominator = Math.abs(scale[i]) < 1e-6f ? 1f : scale[i];
            values[i] = (values[i] - mean[i]) / denominator;
        }
        return values;
    }

    private void fillRemaining(float[] values, String seed) {
        for (int i = 0; i < values.length; i++) {
            if (values[i] == 0f) {
                values[i] = (((seed + "|" + i).hashCode() & 0xFF) / 255.0f) * 0.01f;
            }
        }
    }

    private static JSONArray firstArray(JSONObject json, String... keys) {
        for (String key : keys) {
            JSONArray array = json.optJSONArray(key);
            if (array != null) {
                return array;
            }
        }
        return null;
    }

    private static float[] readFloatArray(JSONArray array, int fallbackSize) {
        if (array == null) {
            return null;
        }
        float[] values = new float[Math.max(array.length(), fallbackSize)];
        for (int i = 0; i < array.length(); i++) {
            values[i] = (float) array.optDouble(i, 0.0);
        }
        for (int i = array.length(); i < values.length; i++) {
            values[i] = 0f;
        }
        return values;
    }

    private static String readAsset(Context context, String path) throws Exception {
        try (InputStream input = context.getAssets().open(path);
             ByteArrayOutputStream output = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[8192];
            int read;
            while ((read = input.read(buffer)) != -1) {
                output.write(buffer, 0, read);
            }
            return output.toString(StandardCharsets.UTF_8.name());
        }
    }

    private static int digitCount(String text) {
        int count = 0;
        if (text == null) return count;
        for (int i = 0; i < text.length(); i++) {
            if (Character.isDigit(text.charAt(i))) count++;
        }
        return count;
    }

    private static float entropy(String text) {
        if (text == null || text.isEmpty()) return 0f;
        int[] counts = new int[256];
        for (int i = 0; i < text.length(); i++) {
            counts[text.charAt(i) & 0xFF]++;
        }
        float entropy = 0f;
        for (int count : counts) {
            if (count == 0) continue;
            float p = count / (float) text.length();
            entropy -= p * (Math.log(p) / Math.log(2.0));
        }
        return entropy;
    }
}
