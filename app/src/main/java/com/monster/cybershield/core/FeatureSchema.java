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
    private final boolean signedLog1p;

    private FeatureSchema(List<String> columns, float[] mean, float[] scale, boolean signedLog1p) {
        this.columns = columns;
        this.mean = mean;
        this.scale = scale;
        this.signedLog1p = signedLog1p;
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
            String transform = json.optString("transform", "");
            return new FeatureSchema(
                    columns,
                    readFloatArray(json.optJSONArray("scaler_mean"), fallbackSize),
                    readFloatArray(json.optJSONArray("scaler_scale"), fallbackSize),
                    transform.toLowerCase(Locale.US).contains("signed_log1p")
            );
        } catch (Exception e) {
            ArrayList<String> columns = new ArrayList<>();
            for (int i = 0; i < fallbackSize; i++) {
                columns.add("feature_" + i);
            }
            return new FeatureSchema(columns, null, null, false);
        }
    }

    public float[] packet(PacketInfo packet, int size) {
        float[] values = new float[size];
        for (int i = 0; i < size && i < columns.size(); i++) {
            values[i] = valueForPacket(columns.get(i), packet);
        }
        return scale(values);
    }

    public float[] flow(FlowStats flow, int size) {
        float[] values = new float[size];
        for (int i = 0; i < size && i < columns.size(); i++) {
            values[i] = valueForFlow(columns.get(i), flow);
        }
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
        String compact = c.replace("_", " ").replace("-", " ");
        if (c.equals("dst_port_norm")) return flow.key.destinationPort / 65535.0f;
        if (c.equals("is_ssh_22")) return flow.key.destinationPort == 22 ? 1f : 0f;
        if (c.equals("is_telnet_23")) return flow.key.destinationPort == 23 ? 1f : 0f;
        if (c.equals("is_smb_445")) return flow.key.destinationPort == 445 ? 1f : 0f;
        if (c.equals("is_mssql_1433")) return flow.key.destinationPort == 1433 ? 1f : 0f;
        if (c.equals("is_vnc_5900")) return flow.key.destinationPort == 5900 ? 1f : 0f;
        if (c.equals("is_known_honeypot_port")) return isHoneypotRiskPort(flow.key.destinationPort) ? 1f : 0f;
        if (c.equals("port_attack_prior")) return honeypotPortPrior(flow.key.destinationPort);
        if (c.equals("port_attack_count_scaled")) return logScale(estimatedPortPressure(flow), 13178f);
        if (c.equals("global_attack_count_scaled")) return 0.50f * honeypotPortPrior(flow.key.destinationPort);
        if (c.equals("unique_ip_count_scaled")) return 0f;
        if (c.equals("honeypot_cowrie_scaled")) return flow.key.destinationPort == 22 || flow.key.destinationPort == 23 ? 1f : 0f;
        if (c.equals("honeypot_dionaea_scaled")) return flow.key.destinationPort == 445 || flow.key.destinationPort == 1433 ? 1f : 0f;
        if (c.equals("honeypot_heralding_scaled")) return flow.key.destinationPort == 5900 ? 1f : 0f;
        if (c.equals("honeypot_honeytrap_scaled")) return isHoneypotRiskPort(flow.key.destinationPort) ? 0.25f : 0f;
        if (c.equals("honeypot_tanner_scaled")) return flow.key.destinationPort == 22 || flow.key.destinationPort == 23 ? 0.35f : 0f;
        if (c.equals("honeypot_mailoney_scaled")) return 0f;
        if (c.equals("flow_packet_count_scaled")) return logScale(flow.packetCount, 4000f);
        if (c.equals("flow_byte_count_scaled")) return logScale(flow.byteCount, 320000f);
        if (c.equals("flow_packets_per_second_scaled")) return logScale(flow.packetsPerSecond(), 800f);
        if (c.equals("flow_bytes_per_second_scaled")) return logScale(flow.bytesPerSecond(), 64000f);
        if (c.equals("flow_duration_scaled")) return Math.min(1f, flow.durationMs() / 60000f);
        if (c.equals("tcp_flag_syn_ratio")) return flow.tcpPackets == 0 ? 0f : flow.synPackets / (float) flow.tcpPackets;
        if (c.equals("tcp_flag_rst_ratio")) return flow.tcpPackets == 0 ? 0f : flow.rstPackets / (float) flow.tcpPackets;
        if (c.equals("tcp_flag_ack_ratio")) return flow.tcpPackets == 0 ? 0f : flow.ackPackets / (float) flow.tcpPackets;
        if (c.equals("dns_flow_hint")) return flow.dnsPackets > 0 ? 1f : 0f;
        if (c.equals("doh_flow_hint")) return flow.dohPackets > 0 || flow.key.destinationPort == 853 ? 1f : 0f;
        if (c.equals("tcp_flow_hint")) return flow.tcpPackets > 0 || flow.key.protocol == 6 ? 1f : 0f;
        if (c.equals("udp_flow_hint")) return flow.udpPackets > 0 || flow.key.protocol == 17 ? 1f : 0f;
        if (c.equals("bruteforce_scan_hint")) return bruteforceScanHint(flow);
        if (c.equals("high_unique_ip_hint")) return 0f;
        if (c.equals("bias")) return 1f;
        if (c.contains("src") && c.contains("port")) return flow.key.sourcePort;
        if ((c.contains("dst") || c.contains("dest")) && c.contains("port")) return flow.key.destinationPort;
        if (c.contains("protocol") || c.equals("proto")) return flow.key.protocol;
        if (c.contains("duration") || c.contains("dur")) return flow.durationMs();
        if (c.contains("total fwd packet") || c.contains("subflow fwd packets")) return flow.fwd.packetCount;
        if (c.contains("total bwd") || c.contains("subflow bwd packets")) return flow.bwd.packetCount;
        if (c.contains("total length of fwd") || c.contains("subflow fwd bytes")) return flow.fwd.byteCount;
        if (c.contains("total length of bwd") || c.contains("subflow bwd bytes")) return flow.bwd.byteCount;
        if (c.contains("fwd packet length max") || c.contains("network_packet-size_max") && compact.contains("src")) return flow.fwd.packetLength.max();
        if (c.contains("fwd packet length min") || c.contains("network_packet-size_min") && compact.contains("src")) return flow.fwd.packetLength.min();
        if (c.contains("fwd packet length mean") || c.contains("fwd segment size avg")) return flow.fwd.packetLength.mean();
        if (c.contains("fwd packet length std")) return flow.fwd.packetLength.std();
        if (c.contains("bwd packet length max") || compact.contains("packet size max") && compact.contains("dst")) return flow.bwd.packetLength.max();
        if (c.contains("bwd packet length min") || compact.contains("packet size min") && compact.contains("dst")) return flow.bwd.packetLength.min();
        if (c.contains("bwd packet length mean") || c.contains("bwd segment size avg")) return flow.bwd.packetLength.mean();
        if (c.contains("bwd packet length std")) return flow.bwd.packetLength.std();
        if (c.contains("flow bytes/s")) return flow.bytesPerSecond();
        if (c.contains("flow packets/s")) return flow.packetsPerSecond();
        if (c.contains("fwd packets/s")) return flow.fwd.packetsPerSecond(flow.durationMs());
        if (c.contains("bwd packets/s")) return flow.bwd.packetsPerSecond(flow.durationMs());
        if (c.contains("flow iat mean")) return flow.flowIatStats.mean();
        if (c.contains("flow iat std")) return flow.flowIatStats.std();
        if (c.contains("flow iat max")) return flow.flowIatStats.max();
        if (c.contains("flow iat min")) return flow.flowIatStats.min();
        if (c.contains("fwd iat total")) return (float) flow.fwdIatStats.sum;
        if (c.contains("fwd iat mean")) return flow.fwdIatStats.mean();
        if (c.contains("fwd iat std")) return flow.fwdIatStats.std();
        if (c.contains("fwd iat max")) return flow.fwdIatStats.max();
        if (c.contains("fwd iat min")) return flow.fwdIatStats.min();
        if (c.contains("bwd iat total")) return (float) flow.bwdIatStats.sum;
        if (c.contains("bwd iat mean")) return flow.bwdIatStats.mean();
        if (c.contains("bwd iat std")) return flow.bwdIatStats.std();
        if (c.contains("bwd iat max")) return flow.bwdIatStats.max();
        if (c.contains("bwd iat min")) return flow.bwdIatStats.min();
        if (c.contains("fwd psh")) return flow.fwdPshPackets;
        if (c.contains("bwd psh")) return flow.bwdPshPackets;
        if (c.contains("fwd urg")) return flow.fwdUrgPackets;
        if (c.contains("bwd urg")) return flow.bwdUrgPackets;
        if (c.contains("fwd header")) return flow.fwd.headerLength.sum == 0 ? flow.fwd.headerLength.mean() : (float) flow.fwd.headerLength.sum;
        if (c.contains("bwd header")) return flow.bwd.headerLength.sum == 0 ? flow.bwd.headerLength.mean() : (float) flow.bwd.headerLength.sum;
        if (c.contains("packet length variance")) {
            float std = flow.packetLengthStats.std();
            return std * std;
        }
        if (c.contains("packet length std") || compact.contains("packet size std")) return flow.packetLengthStats.std();
        if (c.contains("packet length mean") || compact.contains("packet size avg")) return flow.packetLengthStats.mean();
        if (c.contains("average packet size")) return flow.averagePacketBytes();
        if (c.contains("min packet length") || c.contains("packet length min") || compact.contains("packet size min")) return flow.packetLengthStats.min();
        if (c.contains("max packet length") || c.contains("packet length max") || compact.contains("packet size max")) return flow.packetLengthStats.max();
        if (c.contains("fin flag") || compact.contains("tcp flags fin")) return flow.finPackets;
        if (c.contains("syn flag") || compact.contains("tcp flags syn")) return flow.synPackets;
        if (c.contains("rst flag") || compact.contains("tcp flags rst")) return flow.rstPackets;
        if (c.contains("psh flag") || compact.contains("tcp flags psh")) return flow.pshPackets;
        if (c.contains("ack flag") || compact.contains("tcp flags ack")) return flow.ackPackets;
        if (c.contains("urg flag") || compact.contains("tcp flags urg")) return flow.urgPackets;
        if (c.contains("cwr") || c.contains("cwe")) return flow.cwrPackets;
        if (c.contains("ece")) return flow.ecePackets;
        if (c.contains("down/up")) return flow.downUpRatio();
        if (c.contains("init win") && c.contains("fwd")) return flow.fwd.windowSize.max();
        if (c.contains("init win") && c.contains("bwd")) return flow.bwd.windowSize.max();
        if (c.contains("act data")) return flow.fwdActDataPackets;
        if (c.contains("seg size min")) return Math.min(flow.fwd.packetLength.min(), flow.bwd.packetLength.min());
        if (c.contains("active mean")) return flow.activeStats.mean();
        if (c.contains("active std")) return flow.activeStats.std();
        if (c.contains("active max")) return flow.activeStats.max();
        if (c.contains("active min")) return flow.activeStats.min();
        if (c.contains("idle mean")) return flow.idleStats.mean();
        if (c.contains("idle std")) return flow.idleStats.std();
        if (c.contains("idle max")) return flow.idleStats.max();
        if (c.contains("idle min")) return flow.idleStats.min();
        if (compact.contains("fragmentation score")) return flow.packetCount == 0 ? 0 : flow.fragmentedPackets / (float) flow.packetCount;
        if (compact.contains("fragmented packets")) return flow.fragmentedPackets;
        if (compact.contains("header length avg")) return flow.headerLengthStats.mean();
        if (compact.contains("header length max")) return flow.headerLengthStats.max();
        if (compact.contains("header length min")) return flow.headerLengthStats.min();
        if (compact.contains("header length std")) return flow.headerLengthStats.std();
        if (compact.contains("interval packets")) return flow.packetsPerSecond();
        if (compact.contains("ip flags avg")) return flow.ipFlagsStats.mean();
        if (compact.contains("ip flags max")) return flow.ipFlagsStats.max();
        if (compact.contains("ip flags min")) return flow.ipFlagsStats.min();
        if (compact.contains("ip flags std")) return flow.ipFlagsStats.std();
        if (compact.contains("ip length avg")) return flow.packetLengthStats.mean();
        if (compact.contains("ip length max")) return flow.packetLengthStats.max();
        if (compact.contains("ip length min")) return flow.packetLengthStats.min();
        if (compact.contains("ip length std")) return flow.packetLengthStats.std();
        if (compact.contains("ips all count")) return flow.allIpCount();
        if (compact.contains("ips dst count")) return flow.dstIpCount();
        if (compact.contains("ips src count")) return flow.srcIpCount();
        if (compact.contains("macs")) return 0f;
        if (compact.contains("mss avg")) return Math.max(0f, flow.packetLengthStats.mean() - flow.headerLengthStats.mean());
        if (compact.contains("mss max")) return Math.max(0f, flow.packetLengthStats.max() - flow.headerLengthStats.mean());
        if (compact.contains("mss min")) return Math.max(0f, flow.packetLengthStats.min() - flow.headerLengthStats.mean());
        if (compact.contains("mss std")) return flow.packetLengthStats.std();
        if (compact.contains("packets all count")) return flow.packetCount;
        if (compact.contains("packets dst count")) return flow.bwd.packetCount;
        if (compact.contains("packets src count")) return flow.fwd.packetCount;
        if (compact.contains("payload length avg")) return combinedPayloadMean(flow);
        if (compact.contains("payload length max")) return Math.max(flow.fwd.payloadLength.max(), flow.bwd.payloadLength.max());
        if (compact.contains("payload length min")) return nonZeroMin(flow.fwd.payloadLength.min(), flow.bwd.payloadLength.min());
        if (compact.contains("payload length std")) return Math.max(flow.fwd.payloadLength.std(), flow.bwd.payloadLength.std());
        if (compact.contains("ports all count")) return flow.allPortCount();
        if (compact.contains("ports dst count")) return flow.dstPortCount();
        if (compact.contains("ports src count")) return flow.srcPortCount();
        if (compact.contains("protocols")) return flow.protocolCount();
        if (compact.contains("tcp flags avg")) return flow.packetCount == 0 ? 0 : (flow.synPackets + flow.ackPackets + flow.finPackets + flow.rstPackets + flow.pshPackets + flow.urgPackets) / (float) flow.packetCount;
        if (compact.contains("tcp flags max")) return Math.max(flow.synPackets, Math.max(flow.ackPackets, Math.max(flow.finPackets, flow.rstPackets)));
        if (compact.contains("tcp flags min")) return 0f;
        if (compact.contains("tcp flags std")) return flow.packetLengthStats.std();
        if (compact.contains("time delta avg")) return flow.flowIatStats.mean();
        if (compact.contains("time delta max")) return flow.flowIatStats.max();
        if (compact.contains("time delta min")) return flow.flowIatStats.min();
        if (compact.contains("time delta std")) return flow.flowIatStats.std();
        if (compact.contains("ttl avg")) return flow.ttlStats.mean();
        if (compact.contains("ttl max")) return flow.ttlStats.max();
        if (compact.contains("ttl min")) return flow.ttlStats.min();
        if (compact.contains("ttl std")) return flow.ttlStats.std();
        if (compact.contains("window size avg")) return flow.windowStats.mean();
        if (compact.contains("window size max")) return flow.windowStats.max();
        if (compact.contains("window size min")) return flow.windowStats.min();
        if (compact.contains("window size std")) return flow.windowStats.std();
        if (compact.contains("log")) return 0f;
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

    private static boolean isHoneypotRiskPort(int port) {
        return port == 22 || port == 23 || port == 445 || port == 1433 || port == 5900;
    }

    private static float honeypotPortPrior(int port) {
        if (port == 5900) return 1.0f;
        if (port == 1433) return 1294131f / 1375095f;
        if (port == 445) return 1177719f / 1375095f;
        if (port == 22) return 1096773f / 1375095f;
        if (port == 23) return 65230f / 1375095f;
        return 0f;
    }

    private static float estimatedPortPressure(FlowStats flow) {
        float multiplier = isHoneypotRiskPort(flow.key.destinationPort) ? 25f : 1f;
        float flagPressure = flow.synPackets * 40f + flow.rstPackets * 20f;
        return Math.max(flow.packetCount * multiplier, flagPressure);
    }

    private static float bruteforceScanHint(FlowStats flow) {
        float synRatio = flow.tcpPackets == 0 ? 0f : flow.synPackets / (float) flow.tcpPackets;
        float rstRatio = flow.tcpPackets == 0 ? 0f : flow.rstPackets / (float) flow.tcpPackets;
        float portHint = isHoneypotRiskPort(flow.key.destinationPort) ? 0.55f : 0f;
        float rateHint = Math.min(0.30f, flow.packetsPerSecond() / 1000f);
        return Math.min(1f, portHint + 0.35f * synRatio + 0.25f * rstRatio + rateHint);
    }

    private static float logScale(double value, double denom) {
        return (float) (Math.log1p(Math.max(0.0, value)) / Math.log1p(Math.max(1.0, denom)));
    }

    private static float combinedPayloadMean(FlowStats flow) {
        int count = flow.fwd.payloadLength.count + flow.bwd.payloadLength.count;
        if (count == 0) {
            return 0f;
        }
        return (float) ((flow.fwd.payloadLength.sum + flow.bwd.payloadLength.sum) / count);
    }

    private static float nonZeroMin(float a, float b) {
        if (a == 0f) return b;
        if (b == 0f) return a;
        return Math.min(a, b);
    }

    private float[] scale(float[] values) {
        if (signedLog1p) {
            for (int i = 0; i < values.length; i++) {
                values[i] = (float) (Math.signum(values[i]) * Math.log1p(Math.abs(values[i])));
            }
        }
        if (mean == null || scale == null) {
            return values;
        }
        for (int i = 0; i < values.length && i < mean.length && i < scale.length; i++) {
            float denominator = Math.abs(scale[i]) < 1e-6f ? 1f : scale[i];
            values[i] = (values[i] - mean[i]) / denominator;
        }
        return values;
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
