package com.monster.cybershield.core;

import android.content.Intent;
import android.net.VpnService;
import android.os.Build;

import com.monster.cybershield.CyberDefenseService;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicReference;

public final class DirectSocksProxy implements AutoCloseable {
    private final VpnService vpnService;
    private final BlocklistStore blocklist;
    private final ProtectionPolicyStore protectionPolicy;
    private final ProxyTrafficMirror trafficMirror;
    private final ThreatIntelStore threatIntelStore;
    private final int port;
    private final ExecutorService workers = Executors.newCachedThreadPool();
    private final java.util.concurrent.atomic.AtomicLong acceptedConnections = new java.util.concurrent.atomic.AtomicLong();
    private final java.util.concurrent.atomic.AtomicLong blockedRequests = new java.util.concurrent.atomic.AtomicLong();
    private final java.util.concurrent.atomic.AtomicLong lastActivityAt = new java.util.concurrent.atomic.AtomicLong();
    private volatile boolean running;
    private ServerSocket serverSocket;
    private Thread acceptThread;

    public DirectSocksProxy(VpnService vpnService, int port) {
        this.vpnService = vpnService;
        this.blocklist = new BlocklistStore(vpnService);
        this.protectionPolicy = new ProtectionPolicyStore(vpnService);
        this.trafficMirror = new ProxyTrafficMirror(vpnService);
        this.threatIntelStore = new ThreatIntelStore(vpnService);
        this.port = port;
    }

    public synchronized void start() throws IOException {
        if (running) {
            return;
        }
        serverSocket = new ServerSocket();
        serverSocket.setReuseAddress(true);
        serverSocket.bind(new InetSocketAddress(InetAddress.getByName("127.0.0.1"), port));
        running = true;
        acceptThread = new Thread(new Runnable() {
            @Override
            public void run() {
                acceptLoop();
            }
        }, "cybershield-socks-accept");
        acceptThread.start();
    }

    private void acceptLoop() {
        while (running) {
            try {
                final Socket client = serverSocket.accept();
                acceptedConnections.incrementAndGet();
                lastActivityAt.set(System.currentTimeMillis());
                workers.execute(new Runnable() {
                    @Override
                    public void run() {
                        handleClient(client);
                    }
                });
            } catch (IOException ignored) {
                if (!running) {
                    return;
                }
            }
        }
    }

    private void handleClient(Socket client) {
        try (Socket local = client) {
            local.setTcpNoDelay(true);
            InputStream input = local.getInputStream();
            OutputStream output = local.getOutputStream();
            if (!readGreeting(input, output)) {
                return;
            }
            Request request = readRequest(input);
            if (request == null || isBlocked(request.host, request.port)) {
                blockedRequests.incrementAndGet();
                writeFailure(output, 0x02);
                return;
            }
            if (protectionPolicy.shouldBlockDohEndpoint(request.host, request.port)) {
                blockedRequests.incrementAndGet();
                raiseDnsLeakAlert(request.host, request.port, "DoH endpoint sinirlandi");
                writeFailure(output, 0x02);
                return;
            }
            if (shouldBlockCleartextHttp(request.host, request.port)) {
                blockedRequests.incrementAndGet();
                raiseCleartextHttpAlert(request.host, request.port);
                writeFailure(output, 0x02);
                return;
            }
            if (request.command == 0x01) {
                handleConnect(local, input, output, request);
            } else if (request.command == 0x03) {
                handleUdpAssociate(local, output);
            } else {
                writeFailure(output, 0x07);
            }
        } catch (IOException ignored) {
        }
    }

    private boolean readGreeting(InputStream input, OutputStream output) throws IOException {
        int version = input.read();
        int methods = input.read();
        if (version != 0x05 || methods <= 0) {
            return false;
        }
        skipFully(input, methods);
        output.write(new byte[]{0x05, 0x00});
        output.flush();
        return true;
    }

    private Request readRequest(InputStream input) throws IOException {
        int version = input.read();
        int command = input.read();
        input.read();
        int atyp = input.read();
        if (version != 0x05) {
            return null;
        }
        String host;
        if (atyp == 0x01) {
            byte[] address = readFully(input, 4);
            host = (address[0] & 0xFF) + "." + (address[1] & 0xFF) + "." + (address[2] & 0xFF) + "." + (address[3] & 0xFF);
        } else if (atyp == 0x03) {
            int len = input.read();
            host = new String(readFully(input, len), StandardCharsets.UTF_8);
        } else if (atyp == 0x04) {
            byte[] address = readFully(input, 16);
            host = InetAddress.getByAddress(address).getHostAddress();
        } else {
            return null;
        }
        int port = ((input.read() & 0xFF) << 8) | (input.read() & 0xFF);
        return new Request(command, host, port);
    }

    private void handleConnect(Socket client, InputStream clientInput, OutputStream clientOutput, Request request) throws IOException {
        Socket remote = new Socket();
        vpnService.protect(remote);
        try {
            remote.connect(new InetSocketAddress(targetHostForRequest(request.host, request.port), request.port), 12_000);
        } catch (IOException e) {
            writeFailure(clientOutput, 0x05);
            closeQuietly(remote);
            return;
        }
        clientOutput.write(successReply("127.0.0.1", port));
        clientOutput.flush();
        trafficMirror.recordTcpConnect(request.host, request.port);
        final Socket remoteSocket = remote;
        workers.execute(new Runnable() {
            @Override
            public void run() {
                pipe(clientInput, remoteSocket, request, true);
            }
        });
        pipe(remoteSocket, client, request, false);
    }

    private void handleUdpAssociate(Socket control, OutputStream output) throws IOException {
        final DatagramSocket clientSocket = new DatagramSocket(new InetSocketAddress(InetAddress.getByName("127.0.0.1"), 0));
        final DatagramSocket remoteSocket = new DatagramSocket();
        final AtomicReference<SocketAddress> clientAddress = new AtomicReference<>();
        final AtomicReference<UdpRequest> lastRequest = new AtomicReference<>();
        vpnService.protect(remoteSocket);
        output.write(successReply("127.0.0.1", clientSocket.getLocalPort()));
        output.flush();
        workers.execute(new Runnable() {
            @Override
            public void run() {
                udpClientToRemote(clientSocket, remoteSocket, clientAddress, lastRequest);
            }
        });
        workers.execute(new Runnable() {
            @Override
            public void run() {
                udpRemoteToClient(clientSocket, remoteSocket, clientAddress, lastRequest);
            }
        });
        try {
            while (running && !control.isClosed() && control.getInputStream().read() >= 0) {
            }
        } catch (IOException ignored) {
        } finally {
            clientSocket.close();
            remoteSocket.close();
        }
    }

    private void udpClientToRemote(DatagramSocket clientSocket, DatagramSocket remoteSocket, AtomicReference<SocketAddress> clientAddress, AtomicReference<UdpRequest> lastRequest) {
        byte[] buffer = new byte[65535];
        while (running && !clientSocket.isClosed()) {
            try {
                DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
                clientSocket.receive(packet);
                clientAddress.set(packet.getSocketAddress());
                UdpRequest request = parseUdpRequest(packet);
                if (request == null || isBlocked(request.host, request.port)) {
                    blockedRequests.incrementAndGet();
                    continue;
                }
                String dnsQuery = request.port == 53 ? parseDnsQueryDomain(request.payload) : "";
                if (!dnsQuery.isEmpty() && isBlocked(dnsQuery, 53)) {
                    blockedRequests.incrementAndGet();
                    continue;
                }
                lastActivityAt.set(System.currentTimeMillis());
                lastRequest.set(request);
                trafficMirror.recordUdp(request.host, request.port, request.payload.length, true, dnsQuery);
                String targetHost = targetHostForRequest(request.host, request.port);
                DatagramPacket out = new DatagramPacket(request.payload, request.payload.length, InetAddress.getByName(targetHost), request.port);
                remoteSocket.send(out);
            } catch (IOException ignored) {
            }
        }
    }

    private void udpRemoteToClient(DatagramSocket clientSocket, DatagramSocket remoteSocket, AtomicReference<SocketAddress> clientAddress, AtomicReference<UdpRequest> lastRequest) {
        byte[] buffer = new byte[65535];
        while (running && !remoteSocket.isClosed()) {
            try {
                DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
                remoteSocket.receive(packet);
                SocketAddress target = clientAddress.get();
                if (target == null) {
                    continue;
                }
                byte[] response = wrapUdpResponse(packet);
                UdpRequest request = lastRequest.get();
                if (request != null) {
                    lastActivityAt.set(System.currentTimeMillis());
                    trafficMirror.recordUdp(request.host, request.port, packet.getLength(), false, "");
                }
                DatagramPacket out = new DatagramPacket(response, response.length, target);
                clientSocket.send(out);
            } catch (IOException ignored) {
            }
        }
    }

    private UdpRequest parseUdpRequest(DatagramPacket packet) throws IOException {
        byte[] data = packet.getData();
        int offset = packet.getOffset();
        int length = packet.getLength();
        if (length < 10 || data[offset] != 0 || data[offset + 1] != 0 || data[offset + 2] != 0) {
            return null;
        }
        int pos = offset + 3;
        int atyp = data[pos++] & 0xFF;
        String host;
        if (atyp == 0x01) {
            host = (data[pos] & 0xFF) + "." + (data[pos + 1] & 0xFF) + "." + (data[pos + 2] & 0xFF) + "." + (data[pos + 3] & 0xFF);
            pos += 4;
        } else if (atyp == 0x03) {
            int hostLen = data[pos++] & 0xFF;
            host = new String(data, pos, hostLen, StandardCharsets.UTF_8);
            pos += hostLen;
        } else {
            return null;
        }
        int targetPort = ((data[pos++] & 0xFF) << 8) | (data[pos++] & 0xFF);
        byte[] payload = new byte[offset + length - pos];
        System.arraycopy(data, pos, payload, 0, payload.length);
        return new UdpRequest(host, targetPort, payload);
    }

    private byte[] wrapUdpResponse(DatagramPacket packet) {
        byte[] address = packet.getAddress().getAddress();
        int atyp = address.length == 4 ? 0x01 : 0x04;
        byte[] payload = packet.getData();
        int payloadOffset = packet.getOffset();
        int payloadLength = packet.getLength();
        byte[] out = new byte[3 + 1 + address.length + 2 + payloadLength];
        int pos = 0;
        out[pos++] = 0;
        out[pos++] = 0;
        out[pos++] = 0;
        out[pos++] = (byte) atyp;
        System.arraycopy(address, 0, out, pos, address.length);
        pos += address.length;
        out[pos++] = (byte) ((packet.getPort() >> 8) & 0xFF);
        out[pos++] = (byte) (packet.getPort() & 0xFF);
        System.arraycopy(payload, payloadOffset, out, pos, payloadLength);
        return out;
    }

    private boolean isBlocked(String host, int targetPort) {
        String normalized = host == null ? "" : host.toLowerCase(Locale.US);
        return blocklist.isBlocked(normalized)
                || blocklist.isBlocked(normalized + ":" + targetPort)
                || threatIntelStore.isKnownMaliciousTarget(normalized)
                || threatIntelStore.isKnownMaliciousTarget(normalized + ":" + targetPort);
    }

    private String targetHostForRequest(String host, int targetPort) {
        if (targetPort == 53 && protectionPolicy.isDnsLeakProtectionEnabled()) {
            if (!protectionPolicy.shouldAllowDnsResolver(host)) {
                raiseDnsLeakAlert(host, targetPort, "DNS leak yonlendirildi");
            }
            return protectionPolicy.dnsProvider();
        }
        return host;
    }

    private boolean shouldBlockCleartextHttp(String host, int targetPort) {
        if (targetPort != 80 || !protectionPolicy.shouldBlockCleartextHttp()) {
            return false;
        }
        String normalized = host == null ? "" : host.toLowerCase(Locale.US);
        return !blocklist.isAllowed(normalized) && !blocklist.isAllowed(normalized + ":" + targetPort);
    }

    private void raiseCleartextHttpAlert(String host, int targetPort) {
        if (!protectionPolicy.shouldRaiseHttpDowngradeAlert()) {
            return;
        }
        Intent intent = new Intent(vpnService, CyberDefenseService.class);
        intent.setAction(CyberDefenseService.ACTION_RAISE_THREAT);
        intent.putExtra(CyberDefenseService.EXTRA_MODEL_ID, "wifi_threat");
        intent.putExtra(CyberDefenseService.EXTRA_TITLE, "HTTP downgrade engellendi");
        intent.putExtra(CyberDefenseService.EXTRA_SOURCE, "vpn_http_guard");
        intent.putExtra(CyberDefenseService.EXTRA_TARGET, host + ":" + targetPort);
        intent.putExtra(CyberDefenseService.EXTRA_SEVERITY, "high");
        intent.putExtra(CyberDefenseService.EXTRA_PROBABILITY, 0.78);
        intent.putExtra(CyberDefenseService.EXTRA_RECOMMENDED_ACTION, "block_flow");
        try {
            if (Build.VERSION.SDK_INT >= 26) {
                vpnService.startForegroundService(intent);
            } else {
                vpnService.startService(intent);
            }
        } catch (Exception ignored) {
        }
    }

    private void raiseDnsLeakAlert(String host, int targetPort, String title) {
        if (!protectionPolicy.shouldRaiseDnsLeakAlert()) {
            return;
        }
        Intent intent = new Intent(vpnService, CyberDefenseService.class);
        intent.setAction(CyberDefenseService.ACTION_RAISE_THREAT);
        intent.putExtra(CyberDefenseService.EXTRA_MODEL_ID, "dns_stateful");
        intent.putExtra(CyberDefenseService.EXTRA_TITLE, title);
        intent.putExtra(CyberDefenseService.EXTRA_SOURCE, "vpn_dns_leak_guard");
        intent.putExtra(CyberDefenseService.EXTRA_TARGET, host + ":" + targetPort);
        intent.putExtra(CyberDefenseService.EXTRA_SEVERITY, "high");
        intent.putExtra(CyberDefenseService.EXTRA_PROBABILITY, 0.82);
        intent.putExtra(CyberDefenseService.EXTRA_RECOMMENDED_ACTION, "block_flow");
        try {
            if (Build.VERSION.SDK_INT >= 26) {
                vpnService.startForegroundService(intent);
            } else {
                vpnService.startService(intent);
            }
        } catch (Exception ignored) {
        }
    }

    private static String parseDnsQueryDomain(byte[] payload) {
        if (payload == null || payload.length < 13) {
            return "";
        }
        try {
            int flags = ((payload[2] & 0xFF) << 8) | (payload[3] & 0xFF);
            int qdCount = ((payload[4] & 0xFF) << 8) | (payload[5] & 0xFF);
            boolean isResponse = (flags & 0x8000) != 0;
            if (isResponse || qdCount <= 0) {
                return "";
            }
            StringBuilder name = new StringBuilder();
            int pos = 12;
            int labels = 0;
            while (pos < payload.length && labels < 32) {
                int len = payload[pos++] & 0xFF;
                if (len == 0) {
                    break;
                }
                if ((len & 0xC0) != 0 || len > 63 || pos + len > payload.length) {
                    return "";
                }
                if (name.length() > 0) {
                    name.append('.');
                }
                for (int i = 0; i < len; i++) {
                    int ch = payload[pos + i] & 0xFF;
                    if (ch <= 32 || ch >= 127) {
                        return "";
                    }
                    name.append((char) ch);
                }
                pos += len;
                labels++;
            }
            return name.toString().toLowerCase(Locale.US);
        } catch (Exception ignored) {
            return "";
        }
    }

    private byte[] successReply(String host, int bindPort) throws IOException {
        byte[] address = InetAddress.getByName(host).getAddress();
        byte[] reply = new byte[10];
        reply[0] = 0x05;
        reply[1] = 0x00;
        reply[2] = 0x00;
        reply[3] = 0x01;
        System.arraycopy(address, 0, reply, 4, 4);
        reply[8] = (byte) ((bindPort >> 8) & 0xFF);
        reply[9] = (byte) (bindPort & 0xFF);
        return reply;
    }

    private void writeFailure(OutputStream output, int code) throws IOException {
        output.write(new byte[]{0x05, (byte) code, 0x00, 0x01, 0, 0, 0, 0, 0, 0});
        output.flush();
    }

    private void pipe(InputStream input, Socket outputSocket, Request request, boolean outbound) {
        try {
            OutputStream output = outputSocket.getOutputStream();
            byte[] buffer = new byte[32 * 1024];
            int read;
            while ((read = input.read(buffer)) >= 0) {
                lastActivityAt.set(System.currentTimeMillis());
                trafficMirror.recordTcpBytes(request.host, request.port, read, outbound);
                output.write(buffer, 0, read);
                output.flush();
            }
        } catch (IOException ignored) {
        } finally {
            closeQuietly(outputSocket);
        }
    }

    private void pipe(Socket inputSocket, Socket outputSocket, Request request, boolean outbound) {
        try {
            InputStream input = inputSocket.getInputStream();
            OutputStream output = outputSocket.getOutputStream();
            byte[] buffer = new byte[32 * 1024];
            int read;
            while ((read = input.read(buffer)) >= 0) {
                lastActivityAt.set(System.currentTimeMillis());
                trafficMirror.recordTcpBytes(request.host, request.port, read, outbound);
                output.write(buffer, 0, read);
                output.flush();
            }
        } catch (IOException ignored) {
        } finally {
            closeQuietly(inputSocket);
            closeQuietly(outputSocket);
        }
    }

    private static byte[] readFully(InputStream input, int length) throws IOException {
        byte[] data = new byte[length];
        int offset = 0;
        while (offset < length) {
            int read = input.read(data, offset, length - offset);
            if (read < 0) {
                throw new IOException("unexpected eof");
            }
            offset += read;
        }
        return data;
    }

    private static void skipFully(InputStream input, int length) throws IOException {
        while (length > 0) {
            long skipped = input.skip(length);
            if (skipped <= 0) {
                if (input.read() < 0) {
                    throw new IOException("unexpected eof");
                }
                skipped = 1;
            }
            length -= skipped;
        }
    }

    private static void closeQuietly(Socket socket) {
        try {
            socket.close();
        } catch (IOException ignored) {
        }
    }

    @Override
    public synchronized void close() {
        running = false;
        try {
            if (serverSocket != null) {
                serverSocket.close();
            }
        } catch (IOException ignored) {
        }
        workers.shutdownNow();
        trafficMirror.close();
    }

    public long acceptedConnections() {
        return acceptedConnections.get();
    }

    public long blockedRequests() {
        return blockedRequests.get();
    }

    public long mirroredBytes() {
        return trafficMirror.mirroredBytes();
    }

    public long analyzedFlows() {
        return trafficMirror.analyzedFlows();
    }

    public long lastActivityAt() {
        return Math.max(lastActivityAt.get(), trafficMirror.lastMirrorAt());
    }

    private static final class Request {
        final int command;
        final String host;
        final int port;

        Request(int command, String host, int port) {
            this.command = command;
            this.host = host;
            this.port = port;
        }
    }

    private static final class UdpRequest {
        final String host;
        final int port;
        final byte[] payload;

        UdpRequest(String host, int port, byte[] payload) {
            this.host = host;
            this.port = port;
            this.payload = payload;
        }
    }
}
