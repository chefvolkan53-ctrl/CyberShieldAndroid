package com.monster.cybershield.core;

import java.util.Objects;

public final class FlowKey {
    public final String sourceAddress;
    public final String destinationAddress;
    public final int sourcePort;
    public final int destinationPort;
    public final int protocol;

    private FlowKey(String sourceAddress, String destinationAddress, int sourcePort, int destinationPort, int protocol) {
        this.sourceAddress = safe(sourceAddress);
        this.destinationAddress = safe(destinationAddress);
        this.sourcePort = sourcePort;
        this.destinationPort = destinationPort;
        this.protocol = protocol;
    }

    public static FlowKey from(PacketInfo packet) {
        return new FlowKey(packet.sourceAddress, packet.destinationAddress, packet.sourcePort, packet.destinationPort, packet.protocol);
    }

    public String target() {
        return destinationAddress + ":" + destinationPort;
    }

    @Override
    public boolean equals(Object obj) {
        if (!(obj instanceof FlowKey)) {
            return false;
        }
        FlowKey other = (FlowKey) obj;
        return sourcePort == other.sourcePort
                && destinationPort == other.destinationPort
                && protocol == other.protocol
                && sourceAddress.equals(other.sourceAddress)
                && destinationAddress.equals(other.destinationAddress);
    }

    @Override
    public int hashCode() {
        return Objects.hash(sourceAddress, destinationAddress, sourcePort, destinationPort, protocol);
    }

    private static String safe(String value) {
        return value == null ? "" : value;
    }
}
