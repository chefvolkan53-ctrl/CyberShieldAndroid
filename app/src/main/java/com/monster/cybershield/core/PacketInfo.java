package com.monster.cybershield.core;

public final class PacketInfo {
    public int totalLength;
    public int protocol;
    public int sourcePort;
    public int destinationPort;
    public int payloadLength;
    public int tcpFlags;
    public String sourceAddress = "";
    public String destinationAddress = "";
    public String queryName = "";
    public boolean isDns;
    public boolean isDohLike;

    public String target() {
        if (queryName != null && !queryName.isEmpty()) {
            return queryName;
        }
        return destinationAddress + ":" + destinationPort;
    }
}
