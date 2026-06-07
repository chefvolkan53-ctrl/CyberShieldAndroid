package com.monster.cybershield.core;

public final class PacketInfo {
    public int totalLength;
    public int ipHeaderLength;
    public int transportHeaderLength;
    public int protocol;
    public int ttl;
    public int ipFlags;
    public int fragmentOffset;
    public int sourcePort;
    public int destinationPort;
    public int payloadLength;
    public int tcpFlags;
    public int tcpWindowSize;
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
