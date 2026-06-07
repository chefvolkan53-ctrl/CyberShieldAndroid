package com.monster.cybershield.core;

public final class NativeVpnForwarder {
    private static final boolean AVAILABLE;

    static {
        boolean loaded;
        try {
            System.loadLibrary("cybershield_forwarder");
            loaded = true;
        } catch (Throwable ignored) {
            loaded = false;
        }
        AVAILABLE = loaded;
    }

    private NativeVpnForwarder() {
    }

    public static boolean isAvailable() {
        return AVAILABLE;
    }

    public static int start(String configPath, int tunFd, int mtu) {
        if (!AVAILABLE) {
            return -1;
        }
        try {
            TProxyStartService(configPath, tunFd);
            return 0;
        } catch (Throwable ignored) {
            return -2;
        }
    }

    public static void stop() {
        if (AVAILABLE) {
            TProxyStopService();
        }
    }

    public static long[] stats() {
        if (!AVAILABLE) {
            return new long[]{0L, 0L, 0L, 0L};
        }
        try {
            long[] stats = TProxyGetStats();
            return stats == null ? new long[]{0L, 0L, 0L, 0L} : stats;
        } catch (Throwable ignored) {
            return new long[]{0L, 0L, 0L, 0L};
        }
    }

    private static native void TProxyStartService(String configPath, int tunFd);

    private static native void TProxyStopService();

    private static native long[] TProxyGetStats();
}
