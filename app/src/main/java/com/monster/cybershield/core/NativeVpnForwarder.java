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

    public static int start(int tunFd, int mtu) {
        if (!AVAILABLE) {
            return -1;
        }
        return nativeStart(tunFd, mtu);
    }

    public static void stop() {
        if (AVAILABLE) {
            nativeStop();
        }
    }

    private static native int nativeStart(int tunFd, int mtu);

    private static native void nativeStop();
}
