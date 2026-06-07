-keep class org.tensorflow.lite.** { *; }
-dontwarn org.tensorflow.lite.**

-keep class com.monster.cybershield.core.NativeVpnForwarder {
    private static native <methods>;
    public static <methods>;
}

-keep class com.monster.cybershield.model.** { *; }
-keep class com.monster.cybershield.core.ThreatEvent { *; }
