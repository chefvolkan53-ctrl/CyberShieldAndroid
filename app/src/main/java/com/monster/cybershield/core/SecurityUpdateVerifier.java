package com.monster.cybershield.core;

import android.util.Base64;

import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.Locale;

public final class SecurityUpdateVerifier {
    private static final String UPDATE_SIGNING_PUBLIC_KEY_BASE64 =
            "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEmQZ5zCTkNyWvy+mMH700ANjoGRpahPW3wxDwrYzentp4J8PIJDfIuc8KWVai5A9McbAa2zfYw2EathzyJ1zt5Q==";

    private SecurityUpdateVerifier() {
    }

    public static String sha256(byte[] data) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(data);
        StringBuilder builder = new StringBuilder(hash.length * 2);
        for (byte b : hash) {
            builder.append(String.format(Locale.US, "%02x", b & 0xFF));
        }
        return builder.toString();
    }

    public static boolean sha256Matches(byte[] data, String expectedHex) throws Exception {
        String expected = expectedHex == null ? "" : expectedHex.trim().toLowerCase(Locale.US);
        return !expected.isEmpty() && MessageDigest.isEqual(sha256(data).getBytes("UTF-8"), expected.getBytes("UTF-8"));
    }

    public static boolean signatureMatches(byte[] data, String base64Signature) throws Exception {
        String signatureValue = base64Signature == null ? "" : base64Signature.trim();
        if (signatureValue.isEmpty()) {
            return false;
        }
        byte[] keyBytes = Base64.decode(UPDATE_SIGNING_PUBLIC_KEY_BASE64, Base64.DEFAULT);
        PublicKey publicKey = KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(keyBytes));
        Signature signature = Signature.getInstance("SHA256withECDSA");
        signature.initVerify(publicKey);
        signature.update(data);
        return signature.verify(Base64.decode(signatureValue, Base64.DEFAULT));
    }
}
