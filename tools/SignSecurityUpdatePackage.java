import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.MessageDigest;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

public final class SignSecurityUpdatePackage {
    public static void main(String[] args) throws Exception {
        if (args.length != 2) {
            System.err.println("Usage: java tools/SignSecurityUpdatePackage.java <package-file> <private-key-pem>");
            System.exit(2);
        }
        byte[] data = Files.readAllBytes(Path.of(args[0]));
        PrivateKey privateKey = readPrivateKey(Path.of(args[1]));
        Signature signer = Signature.getInstance("SHA256withECDSA");
        signer.initSign(privateKey);
        signer.update(data);
        String signature = Base64.getEncoder().encodeToString(signer.sign());
        System.out.println("{");
        System.out.println("  \"name\": \"" + Path.of(args[0]).getFileName() + "\",");
        System.out.println("  \"sha256\": \"" + sha256(data) + "\",");
        System.out.println("  \"signature\": \"" + signature + "\"");
        System.out.println("}");
    }

    private static PrivateKey readPrivateKey(Path path) throws Exception {
        String pem = Files.readString(path, StandardCharsets.US_ASCII)
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s+", "");
        byte[] der = Base64.getDecoder().decode(pem);
        return KeyFactory.getInstance("EC").generatePrivate(new PKCS8EncodedKeySpec(der));
    }

    private static String sha256(byte[] data) throws Exception {
        byte[] hash = MessageDigest.getInstance("SHA-256").digest(data);
        StringBuilder builder = new StringBuilder(hash.length * 2);
        for (byte b : hash) {
            builder.append(String.format("%02x", b & 0xFF));
        }
        return builder.toString();
    }
}
