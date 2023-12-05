import java.io.FileInputStream;
import java.util.Base64;
import java.security.NoSuchAlgorithmException;
import java.io.IOException;

public class FileDigest {
    public static void main(String[] arry) throws IOException, NoSuchAlgorithmException {
        String inputxt = arry[0];
        HandshakeDigest InputDigest = new HandshakeDigest();
        FileInputStream InputStream = new FileInputStream(inputxt);
        byte[] handshakedigest = InputStream.readAllBytes();
        InputDigest.update(handshakedigest);
        InputDigest.digest();
        Base64.Encoder encoder = Base64.getEncoder();
        encoder.encodeToString(InputDigest.digest);
        System.out.println(encoder.encodeToString(InputDigest.digest));
    }
}
