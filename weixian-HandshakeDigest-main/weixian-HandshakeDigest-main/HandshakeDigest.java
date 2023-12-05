import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class HandshakeDigest {
    public MessageDigest inputDigest;
    public byte[] digest;
    /*
     * Constructor -- initialise a digest for SHA-256
     */

    public HandshakeDigest() throws NoSuchAlgorithmException {
        this.inputDigest = MessageDigest.getInstance("SHA-256");
    }

    /*
     * Update digest with input data
     */
    public void update(byte[] input) {
        this.inputDigest.update(input);
    }

    /*
     * Compute final digest
     */
    public byte[] digest() {
        this.digest = this.inputDigest.digest();
        return this.digest;
    }
}
