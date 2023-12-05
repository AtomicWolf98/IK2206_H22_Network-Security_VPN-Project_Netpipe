import java.io.InputStream;
import java.io.OutputStream;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidParameterSpecException;
import java.util.Random;

public class SessionCipher {
    SessionKey sessionKey;
    Cipher session;
    byte[] counter;
    IvParameterSpec ivParameterSpec;
    /*
     * Constructor to create a SessionCipher from a SessionKey. The IV is
     * created automatically.
     */
    public SessionCipher(SessionKey key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidParameterSpecException, InvalidKeyException, InvalidAlgorithmParameterException {
        session = Cipher.getInstance("AES/CTR/NoPadding");
        this.sessionKey = key;
        SecureRandom random = new SecureRandom();
        counter = random.generateSeed(16);
        ivParameterSpec = new IvParameterSpec(counter);
        //this.IVbyte = cipher.getParameters().getParameterSpec(IvParameterSpec.class).getIV();
        session.init(Cipher.ENCRYPT_MODE, key.getSecretKey(), ivParameterSpec);
    }

    /*
     * Constructor to create a SessionCipher from a SessionKey and an IV,
     * given as a byte array.
     */

    public SessionCipher(SessionKey key, byte[] ivbytes)throws InvalidAlgorithmParameterException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidParameterSpecException {
        session = Cipher.getInstance("AES/CTR/NoPadding");
        this.sessionKey = key;
        //this.IVbyte = cipher.getParameters().getParameterSpec(IvParameterSpec.class).getIV();
        ivParameterSpec = new IvParameterSpec(ivbytes);
        this.session.init(Cipher.ENCRYPT_MODE, key.getSecretKey(), ivParameterSpec);
    }

    /*
     * Return the SessionKey
     */
    public SessionKey getSessionKey() {
        return sessionKey;
    }

    /*
     * Return the IV as a byte array
     */
    public byte[] getIVBytes() {
        return ivParameterSpec.getIV();
    }

    /*
     * Attach OutputStream to which encrypted data will be written.
     * Return result as a CipherOutputStream instance.
     */
    CipherOutputStream openEncryptedOutputStream(OutputStream os) {
        return new CipherOutputStream(os, session);
    }

    /*
     * Attach InputStream from which decrypted data will be read.
     * Return result as a CipherInputStream instance.
     */

    CipherInputStream openDecryptedInputStream(InputStream inputstream) {
        return new CipherInputStream(inputstream, session);
    }
}
