import jdk.dynalink.beans.StaticClass;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.net.Socket;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidParameterSpecException;
import java.util.Base64;

public class SessionSetup {
    public static HandshakeCertificate serverCertificate;
    static SessionCipher Encrypt;
    static SessionCipher Decrypt;
    public static SessionKey sessionKey;
    public static HandshakeMessage sessionMessage;
    static byte[] sessionKeyBytes;
    static byte[] sessionIVBytes;

    public static void setSession(Socket socket) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException, InvalidParameterSpecException {
        sessionMessage = new HandshakeMessage(HandshakeMessage.MessageType.SESSION);
        sessionKey = new SessionKey(128);
        Encrypt = new SessionCipher(sessionKey, sessionIVBytes,0);
        sessionKeyBytes = sessionKey.getKeyBytes();
        sessionIVBytes = Encrypt.getIVBytes();
        Decrypt = new SessionCipher(sessionKey,sessionIVBytes,0);
        HandshakeCrypto handshakeCrypto = new HandshakeCrypto(serverCertificate); //get Server Publickey
        byte[] keyEncrypted = handshakeCrypto.encrypt(sessionKeyBytes);
        byte[] IVEncrypted = handshakeCrypto.encrypt(sessionIVBytes);
        sessionMessage.putParameter("SessionKey", Base64.getEncoder().encodeToString(keyEncrypted));
        sessionMessage.putParameter("SessionIV", Base64.getEncoder().encodeToString(IVEncrypted));
        sessionMessage.send(socket);
        System.out.println("Session Setup Over");
        System.out.println(sessionMessage);

    }
}
