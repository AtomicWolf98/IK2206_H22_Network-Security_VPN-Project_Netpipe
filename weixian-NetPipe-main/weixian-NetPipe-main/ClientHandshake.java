import java.io.FileInputStream;
import java.io.IOException;
import java.net.Socket;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Base64;

public class ClientHandshake {

    public HandshakeMessage ClientHello;

    public static HandshakeMessage ServerHello;

    public HandshakeMessage SessionMessage;

    public SessionKey sessionKey;

    public static HandshakeCertificate ServerCertificate;
    public String sessionHost;
    public int sessionPort;

    public byte[] BytesessionKey;

    public byte[] sessionIV;

    public String getSessionHost() {
        return sessionHost;
    }

    public int getSessionPort() {
        return sessionPort;
    }

    public static void ClientHelloinit(Socket socket, String clientcert) throws CertificateException, IOException {
        HandshakeMessage ClientHello = new HandshakeMessage(HandshakeMessage.MessageType.CLIENTHELLO);
        FileInputStream fileinputstream = new FileInputStream(clientcert);
        X509Certificate ClientCertificate = new HandshakeCertificate(fileinputstream).getCertificate();
        ClientHello.putParameter("MessageType", "ClientHello");
        ClientHello.send(socket);
        System.out.println("Client Hello Sent");
    }

    public static void ServerHelloVerify(Socket socket, String servercert) throws Exception {
        ServerHello.recv(socket);
        if (! ServerHello.getParameter("MessageType").equals("ServerHello")){
            throw new Exception("Wrong Hello Type");
        } else if(ServerHello.getParameter("MessageType").equals("ServerHello")){
            FileInputStream fileinputstream = new FileInputStream(servercert);
            HandshakeCertificate sercertfile = new HandshakeCertificate(fileinputstream);
            String serverCertificate = ServerHello.getParameter("Certificate");
            byte[] ByteSeverCertificate = Base64.getDecoder().decode(serverCertificate);
            ServerCertificate = new HandshakeCertificate(ByteSeverCertificate);
            sercertfile.verify(sercertfile);
            ServerCertificate.verify(ServerCertificate);
            System.out.println("Server certificate verified succeed.");
        }else {
            System.err.println("Server certificate verified ERROR.");
        }
    }
}
