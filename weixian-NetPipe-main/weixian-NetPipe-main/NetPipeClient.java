import java.net.*;
import java.io.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;

public class NetPipeClient {
    private static String PROGRAMNAME = NetPipeClient.class.getSimpleName();
    private static Arguments arguments;

    /*
     * Usage: explain how to use the program, then exit with failure status
     */
    private static void usage() {
        String indent = "";
        System.err.println(indent + "Usage: " + PROGRAMNAME + " options");
        System.err.println(indent + "Where options are:");
        indent += "    ";
        System.err.println(indent + "--host=<hostname>");
        System.err.println(indent + "--port=<portnumber>");
        System.err.println(indent + "--usercert=<client certificate PEM file>");
        System.err.println(indent + "--cacert=<CA certificate PEM file>");
        System.err.println(indent + "--key=<client private key DER file>");
        System.exit(1);
    }

    /*
     * Parse arguments on command line
     */
    private static void parseArgs(String[] args) {
        arguments = new Arguments();
        arguments.setArgumentSpec("host", "hostname");
        arguments.setArgumentSpec("port", "portnumber");
        arguments.setArgumentSpec("usercert", "filename");
        arguments.setArgumentSpec("cacert", "filename");
        arguments.setArgumentSpec("key", "filename");

        try {
        arguments.loadArguments(args);
        } catch (IllegalArgumentException ex) {
            usage();
        }
    }
    /*
     * Main program.
     * Parse arguments on command line, connect to server,
     * and call forwarder to forward data between streams.
     */
    public static void main( String[] args) {
        Socket socket = null;

        parseArgs(args);
        String host = arguments.get("host");
        int port = Integer.parseInt(arguments.get("port"));
        try {
            socket = new Socket(host, port);
        } catch (IOException ex) {
            System.err.printf("Can't connect to server at %s:%d\n", host, port);
            System.exit(1);
        }
        /*
         * HandShake
         */
        try{
            String usercert = arguments.get("usercert");
            String cacert = arguments.get("cacert");
            String key = arguments.get("key");
            ClientHandshake.ClientHelloinit(socket, usercert);
            ClientHandshake.ServerHelloVerify(socket, cacert);
            SessionSetup.setSession(socket);
        }catch (IOException ex){
            System.out.println("Client Hello Error\n");
            System.exit(1);
        } catch (CertificateException e) {
            System.out.println("Server Hello Error\n");
            System.exit(1);
        } catch (Exception e) {
            System.out.println("Session Setup Error\n");
            System.exit(1);
        }
        try {
            OutputStream socketOutEncrypt = SessionCipher.openEncryptedOutputStream(socket.getOutputStream());
            InputStream  socketInDecrypt = SessionCipher.openDecryptedInputStream(socket.getInputStream());
            Forwarder.forwardStreams(System.in, System.out,socketInDecrypt, socketOutEncrypt, socket);
        } catch (IOException ex) {
            System.out.println("Data Forwarding error\n");
            System.exit(1);
        }
    }
}
