package com.securegroupchat;

import com.securegroupchat.PGPUtilities;
import com.securegroupchat.LoggingLevel;

import java.net.*;
import java.io.*;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.util.logging.Logger;
import java.util.Enumeration;

/**
 * Client is a class that represents a connected group chat participant.
 * Generates an RSA key pair and a CA-signed X509 certificate.
 * Spawns incoming and outgoing message handlers to facilitate the simultaneous sending and receiving of messages.
 * Messages are encrypted securely for every connected client and delivered by means of the server.
 *
 * @author Jaron Cohen
 * @author Carl Combrinck
 * @author Bailey Green
 * @version 1.0.0
 */
public class Client {
    private final static Logger logger = Logger.getLogger(Client.class.getName());
    private final static String logTemplate = "%-20s%-5s%-10s%s";
    private final static String errTemplate = "%-20s%s";
    private final String hostname;
    private final int port;
    private final KeyPair personalKeyPair;
    private KeyStore keyRing;
    private String clientName;

    /**
     * Default class constructor - generates RSA key pair
     * @throws NoSuchAlgorithmException
     */
    public Client() throws NoSuchAlgorithmException {
        this.hostname = "localhost";
        this.port = 4444;
        this.personalKeyPair = PGPUtilities.generateRSAKeyPair();
    }

    /**
     * Class constructor - specify server hostname and port
     * @param hostname - hostname of the server
     * @param port - port the server is listening on
     * @throws NoSuchAlgorithmException
     */
    public Client(String hostname, int port) throws NoSuchAlgorithmException {
        this.hostname = hostname;
        this.port = port;
        this.personalKeyPair = PGPUtilities.generateRSAKeyPair();
    }

    /**
     * Add specified certificate to client keyring associated with specified alias
     * @param name - alias associated with certificate
     * @param cert - X509Certificate
     */
    public void addKeyToRing(String name, X509Certificate cert){
        try {
            keyRing.setCertificateEntry(name, cert);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * Remove certificate associated with specified alias
     * @param name - alias associated with certificate
     */
    public void removeFromKeyring(String name){
        try{
            keyRing.deleteEntry(name);
        }catch(Exception e){
            e.printStackTrace();
        }
    }

    /**
     * Establishes client connection with server, creates input and output object streams and starts incoming message handler
     */
    private void connectToServer() {
        try {
            Socket socket = new Socket(hostname, port);
            ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
            ObjectInputStream in = new ObjectInputStream(socket.getInputStream());

            new IncomingHandler(socket, in, out).start();

        } catch (UnknownHostException e) {
            System.exit(1);
        } catch (IOException e) {
            System.exit(1);
        }
    }

    /**
     * Creates in-memory KeyStore object that functions as client's keyring to store certificates
     * @throws KeyStoreException
     * @throws CertificateException
     * @throws IOException
     * @throws NoSuchAlgorithmException
     */
    private void createKeyRing() throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException {
        this.keyRing = KeyStore.getInstance("PKCS12");
        this.keyRing.load(null,null);
    }

    /**
     * Creates a client instance, performs setup and connects to server.
     * @param args - <host name> <port number> [-debug]
     * @throws NoSuchAlgorithmException
     */
    public static void main(String[] args) throws NoSuchAlgorithmException {
        Client client;
        //ConsoleHandler ch = new ConsoleHandler();

        boolean debug = false;

        if(args[args.length-1].equals("-debug")){
            logger.setLevel(LoggingLevel.DEBUG);
            debug = true;
        }
        else{
            logger.setLevel(LoggingLevel.INFO);
        }
        if ((args.length == 1 && debug) || (args.length == 0 && !debug)) {
            client = new Client();
            client.setup();
            client.connectToServer();
        } else if ((args.length == 3 && debug) || (args.length == 2 && !debug)) {
            String hostname = args[0];
            int port = Integer.parseInt(args[1]);
            client = new Client(hostname, port);
            client.setup();
            client.connectToServer();
        } else {
            logger.log(LoggingLevel.INFO, String.format(errTemplate, "[ARGS_ERR]", "Usage: java Client <host name> <port number> [-debug]"));
            System.exit(1);
        }
    }

    /**
     * Setup method gets user's name and X509Certificate signed by CA needed prior to connection with server
     */
    private void setup(){
        String clientName = "";
        BufferedReader stdin = new BufferedReader(new InputStreamReader(System.in));
        try {
            System.out.println("Welcome to the Secure Group Chat Application.");
            System.out.print("Please enter your chat name: ");
            clientName = stdin.readLine();
            setClientName(clientName);
            System.out.println("Welcome, "+ clientName);

            //Get signed certificate
            X509Certificate certificate = new CertificateAuthority().generateSignedCertificate(clientName, personalKeyPair.getPublic());
            logger.log(LoggingLevel.INFO, String.format(errTemplate, "[INIT]", "Certificate generated."));

            createKeyRing();
            addKeyToRing(clientName,certificate); //Store client's certificate in in-memory KeyStore

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * Sets name of client
     * @param clientName - alias or name the user will be using in the group chat
     */
    private void setClientName(String clientName){
        this.clientName = clientName;
    }

    /**
     * Gets name of client
     * @return client's name
     */
    private String getClientName(){
        return this.clientName;
    }

    /**
     * IncomingHandler is a private inner class that extends Thread and is spawned by a connected Client to facilitate the reception
     * of messages.
     * @author Jaron Cohen
     * @author Carl Combrinck
     * @author Bailey Green
     * @version 1.0.0
     */
    private class IncomingHandler extends Thread {
        private Socket socket;
        private ObjectInputStream in;
        private ObjectOutputStream out;

        /**
         * Class constructor
         * @param socket - socket established to communicate with the server
         * @param in - ObjectInputStream for incoming message objects
         * @param out ObjectOutputStream for outgoing message objects
         */
        public IncomingHandler(Socket socket, ObjectInputStream in, ObjectOutputStream out) {
            this.socket = socket;
            this.in = in;
            this.out = out;
        }

        /**
         * Concurrent writing to output stream
         * @param obj - Object to write
         * @throws IOException
         */
        private void writeToStream(Object obj) throws IOException{
            synchronized (this.out) {
                this.out.writeObject(obj);
            }
        }

        public void run() {
            while(true){
                try {

                    Object message = in.readObject();

                    if (message instanceof CommandMessage){

                        CommandMessage commandMessage = (CommandMessage) message;

                        // Successful Connection Message
                        if(commandMessage.getCommand().equals("CONN_SUCC")){
                            logger.log(LoggingLevel.DEBUG, String.format(logTemplate, "[TRANSMISSION]", "IN", "<CMD>", "CONN_SUCC"));
                            logger.log(LoggingLevel.INFO, String.format(errTemplate, "[SERVER]", "Connected to server."));
                            //Send client's certificate to the server
                            CertificateMessage certificateMessage = new CertificateMessage(clientName,"<ALL>", (X509Certificate) keyRing.getCertificate(clientName), false);
                            writeToStream(certificateMessage);
                            logger.log(LoggingLevel.DEBUG, String.format(logTemplate, "[TRANSMISSION]", "OUT", "<CERT>", "-> " + certificateMessage.getReceiver()));
                        }
                        else if(commandMessage.getCommand().equals("CERT_BROADCAST")){
                            logger.log(LoggingLevel.DEBUG, String.format(logTemplate, "[TRANSMISSION]", "IN", "<CMD>", "CERT_BROADCAST"));
                            logger.log(LoggingLevel.INFO, String.format(errTemplate, "[SERVER]", "Certificate broadcast, you may now send messages."));
                            new OutgoingHandler(socket, in, out).start(); //Client ready to send messages
                        }

                    } else if (message instanceof CertificateMessage) {

                        CertificateMessage certificateMessage = (CertificateMessage) message;

                        // Handle CertificateMessages that are not from me
                        if(!certificateMessage.getSender().equals(Client.this.getClientName())){
                            X500Name x500name = new JcaX509CertificateHolder(certificateMessage.getCertificate()).getSubject();
                            String CNalias = x500name.toString().substring(3);

                            logger.log(LoggingLevel.DEBUG, String.format(logTemplate, "[TRANSMISSION]", "IN", "<CERT>", "<- " + CNalias));

                            try {
                                CertificateAuthority ca = new CertificateAuthority();
                                certificateMessage.getCertificate().verify(ca.getPublicKey()); // Verify certificate
                                Client.this.addKeyToRing(CNalias, certificateMessage.getCertificate());
                                logger.log(LoggingLevel.DEBUG, String.format(errTemplate, "[CERT]", "Certificate verified: " + CNalias));
                                if(!certificateMessage.getReply()) {
                                    // Send client's certificate back as a reply
                                    CertificateMessage reply = new CertificateMessage(clientName, CNalias, (X509Certificate) keyRing.getCertificate(clientName), true);
                                    writeToStream(reply);
                                    logger.log(LoggingLevel.DEBUG, String.format(logTemplate, "[TRANSMISSION]", "OUT", "<CERT>", "-> " + reply.getReceiver()));
                                }

                            } catch (Exception e) {
                                logger.log(LoggingLevel.INFO, String.format(errTemplate, "[CERT]", "Could not verify certificate!"));
                            }
                        }

                    }else if (message instanceof  PGPMessage){
                        PGPMessage pgpMessage = (PGPMessage) message;
                        String sender = pgpMessage.getSender();
                        boolean protocol = pgpMessage.getProtocol();
                        logger.log(LoggingLevel.DEBUG, String.format(logTemplate, "[TRANSMISSION]", "IN", protocol ? "<PGP_CMD>" : "<PGP>", "<- " + pgpMessage.getSender()));

                        try {
                            byte[] decodedPGPdata = PGPUtilities.decode(pgpMessage.getPgpMessage(),personalKeyPair.getPrivate(),keyRing.getCertificate(sender).getPublicKey(), logger);
                            String plaintext = new String(decodedPGPdata);

                            if(protocol){
                                if(plaintext.equals("QUIT")){
                                    removeFromKeyring(pgpMessage.getSender());
                                    logger.log(LoggingLevel.INFO, String.format(errTemplate, "[QUIT]", pgpMessage.getSender()+" has quit."));
                                }
                            } else{
                                System.out.println("<<< " + sender+": "+plaintext);
                            }

                        } catch (InvalidAlgorithmParameterException | NoSuchPaddingException | IllegalBlockSizeException |
                                 NoSuchAlgorithmException | BadPaddingException | SignatureException | InvalidKeyException e) {
                            logger.log(LoggingLevel.INFO, String.format(errTemplate, "[DECODE]", "Could not decode PGP message!"));
                        }

                    }

                } catch (IOException | ClassNotFoundException | KeyStoreException | CertificateEncodingException e) {
                    e.printStackTrace();
                    System.exit(1);
                }
            }
        }
    }

    /**
     * OutgoingHandler is a private inner class that extends Thread and is spawned by a connected Client to facilitate the sending
     * of messages.
     * @author Jaron Cohen
     * @author Carl Combrinck
     * @author Bailey Green
     * @version 1.0.0
     */
    private class OutgoingHandler extends Thread {
        private Socket socket;
        private ObjectOutputStream out;
        private ObjectInputStream in;

        /**
         * Class constructor
         * @param socket - socket established to communicate with the server
         * @param in - ObjectInputStream for incoming message objects
         * @param out ObjectOutputStream for outgoing message objects
         */
        public OutgoingHandler(Socket socket, ObjectInputStream in, ObjectOutputStream out) {
            this.socket = socket;
            this.in = in;
            this.out = out;
        }

        /**
         * Concurrent writing to output stream
         * @param obj - Object to write
         * @throws IOException
         */
        private void writeToStream(Object obj) throws IOException{
            synchronized (this.out) {
                this.out.writeObject(obj);
            }
        }

        /**
         * Method to send a piece of plaintext encrypted individually to every connected client for which there is a corresponding
         * certificate in the keyring
         * @param plaintext - Message data
         * @param protocol - flag to indicate whether PGP message is a protocol or chat message
         * @throws KeyStoreException
         * @throws IOException
         * @throws InvalidAlgorithmParameterException
         * @throws NoSuchPaddingException
         * @throws IllegalBlockSizeException
         * @throws NoSuchAlgorithmException
         * @throws BadPaddingException
         * @throws InvalidKeyException
         */
        private void sendPGPMessageToAll(byte[] plaintext, boolean protocol) throws KeyStoreException, IOException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
            Enumeration<String> enumeration = keyRing.aliases();

            while(enumeration.hasMoreElements()) {
                String alias = enumeration.nextElement();
                X509Certificate tempRecipientCertificate = (X509Certificate) keyRing.getCertificate(alias);

                try {
                    X500Name x500name = new JcaX509CertificateHolder(tempRecipientCertificate).getSubject();
                    String CNalias = x500name.toString().substring(3); //Retrieve actual alias from certificate

                    if(!CNalias.equals(clientName)){
                        byte[] encodedPGPdata = PGPUtilities.encode(plaintext,personalKeyPair.getPrivate(),tempRecipientCertificate.getPublicKey(), logger);
                        PGPMessage pgpMessage = new PGPMessage(clientName,CNalias,encodedPGPdata,protocol);
                        writeToStream(pgpMessage);
                        logger.log(LoggingLevel.DEBUG, String.format(logTemplate, "[TRANSMISSION]", "OUT", protocol ? "<PGP_CMD>" : "<PGP>", "-> " + pgpMessage.getReceiver()));
                    }
                }catch(Exception e){
                    e.printStackTrace();
                }

            }
        }

        public void run() {

            try (BufferedReader stdIn = new BufferedReader(new InputStreamReader(System.in))) {
                String userInput;
                do{
                    System.out.println("Enter message: ");
                    userInput = stdIn.readLine();

                    if(userInput.equals("quit")){
                        sendPGPMessageToAll("QUIT".getBytes(),true);
                        System.out.println("Quitting application...");
                        System.exit(0);
                    }
                    else{
                        byte[] plaintext = userInput.getBytes();
                        sendPGPMessageToAll(plaintext,false);
                        System.out.println(">>> You: " + userInput);
                    }

                } while(!userInput.equals("quit"));
                
            } catch (Error | KeyStoreException | IOException | InvalidAlgorithmParameterException |
                    NoSuchPaddingException | IllegalBlockSizeException | NoSuchAlgorithmException |
                    BadPaddingException | InvalidKeyException e) {
                e.printStackTrace();
                System.exit(1);
            }
        }
    }
}
