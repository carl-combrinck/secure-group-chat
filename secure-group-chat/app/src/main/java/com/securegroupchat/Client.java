package com.securegroupchat;

import com.securegroupchat.PGPUtilities;

import java.net.*;
import java.io.*;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.concurrent.atomic.AtomicBoolean;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;


public class Client {
    private final String hostname;
    private final int port;
    private final KeyPair personalKeyPair;
    private KeyStore keyRing;
    private String clientName;

    public Client() throws NoSuchAlgorithmException {
        this.hostname = "localhost";
        this.port = 4444;
        this.personalKeyPair = PGPUtilities.generateRSAKeyPair();
    }

    public Client(String hostname, int port) throws NoSuchAlgorithmException {
        this.hostname = hostname;
        this.port = port;
        this.personalKeyPair = PGPUtilities.generateRSAKeyPair();
    }

    public void addKeyToRing(String name, X509Certificate cert){
        try {
            keyRing.setCertificateEntry(name, cert);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void connectToServer() {
        try {
            Socket socket = new Socket(hostname, port);
            ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
            ObjectInputStream in = new ObjectInputStream(socket.getInputStream());
            AtomicBoolean ready = new AtomicBoolean(false);

            new IncomingHandler(socket, in, out, ready).start();
            new OutgoingHandler(socket, in, out, ready).start();

        } catch (UnknownHostException e) {
            System.exit(1);
        } catch (IOException e) {
            System.exit(1);
        }
    }

    private void createKeyRing() throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException {
        this.keyRing = KeyStore.getInstance("PKCS12");
        this.keyRing.load(null,null);
    }

    public static void main(String[] args) throws NoSuchAlgorithmException {
        Client client;

        if (args.length == 0) {
            client = new Client();
            client.setup();
            client.connectToServer();
        } else if (args.length == 2) {
            String hostname = args[0];
            int port = Integer.parseInt(args[1]);
            client = new Client(hostname, port);
            client.setup();
            client.connectToServer();
        } else {
            System.err.println("Usage: java Client <host name> <port number>");
            System.exit(1);
        }
    }

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
            System.out.println("Certificate generated.");
            //System.out.println(certificate);

            createKeyRing();
            addKeyToRing(clientName,certificate); //Store client's certificate in in-memory KeyStore

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void setClientName(String clientName){
        this.clientName = clientName;
    }

    private String getClientName(){
        return this.clientName;
    }

    private class IncomingHandler extends Thread {
        private Socket socket;
        private ObjectInputStream in;
        private ObjectOutputStream out;
        private AtomicBoolean ready;

        public IncomingHandler(Socket socket, ObjectInputStream in, ObjectOutputStream out, AtomicBoolean ready) {
            this.socket = socket;
            this.in = in;
            this.out = out;
            this.ready = ready;
        }

        // For concurrent writing to output stream
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
                            System.out.println("> Connection to server successful.");
                            //Send client's certificate to the server
                            CertificateMessage certificateMessage = new CertificateMessage(clientName,"<ALL>", (X509Certificate) keyRing.getCertificate(clientName));
                            writeToStream(certificateMessage);
                            System.out.println("Sent certificate to server.");
                        }
                        // End Connection Message
                        else if(commandMessage.getCommand().equals("CONN_END")){
                            System.out.println("> Connection to server closed.");
                            break;
                        }


                    } else if (message instanceof CertificateMessage) {

                        CertificateMessage certificateMessage = (CertificateMessage) message;

                        // Handle CertificateMessages that are not from me
                        if(!certificateMessage.getSender().equals(Client.this.getClientName())){
                            X500Name x500name = new JcaX509CertificateHolder(certificateMessage.getCertificate()).getSubject();
                            //TODO Change to CN
                            System.out.println("Received certificate from " + x500name.toString());
                            try {
                                CertificateAuthority ca = new CertificateAuthority();
                                certificateMessage.getCertificate().verify(ca.getPublicKey()); // Verify certificate
                                // TODO Change name to be from Certificate
                                Client.this.addKeyToRing(certificateMessage.getSender(), certificateMessage.getCertificate());
                                System.out.println("Certificate Valid");
                                // TODO Return my certificate
                            } catch (Exception e) {
                                System.out.println("Could not verify cerificate!");
                            }
                        }

                    }else if (message instanceof  PGPMessage){

                        PGPMessage pgpMessage = (PGPMessage) message;
                        System.out.println("Received PGP message:");
                        System.out.println("Decoding...");

                    }

                } catch (IOException | ClassNotFoundException | KeyStoreException | CertificateEncodingException e) {
                    e.printStackTrace();
                    System.exit(1);
                }
            }
        }
    }

    private class OutgoingHandler extends Thread {
        private Socket socket;
        private ObjectOutputStream out;
        private ObjectInputStream in;
        private AtomicBoolean ready;

        public OutgoingHandler(Socket socket, ObjectInputStream in, ObjectOutputStream out, AtomicBoolean ready) {
            this.socket = socket;
            this.in = in;
            this.out = out;
            this.ready = ready;
        }

        private void writeToStream(Object obj) throws IOException{
            synchronized (this.out) {
                this.out.writeObject(obj);
            }
        } 

        public void run() {



            try (BufferedReader stdIn = new BufferedReader(new InputStreamReader(System.in))) {
                String userInput;
                do{
                    System.out.println("Enter message: ");
                    userInput = stdIn.readLine();

                    if(userInput.equals("quit")){
                        CommandMessage quit = new CommandMessage(Client.this.clientName, "server", "QUIT");
                        writeToStream(quit);
                    }
                    else{
                        //Just testing with command messages for now
                        CommandMessage message = new CommandMessage(Client.this.clientName, "server", userInput);
                        writeToStream(message);
                    }

                }while(!userInput.equals("quit"));
                
            } catch (IOException e) {
                e.printStackTrace();
                System.exit(1);
            }
        }
    }


}
