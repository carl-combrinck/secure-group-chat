package com.securegroupchat;

import com.securegroupchat.PGPUtilities;

import java.net.*;
import java.io.*;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;


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

    private void connectToServer() {
        try {
            Socket socket = new Socket(hostname, port);
            ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
            ObjectInputStream in = new ObjectInputStream(socket.getInputStream());

            //Send client's certificate to the server
            CertificateMessage certificateMessage = new CertificateMessage(clientName,"server", (X509Certificate) keyRing.getCertificate(clientName));
            out.writeObject(certificateMessage);

            new IncomingHandler(socket, in).start();
            new OutgoingHandler(socket, out).start();

        } catch (UnknownHostException e) {
            System.exit(1);
        } catch (IOException e) {
            System.exit(1);
        } catch (KeyStoreException e) {
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
            System.out.println(certificate);

            createKeyRing();
            keyRing.setCertificateEntry(clientName,certificate); //Store client's certificate in in-memory KeyStore

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void setClientName(String clientName){
        this.clientName = clientName;
    }

    private String getClientName(String clientName){
        return this.clientName;
    }

    private class IncomingHandler extends Thread {
        private Socket socket;
        private ObjectInputStream in;

        public IncomingHandler(Socket socket, ObjectInputStream in) {
            this.socket = socket;
            this.in = in;
        }

        public void run() {
            try {
//                String receivedLine;
//                while ((receivedLine = in.readLine()) != null) {
//                    System.out.println("Received: " + receivedLine);
//                    System.out.print("Enter message: ");
//                }
                Object message = in.readObject();

                if (message instanceof CommandMessage){

                    CommandMessage commandMessage = (CommandMessage) message;
                    System.out.println("Received command:");
                    System.out.println(commandMessage.getCommand());

                } else if (message instanceof CertificateMessage) {

                    CertificateMessage certificateMessage = (CertificateMessage) message;
                    System.out.println("Received certificate:");
                    System.out.println(certificateMessage.getCertificate());

                }else if (message instanceof  PGPMessage){

                    PGPMessage pgpMessage = (PGPMessage) message;
                    System.out.println("Received PGP message:");
                    System.out.println("Decoding...");

                }

            } catch (IOException | ClassNotFoundException e) {
                e.printStackTrace();
                System.exit(1);
            }
        }
    }

    private class OutgoingHandler extends Thread {
        private Socket socket;
        private ObjectOutputStream out;

        public OutgoingHandler(Socket socket, ObjectOutputStream out) {
            this.socket = socket;
            this.out = out;
        }

        public void run() {

            try (BufferedReader stdIn = new BufferedReader(new InputStreamReader(System.in))) {
                String userInput;
                do{
                    System.out.println("Enter message: ");
                    userInput = stdIn.readLine();

                    //Just testing with command messages for now
                    CommandMessage message = new CommandMessage(Client.this.clientName, null, userInput);
                    out.writeObject(message);

                }while(userInput != "quit");

            } catch (IOException e) {
                e.printStackTrace();
                System.exit(1);
            }
        }
    }


}
