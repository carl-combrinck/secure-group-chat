package com.nis;

import com.nis.shared.PGPUtilities;

import java.net.*;
import java.io.*;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

public class Client {
    private final String hostname;
    private final int port;
    private final KeyPair personalKeyPair;
    private KeyStore keyRing;

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
            PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
            BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));

            new IncomingHandler(socket, in).start();
            new OutgoingHandler(socket, out).start();

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
            client.connectToServer();
        } else if (args.length == 2) {
            String hostname = args[0];
            int port = Integer.parseInt(args[1]);
            client = new Client(hostname, port);
            client.connectToServer();
        } else {
            System.err.println("Usage: java Client <host name> <port number>");
            System.exit(1);
        }

    }

    private static class IncomingHandler extends Thread {
        private Socket socket;
        private BufferedReader in;

        public IncomingHandler(Socket socket, BufferedReader in) {
            this.socket = socket;
            this.in = in;
        }

        public void run() {

            try {
                String receivedLine;
                while ((receivedLine = in.readLine()) != null) {
                    System.out.println("Received: " + receivedLine);
                    System.out.print("Enter message: ");
                }
            } catch (IOException e) {
                e.printStackTrace();
                System.exit(1);
            }
        }
    }

    private static class OutgoingHandler extends Thread {
        private Socket socket;
        private PrintWriter out;

        public OutgoingHandler(Socket socket, PrintWriter out) {
            this.socket = socket;
            this.out = out;
        }

        public void run() {

            try (BufferedReader stdIn = new BufferedReader(new InputStreamReader(System.in))) {
                String userInput;
                do{
                    System.out.println("Enter message: ");
                    userInput = stdIn.readLine();
                    out.println(userInput);
                }while(userInput != "quit");

            } catch (IOException e) {
                e.printStackTrace();
                System.exit(1);
            }
        }
    }


}
