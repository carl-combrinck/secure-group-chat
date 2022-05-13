package com.nis;

import java.net.*;
import java.io.*;

public class Client {
    private final String hostname;
    private final int port;

    public Client() {
        this.hostname = "localhost";
        this.port = 4444;
    }

    public Client(String hostname, int port) {
        this.hostname = hostname;
        this.port = port;
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

    public static void main(String[] args) {
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
