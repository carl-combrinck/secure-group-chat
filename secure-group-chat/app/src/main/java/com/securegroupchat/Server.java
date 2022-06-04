package com.securegroupchat;

import java.net.*;
import java.io.*;
import java.util.*;

public class Server {
    private final int port;
    private boolean listening = true;

    private final Set<ClientHandler> clientHandlers = new HashSet<>();

    public Server() {
        this.port = 4444;
    }

    public Server(int port) {
        this.port = port;
    }

    public static void main(String[] args) {

        Server server;

        if (args.length == 0) {
            server = new Server();
            server.start();
        } else if (args.length == 1) {
            server = new Server(Integer.parseInt(args[0]));
            server.start();
        } else {
            System.err.println("Usage: java Server <port number>");
            System.exit(1);
        }
    }

    public void start() {

        try (ServerSocket serverSocket = new ServerSocket(port)) {
            System.out.println("Server Initialising.");
            while (listening) {
                System.out.println("Server Listening.");
                Socket socket = serverSocket.accept(); // listen for incoming client connections

                ClientHandler clientHandler = new ClientHandler(socket);
                clientHandlers.add(clientHandler);
                clientHandler.start();
            }

        } catch (IOException e) {
            System.err.println("Could not listen on port " + port);
            System.exit(-1);
        }
    }

    private class ClientHandler extends Thread {
        private Socket clientSocket;
        private boolean connectionActive = true;

        public ClientHandler(Socket socket) {
            super();
            this.clientSocket = socket;
            System.out.println("ClientHandler created.");
        }

        public void run() {

            try (ObjectOutputStream out = new ObjectOutputStream(clientSocket.getOutputStream());
                    ObjectInputStream in = new ObjectInputStream(clientSocket.getInputStream())) {

                out.writeObject(new CommandMessage("server", null, "Connection to server successful."));

                while (connectionActive) {
                    try {
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

                        }
                    } catch (IOException | ClassNotFoundException e) {
                        e.printStackTrace();
                    }
                }

                clientSocket.close();

            } catch (IOException e) {
                e.printStackTrace();
            }


        }

    }

}
