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

    // Thread-safe adding of client
    public void addClientHandler(ClientHandler client){
        synchronized(this.clientHandlers){
            this.clientHandlers.add(client);
        }
    }

    // Thread-safe removing of client
    public void removeClientHandler(ClientHandler client){
        synchronized(this.clientHandlers){
            this.clientHandlers.remove(client);
        }
    }

    // Broadcasts certificates to all connected clients
    public void broadcastCertificate(CertificateMessage originalMessage){
        synchronized(this.clientHandlers){
            for(ClientHandler client : this.clientHandlers){
                try {
                    //TODO Add Receiver (need to have alias stored with handler)
                    CertificateMessage certificateMessage = new CertificateMessage(originalMessage.getSender(), "", originalMessage.getCertificate());
                    client.writeToStream(certificateMessage);
                    System.out.println(String.format("%-15s%-5s%-10s%-10s", certificateMessage.getReceiver(), "OUT", "<CERT>", ""));
                } catch (IOException e) {
                    System.out.println("Error forwarding certificate to client.");
                }
            }
        }
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

                ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
                ObjectInputStream in = new ObjectInputStream(socket.getInputStream());
                ClientHandler clientHandler = new ClientHandler(socket, in, out);
                addClientHandler(clientHandler);
                clientHandler.start();
            }

        } catch (IOException e) {
            System.err.println("Could not listen on port " + port);
            System.exit(-1);
        }
    }

    private class ClientHandler extends Thread {
        private Socket clientSocket;
        private ObjectOutputStream out;
        private ObjectInputStream in;
        private boolean connectionActive = true;

        public ClientHandler(Socket socket, ObjectInputStream in, ObjectOutputStream out) {
            super();
            this.clientSocket = socket;
            this.out = out;
            this.in = in;
            System.out.println("ClientHandler created.");
        }

        // Concurrent writing to output stream
        public void writeToStream(Object obj) throws IOException{
            synchronized(this.out){
                out.writeObject(obj);
            }
        }

        public void run() {

            try {

                writeToStream(new CommandMessage("server", null, "CONN_SUCC"));

                while (connectionActive) {
                    try {
                        Object message = in.readObject();

                        if (message instanceof CommandMessage){

                            CommandMessage commandMessage = (CommandMessage) message;

                            // Quit Command
                            if(commandMessage.getCommand().equals("QUIT")){
                                System.out.println(String.format("%-15s%-5s%-10s%-10s", commandMessage.getSender(), "IN", "<CMD>", "QUIT"));
                                CommandMessage done = new CommandMessage("server", commandMessage.getSender(), "CONN_END");
                                writeToStream(done);
                                System.out.println(String.format("%-15s%-5s%-10s%-10s", commandMessage.getSender(), "OUT", "<CMD>", "DONE"));
                                connectionActive = false;
                                Server.this.removeClientHandler(this);
                            }
                            else{
                                // TODO Remove, just for testing
                                System.out.println(String.format("%-15s%-10s%-10s", commandMessage.getSender(), "<U_CMD>", commandMessage.getCommand()));
                            }

                        } else if (message instanceof CertificateMessage) {

                            CertificateMessage certificateMessage = (CertificateMessage) message;
                            if(certificateMessage.getReceiver().equals("<ALL>")){
                                Server.this.broadcastCertificate(certificateMessage);
                                System.out.println(String.format("%-15s%-10s%-10s", certificateMessage.getSender(), "IN", "<CERT>", certificateMessage.getReceiver()));
                            }
                            else{
                                // TODO Forward certificate onto correct client
                            }
                            
                            //System.out.println(certificateMessage.getCertificate());

                        }else if (message instanceof PGPMessage){

                            PGPMessage pgpMessage = (PGPMessage) message;

                        }
                    } catch (IOException | ClassNotFoundException e) {
                        connectionActive = false;
                        Server.this.clientHandlers.remove(this);
                        System.out.println("Could not reach client, terminating handler.");
                    }
                }

                clientSocket.close();

            } catch (IOException e) {
                e.printStackTrace();
            }

        }

    }

}
