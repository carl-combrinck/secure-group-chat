package com.securegroupchat;

import java.net.*;
import java.io.*;
import java.util.*;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;

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
                    CertificateMessage certificateMessage = new CertificateMessage(originalMessage.getSender(), client.getClientName(), originalMessage.getCertificate(), false);
                    client.writeToStream(certificateMessage);
                    System.out.println(String.format("%-15s%-5s%-10s%-10s", certificateMessage.getReceiver(), "OUT", "<CERT>", client.getClientName()));
                } catch (IOException e) {
                    System.out.println("Error broadcasting certificate to client.");
                }
            }
        }
    }

    // Sends certificate to requested recipient on behalf of client
    public void forwardCertificate(CertificateMessage originalMessage){
        synchronized(this.clientHandlers){
            for(ClientHandler client : this.clientHandlers){
                if(client.clientName.equals(originalMessage.getReceiver())){
                    try {
                        client.writeToStream(originalMessage);
                    }catch(IOException e){
                        System.out.println("Error forwarding certificate to client.");
                    }
                }
            }
        }
    }

    // Sends PGP message to requested recipient on behalf of client
    public void forwardPGPMessage(PGPMessage originalMessage){
        synchronized(this.clientHandlers){
            for(ClientHandler client : this.clientHandlers){
                if(client.clientName.equals(originalMessage.getReceiver())){
                    try {
                        client.writeToStream(originalMessage);
                    }catch(IOException e){
                        System.out.println("Error forwarding PGP message to client.");
                    }
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
        private String clientName = null;
        private boolean connectionActive = true;

        public ClientHandler(Socket socket, ObjectInputStream in, ObjectOutputStream out) {
            super();
            this.clientSocket = socket;
            this.out = out;
            this.in = in;
            System.out.println("ClientHandler created.");
        }

        private void setClientName(String clientName){
            this.clientName = clientName;
        }

        private String getClientName(){
            return clientName;
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

                            // If client has sent certificate for broadcast to other clients - occurs when client initially joins group chat
                            if(certificateMessage.getReceiver().equals("<ALL>")){
                                try {
                                    X500Name x500name = new JcaX509CertificateHolder(certificateMessage.getCertificate()).getSubject();
                                    String CNalias = x500name.toString().substring(3);
                                    setClientName(CNalias);
                                }catch (Exception e){
                                    e.printStackTrace();
                                }

                                Server.this.broadcastCertificate(certificateMessage);
                                System.out.println(String.format("%-15s%-10s%-10s", certificateMessage.getSender(), "IN", "<CERT>", certificateMessage.getReceiver()));

                                //Notify client that certificate has been broadcast - client can then begin sending messages
                                CommandMessage broadcastReply = new CommandMessage("server", getClientName(),"CERT_BROADCAST");
                                writeToStream(broadcastReply);

                            } // Otherwise received CertificateMessage for forwarding purposes
                            else{
                                // Forward certificate for client
                                Server.this.forwardCertificate(certificateMessage);
                            }
                            
                            //System.out.println(certificateMessage.getCertificate());

                        }else if (message instanceof PGPMessage){

                            PGPMessage pgpMessage = (PGPMessage) message;
                            //Forward message for client
                            Server.this.forwardPGPMessage(pgpMessage);
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
