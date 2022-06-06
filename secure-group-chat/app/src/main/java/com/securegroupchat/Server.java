package com.securegroupchat;

import java.net.*;
import java.io.*;
import java.util.*;
import java.util.logging.Logger;
import java.util.logging.Level;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;

public class Server {
    private final int port;
    private boolean listening = true;
    private final static Logger logger = Logger.getLogger(Client.class.getName());
    private final static String logTemplate = "%-15s%-5s%-10s%s";
    private final static String errTemplate = "%-15s%s";

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
                    logger.log(Level.INFO, String.format(logTemplate, certificateMessage.getReceiver(), "OUT", "<CERT>", client.getClientName()));
                } catch (IOException e) {
                    logger.log(Level.INFO, String.format(errTemplate, "SEND_ERR", "Could not forward certificate to " + client.getClientName()));
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
                        logger.log(Level.INFO, String.format(logTemplate, originalMessage.getReceiver(), "OUT", "<CERT>", originalMessage.getSender()));
                    }catch(IOException e){
                        logger.log(Level.INFO, String.format(errTemplate, "SEND_ERR", "Could not forward certificate to " + client.getClientName()));
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
                        logger.log(Level.INFO, String.format(logTemplate, originalMessage.getReceiver(), "OUT", "<PGP>", originalMessage.getSender()));
                    }catch(IOException e){
                        logger.log(Level.INFO, String.format(errTemplate, "SEND_ERR", "Could not forward PGP message to " + client.getClientName()));
                    }
                }
            }
        }
    }

    public static void main(String[] args) {

        Server server;
        logger.setLevel(Level.INFO);

        if (args.length == 0) {
            server = new Server();
            server.start();
        } else if (args.length == 1) {
            server = new Server(Integer.parseInt(args[0]));
            server.start();
        } else {
            logger.log(Level.INFO, String.format(errTemplate, "ARGS_ERR", "Usage: java Server <port number>"));
            System.exit(1);
        }
    }

    public void start() {

        try (ServerSocket serverSocket = new ServerSocket(port)) {
            logger.log(Level.INFO, String.format(errTemplate, "[INIT]", "Server starting..."));
            while (listening) {
                logger.log(Level.INFO, String.format(errTemplate, "[INIT]", "Server listening..."));
                Socket socket = serverSocket.accept(); // listen for incoming client connections

                ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
                ObjectInputStream in = new ObjectInputStream(socket.getInputStream());
                ClientHandler clientHandler = new ClientHandler(socket, in, out);
                addClientHandler(clientHandler);
                clientHandler.start();
            }

        } catch (IOException e) {
            logger.log(Level.INFO, String.format(errTemplate, "PORT_ERR", "Could not listen on port " + this.port));
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
            logger.log(Level.INFO, String.format(errTemplate, "[SOCKET]", "New socket connection created."));
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
                                logger.log(Level.INFO, String.format(logTemplate, commandMessage.getSender(), "IN", "<CMD>", "QUIT"));
                                CommandMessage done = new CommandMessage("server", commandMessage.getSender(), "CONN_END");
                                writeToStream(done);
                                logger.log(Level.INFO, String.format(logTemplate, commandMessage.getSender(), "OUT", "<CMD>", "DONE"));
                                connectionActive = false;
                                Server.this.removeClientHandler(this);
                            }
                            else{
                                logger.log(Level.INFO, String.format(logTemplate, commandMessage.getSender(), "IN", "<CMD>", "UNKNOWN"));
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
                                logger.log(Level.INFO, String.format(logTemplate, certificateMessage.getSender(), "IN", "<CERT>", certificateMessage.getReceiver()));

                                //Notify client that certificate has been broadcast - client can then begin sending messages
                                CommandMessage broadcastReply = new CommandMessage("server", getClientName(),"CERT_BROADCAST");
                                writeToStream(broadcastReply);
                                logger.log(Level.INFO, String.format(logTemplate, broadcastReply.getReceiver(), "OUT", "<CMD>", "CERT_SENT"));

                            } // Otherwise received CertificateMessage for forwarding purposes
                            else{
                                logger.log(Level.INFO, String.format(logTemplate, certificateMessage.getSender(), "IN", "<CERT>", certificateMessage.getReceiver()));
                                // Forward certificate for client
                                Server.this.forwardCertificate(certificateMessage);
                            }

                        }else if (message instanceof PGPMessage){

                            PGPMessage pgpMessage = (PGPMessage) message;
                            logger.log(Level.INFO, String.format(logTemplate, pgpMessage.getSender(), "IN", "<PGP>", pgpMessage.getReceiver()));
                            //Forward message for client
                            Server.this.forwardPGPMessage(pgpMessage);
                        }
                    } catch (IOException | ClassNotFoundException e) {
                        connectionActive = false;
                        Server.this.clientHandlers.remove(this);
                        logger.log(Level.INFO, String.format(errTemplate, "[SOCKET]", "Client " + this.clientName + " disconnected."));
                    }
                }

                clientSocket.close();

            } catch (IOException e) {
                e.printStackTrace();
            }

        }

    }

}
