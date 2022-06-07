package com.securegroupchat;

import com.securegroupchat.LoggingLevel;

import java.net.*;
import java.io.*;
import java.util.*;
import java.util.logging.Logger;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;

/**
 * Server is a class that facilitates the secure PGP communication between multiple Clients.
 * An instance of the Server class is started and listens on a given port for incoming client connections.
 * Acts an intermediary that forwards X509 certificates and secure PGP messages between clients.
 *
 * @author Jaron Cohen
 * @author Carl Combrinck
 * @author Bailey Green
 * @version 1.0.0
 */
public class Server {

    private final int port;
    private boolean listening = true;
    // Logging constants
    private final static Logger logger = Logger.getLogger(Client.class.getName());
    private final static String logTemplate = "%-20s%-5s%-10s%15s -> %s";
    private final static String errTemplate = "%-20s%s";
    // Client handlers
    private final Set<ClientHandler> clientHandlers = new HashSet<>();

    /**
     * Default class constructor
     */
    public Server() {
        this.port = 4444;
    }

    /**
     * Parameterized class constructor
     * @param port Port to listen on
     */
    public Server(int port) {
        this.port = port;
    }

    /**
     * Thread-safe method to add client handler
     * @param client The client handler to add
     */
    public void addClientHandler(ClientHandler client){
        synchronized(this.clientHandlers){
            this.clientHandlers.add(client);
        }
    }

    /**
     * Thread-safe method to remove connected clients
     * @param client The client handler to remove
     */
    public void removeClientHandler(ClientHandler client){
        synchronized(this.clientHandlers){
            this.clientHandlers.remove(client);
        }
    }

    /**
     * Method to broadcast certificate received from new client to other connected clients
     * @param originalMessage The received certificate message
     */
    public void broadcastCertificate(CertificateMessage originalMessage){
        synchronized(this.clientHandlers){
            for(ClientHandler client : this.clientHandlers){
                if(!client.clientName.equals(originalMessage.getSender())){
                    try {
                        // Send new certificate message containing certificate to each client (this is not a reply certificate)
                        CertificateMessage certificateMessage = new CertificateMessage(originalMessage.getSender(), client.getClientName(), originalMessage.getCertificate(), false);
                        client.writeToStream(certificateMessage);
                        logger.log(LoggingLevel.INFO, String.format(logTemplate, "[TRANSMISSION]", "OUT", "<CERT>", originalMessage.getSender(), certificateMessage.getReceiver()));
                    } catch (IOException e) {
                        logger.log(LoggingLevel.INFO, String.format(errTemplate, "[SEND_ERR]", "Could not forward certificate to " + client.getClientName()));
                    }
                }
            }
        }
    }

    /**
     * Sends certificate to requested recipient on behalf of client
     * @param originalMessage The certificate message to forward on
     */
    public void forwardCertificate(CertificateMessage originalMessage){
        synchronized(this.clientHandlers){
            for(ClientHandler client : this.clientHandlers){
                // Forward certificate to intended client
                if(client.clientName.equals(originalMessage.getReceiver())){
                    try {
                        client.writeToStream(originalMessage);
                        logger.log(LoggingLevel.INFO, String.format(logTemplate, "[TRANSMISSION]", "OUT", "<CERT>", originalMessage.getSender(), originalMessage.getReceiver()));
                    }catch(IOException e){
                        logger.log(LoggingLevel.INFO, String.format(errTemplate, "[SEND_ERR]", "Could not forward certificate to " + client.getClientName()));
                    }
                    break;
                }
            }
        }
    }

    /**
     * Sends PGP message to requested recipient on behalf of client
     * @param originalMessage The message to be forwarded
     */
    public void forwardPGPMessage(PGPMessage originalMessage){
        synchronized(this.clientHandlers){
            for(ClientHandler client : this.clientHandlers){
                // Forward certificate to intended client
                if(client.clientName.equals(originalMessage.getReceiver())){
                    try {
                        client.writeToStream(originalMessage);
                        logger.log(LoggingLevel.INFO, String.format(logTemplate, "[TRANSMISSION]", "OUT", "<PGP>", originalMessage.getSender(), originalMessage.getReceiver()));
                    }catch(IOException e){
                        logger.log(LoggingLevel.INFO, String.format(errTemplate, "[SEND_ERR]", "Could not forward PGP message to " + client.getClientName()));
                    }
                }
            }
        }
    }

    /**
     * Creates a server instance and starts server setup process
     * @param args Command lines arguments
     */
    public static void main(String[] args) {

        Server server;
        logger.setLevel(LoggingLevel.INFO);

        if (args.length == 0) {
            server = new Server();
            server.start();
        } else if (args.length == 1) {
            server = new Server(Integer.parseInt(args[0]));
            server.start();
        } else {
            logger.log(LoggingLevel.INFO, String.format(errTemplate, "[ARGS_ERR]", "Usage: java Server <port number>"));
            System.exit(1);
        }
    }

    /**
     * Starts server listening on specified port for incoming client connections.
     * Hands off incoming client connections to ClientHandler instances.
     */
    public void start() {

        try (ServerSocket serverSocket = new ServerSocket(port)) {
            logger.log(LoggingLevel.INFO, String.format(errTemplate, "[INIT]", "Server starting..."));
            while (listening) {
                logger.log(LoggingLevel.INFO, String.format(errTemplate, "[INIT]", "Server listening..."));
                Socket socket = serverSocket.accept(); // listen for incoming client connections

                ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
                ObjectInputStream in = new ObjectInputStream(socket.getInputStream());
                ClientHandler clientHandler = new ClientHandler(socket, in, out);
                addClientHandler(clientHandler);
                clientHandler.start();
            }

        } catch (IOException e) {
            logger.log(LoggingLevel.INFO, String.format(errTemplate, "[PORT_ERR]", "Could not listen on port " + this.port));
            System.exit(-1);
        }
    }

    /**
     * ClientHandler is a private inner class that extends Thread and is spawned by the server for every accepted incoming
     * client connection. The ClientHandler thread is responsible for receiving the message objects sent from the clients
     * to the server and calling the necessary Server methods to forward/broadcast them according to the protocol.
     *
     * @author Jaron Cohen
     * @author Carl Combrinck
     * @author Bailey Green
     * @version 1.0.0
     */
    private class ClientHandler extends Thread {
        private Socket clientSocket;
        private ObjectOutputStream out;
        private ObjectInputStream in;
        private String clientName = null;
        private boolean connectionActive = true;

        /**
         * Class constructor
         * @param socket - socket created by server to communicate with connected client
         * @param in - ObjectInputStream to read in message objects sent by client
         * @param out - ObjectOutputStream to send message objects to client
         */
        public ClientHandler(Socket socket, ObjectInputStream in, ObjectOutputStream out) {
            super();
            this.clientSocket = socket;
            this.out = out;
            this.in = in;
            logger.log(LoggingLevel.INFO, String.format(errTemplate, "[SOCKET]", "New socket connection created."));
        }

        /**
         * Setter method to store client's group chat name/alias
         * @param clientName
         */
        private void setClientName(String clientName){
            this.clientName = clientName;
        }

        /**
         * Getter method to retrieve client's group chat name/alias
         * @return
         */
        private String getClientName(){
            return clientName;
        }


        /**
         * Concurrent writing to ObjectOutputStream
         * @param obj - Object to write
         * @throws IOException
         */
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

                        if (message instanceof CertificateMessage) {

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

                                logger.log(LoggingLevel.INFO, String.format(logTemplate, "[TRANSMISSION]", "IN", "<CERT>", certificateMessage.getSender(), certificateMessage.getReceiver()));
                                Server.this.broadcastCertificate(certificateMessage);

                                //Notify client that certificate has been broadcast - client can then begin sending messages
                                CommandMessage broadcastReply = new CommandMessage("server", getClientName(),"CERT_BROADCAST");
                                writeToStream(broadcastReply);
                                logger.log(LoggingLevel.INFO, String.format(logTemplate, "[TRANSMISSION]", "OUT", "<CMD>", "CERT_SENT", broadcastReply.getReceiver()));

                            } // Otherwise received CertificateMessage for forwarding purposes
                            else{
                                logger.log(LoggingLevel.INFO, String.format(logTemplate, "[TRANSMISSION]", "IN", "<CERT>", certificateMessage.getSender(), certificateMessage.getReceiver()));
                                // Forward certificate for client
                                Server.this.forwardCertificate(certificateMessage);
                            }

                        }else if (message instanceof PGPMessage){

                            PGPMessage pgpMessage = (PGPMessage) message;
                            logger.log(LoggingLevel.INFO, String.format(logTemplate, "[TRANSMISSION]", "IN", "<PGP>", pgpMessage.getSender(), pgpMessage.getReceiver()));
                            //Forward message for client
                            Server.this.forwardPGPMessage(pgpMessage);
                        }
                    } catch (IOException | ClassNotFoundException e) {
                        connectionActive = false;
                        Server.this.clientHandlers.remove(this);
                        logger.log(LoggingLevel.INFO, String.format(errTemplate, "[SOCKET]", "Client " + this.clientName + " disconnected."));
                    }
                }

                clientSocket.close();

            } catch (IOException e) {
                e.printStackTrace();
            }

        }

    }

}
