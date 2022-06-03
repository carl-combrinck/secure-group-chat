package com.securegroupchat;
import java.net.*;
import java.io.*;

public class Server{
    private final int port;
    private boolean listening = true;
    public Server(){
        this.port = 4444;
    }

    public Server(int port){
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

    public void start(){

        try(ServerSocket serverSocket = new ServerSocket(port)){
            System.out.println("Server Initialising.");
            while(listening){
                System.out.println("Server Listening.");
                Socket socket = serverSocket.accept(); //listen for incoming client connections
                new ClientHandler(socket).start();
            }

        }catch(IOException e){
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
            try (PrintWriter out = new PrintWriter(clientSocket.getOutputStream(), true);
                 BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()))
            ) {

                String inputLine, outputLine;
                out.println("Connection to server successful.");

                while (connectionActive){
                    try{
                        inputLine = in.readLine();
                        outputLine = "Echo back => "+inputLine;
                        out.println(outputLine);
                    }catch(IOException e){
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
