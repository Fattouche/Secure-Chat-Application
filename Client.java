import java.net.*;
import java.io.*;
import java.util.*;

public class Client {
      public static void startClient(String serverName, int serverPort) throws UnknownHostException, IOException {
            System.out.println("Trying to connect to host: " + serverName + ": " + serverPort);
            Socket socket = new Socket(serverName, serverPort);
            System.out.println("Connected!");

            BufferedReader input = new BufferedReader(new InputStreamReader(System.in));
            PrintWriter clientMessage = new PrintWriter(socket.getOutputStream(), true);
            BufferedReader serverMessage = new BufferedReader(new InputStreamReader(socket.getInputStream()));

            Thread sendMessage = new Thread(new Runnable() {
                  @Override
                  public void run() {
                        String send;
                        try {

                              while (true) {
                                    send = input.readLine();
                                    clientMessage.println(send);
                                    clientMessage.flush();
                                    if (send.toString().equals("bye")) {
                                          System.out.println("Closed Connection with Server");
                                          break;
                                    }
                              }
                        } catch (IOException ioe) {
                              System.out.println("Error closing ...");
                        }
                  }
            });

            Thread readMessage = new Thread(new Runnable() {
                  @Override
                  public void run() {
                        String recieve;
                        try {
                              while (true) {
                                    recieve = serverMessage.readLine();
                                    System.out.println("server: " + recieve);
                              }
                        } catch (IOException ioe) {
                              System.out.println("Error closing ...");
                        }
                  }
            });

            sendMessage.start();
            readMessage.start();
      }

      public static void main(String args[]) {
            if (args.length != 2) {
                  System.out.println("Usage: java Client <host> <port>");
            } else {
                  // Prompt user to enable/disable security properties
                  Scanner reader = new Scanner(System.in);
                  String confidentiality, integrity, authenticaion;
                  
                  System.out.println("Require confidentiality? (y or n)");
                  while(true){
                        confidentiality = reader.nextLine();
                        if(confidentiality.equals("y") || confidentiality.equals("n")) break; 
                        System.out.println("Invalid input, try again.");
                  }
                  System.out.println("Require integrity? (y or n)");
                  while(true){
                        integrity = reader.nextLine();
                        if(integrity.equals("y") || integrity.equals("n")) break; 
                        System.out.println("Invalid input, try again.");
                  }
                  System.out.println("Require authenticaion? (y or n)");
                   while(true){
                        authenticaion = reader.nextLine();
                        if(authenticaion.equals("y") || authenticaion.equals("n")) break; 
                        System.out.println("Invalid input, try again.");
                  }
                  reader.close();

                  String hostName = args[0];
                  int portNumber = Integer.parseInt(args[1]);
                  try {
                        startClient(hostName, portNumber);
                  } catch (UnknownHostException uhe) {
                        System.out.println("Host unknown: " + uhe.getMessage());
                  } catch (IOException ioe) {
                        System.out.println("Unexpected exception: " + ioe.getMessage());
                  }
            }
      }
}