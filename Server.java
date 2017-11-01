import java.net.*;
import java.io.*;
import java.util.*;

public class Server {
      public static void startServer(int port) throws IOException {
            System.out.println("Binding to port " + port);
            ServerSocket server = new ServerSocket(port);

            System.out.println("Server started: " + server);
            System.out.println("Waiting for a client ...");
            Socket socket = server.accept();
            System.out.println("Connected!");

            BufferedReader input = new BufferedReader(new InputStreamReader(System.in));
            PrintWriter serverMessage = new PrintWriter(socket.getOutputStream(), true);
            BufferedReader clientMessage = new BufferedReader(new InputStreamReader(socket.getInputStream()));

            Thread sendMessage = new Thread(new Runnable() {
                  @Override
                  public void run() {
                        String send;
                        try {

                              while (true) {
                                    send = input.readLine();
                                    serverMessage.println(send);
                                    serverMessage.flush();
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
                                    recieve = clientMessage.readLine();
                                    System.out.println("client: " + recieve);
                                    if (recieve.toString().equals("bye")) {
                                          System.out.println("Client closed connection");
                                          break;
                                    }
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
            if (args.length != 1) {
                  System.out.println("Usage: java server <port>");
            } else {
                  Security security = new Security();

                  int portNumber = Integer.parseInt(args[0]);
                  try {
                        startServer(portNumber);
                  } catch (IOException ioe) {
                        System.out.println("Unexpected exception: " + ioe.getMessage());
                  }
            }
      }
}