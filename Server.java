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
            OutputStream serverMessage = socket.getOutputStream();
            InputStream clientMessage = socket.getInputStream();

            Thread sendMessage = new Thread(new Runnable() {
                  @Override
                  public void run() {
                        String send;
                        try {

                              while (true) {
                                    send = input.readLine();
                                    serverMessage.write(send.getBytes());
                              }
                        } catch (IOException ioe) {
                              System.out.println("Error closing ...");
                        }
                  }
            });

            Thread readMessage = new Thread(new Runnable() {
                  @Override
                  public void run() {
                        try {
                              while (true) {
                                    byte[] msg = new byte[16 * 1024];
                                    int count = clientMessage.read(msg);
                                    String s = new String(msg, 0, count, "US-ASCII");
                                    System.out.println("client: " + s);
                                    if (s.equals("bye")) {
                                          System.out.println("Client closed connection");
                                          server.close();
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
                  ServerPassword passChecker = new ServerPassword();
                  Security security = new Security();

                  if (security.authentication) {
                        passChecker.checkPassword();
                  }

                  int portNumber = Integer.parseInt(args[0]);
                  try {
                        startServer(portNumber);
                  } catch (IOException ioe) {
                        System.out.println("Unexpected exception: " + ioe.getMessage());
                  }
            }
      }
}