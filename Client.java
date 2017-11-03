import java.net.*;
import java.io.*;
import java.util.*;
import java.nio.file.*;

public class Client {
      public static void startClient(String serverName, int serverPort) throws UnknownHostException, IOException {
            System.out.println("Trying to connect to host: " + serverName + ": " + serverPort);
            Socket socket = new Socket(serverName, serverPort);
            System.out.println("Connected!");

            BufferedReader input = new BufferedReader(new InputStreamReader(System.in));
            OutputStream clientMessage = socket.getOutputStream();
            InputStream serverMessage = socket.getInputStream();

            Thread sendMessage = new Thread(new Runnable() {
                  @Override
                  public void run() {
                        String send;
                        try {
                              while (true) {
                                    send = input.readLine();
                                    clientMessage.write(send.getBytes());
                                    if (send.toString().equals("bye")) {
                                          input.close();
                                          serverMessage.close();
                                          clientMessage.close();
                                          socket.close();
                                          break;
                                    }
                              }
                        } catch (IOException ioe) {
                              System.out.println("Closed Connection with Server");
                        }
                  }
            });

            Thread readMessage = new Thread(new Runnable() {
                  @Override
                  public void run() {
                        try {
                              while (true) {
                                    byte[] msg = new byte[16 * 1024];
                                    int count = serverMessage.read(msg);
                                    String s = new String(msg, 0, count, "US-ASCII");
                                    System.out.println("server: " + s);
                              }
                        } catch (IOException ioe) {
                              System.out.println("Closed Connection with Server");
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
                  Security security = new Security();

                  if (security.authentication) {
                        PasswordTools.verifyPassword(Paths.get("client_private", "pass"));
                  }

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