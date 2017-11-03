import java.net.*;
import java.io.*;
import java.util.*;
import java.nio.file.*;

public class Server {
      public static void main(String[] args) throws Exception {
            int portNumber = 8080;
            if (args.length != 1) {
                  System.out.println("Usage: java server <port>");
            } else {
                  Security security = new Security();

                  if (security.authentication) {
                        PasswordTools.verifyPassword(Paths.get("server_private", "pass"));
                  }
                  portNumber = Integer.parseInt(args[0]);
            }

            boolean isOver = false;
            BufferedReader input = new BufferedReader(new InputStreamReader(System.in));
            System.out.println("Binding to port " + portNumber);
            ServerSocket server = new ServerSocket(portNumber);
            System.out.println("Server started: " + server);

            while (!isOver) {
                  Socket socket = server.accept();
                  System.err.println("Accepted connection from client");
                  ClientHandler handler = new ClientHandler(socket, input);
                  handler.handleClient();
            }
            server.close();
            input.close();
      }
}

class ClientHandler extends Thread {
      static BufferedReader input;
      static OutputStream serverMessage;
      static InputStream clientMessage;
      static Socket socket;
      static boolean connected;

      public ClientHandler(Socket socket, BufferedReader input) {
            this.socket = socket;
            this.input = input;
            this.connected = true;
      }

      public static void handleClient() throws IOException {
            Thread sendMessage = new Thread(new Runnable() {
                  @Override
                  public void run() {
                        String send;
                        try {
                              serverMessage = socket.getOutputStream();
                              while (connected) {
                                    send = input.readLine();
                                    if (!socket.isClosed()) {
                                          serverMessage.write(send.getBytes());
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
                        try {
                              clientMessage = socket.getInputStream();
                              while (true) {
                                    byte[] msg = new byte[16 * 1024];
                                    int count = clientMessage.read(msg);
                                    String s = new String(msg, 0, count, "US-ASCII");
                                    System.out.println("client: " + s);
                                    if (s.equals("bye")) {
                                          System.out.println("Client closed connection");
                                          disconnect();
                                          connected = false;
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

      public static void disconnect() {
            try {
                  serverMessage.close();
                  clientMessage.close();
                  socket.close();
            } catch (IOException e) {
                  e.printStackTrace();
            }
      }
}