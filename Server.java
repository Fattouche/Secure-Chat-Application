import java.net.*;
import java.io.*;
import java.util.*;
import java.nio.file.*;

public class Server {
      public static void main(String[] args) throws Exception {
            int portNumber = 8080;
            Security security = null;
            if (args.length != 1) {
                  System.out.println("Usage: java server <port>");
            } else {
                  security = new Security();

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
                  System.err.println("Open session message recieved, comparing protocol");
                  ClientHandler handler = new ClientHandler(socket, input, security);
                  handler.handleClient();
            }
            server.close();
            input.close();
      }
}

class ClientHandler extends Thread {
      static BufferedReader input;
      static OutputStream serverStream;
      static InputStream clientStream;
      static Socket socket;
      static boolean connected;
      static Security security;
      static byte[] key = null;

      public ClientHandler(Socket socket, BufferedReader input, Security security) {
            this.socket = socket;
            this.input = input;
            this.security = security;
            this.connected = true;
      }

      public static void handleClient() throws IOException {
            serverStream = socket.getOutputStream();
            clientStream = socket.getInputStream();
            try {
                  if (invalidProtocol(clientStream, serverStream)) {
                        return;
                  }
            } catch (IOException ioe) {
                  System.out.println("Client closed connection");
            }
            if (security.confidentiality || security.integrity) {
                  key = DoServerDiffie.doServerDiffie(clientStream, serverStream);
            }

            Thread sendMessage = new Thread(new Runnable() {
                  @Override
                  public void run() {
                        String send;
                        try {
                              while (connected) {
                                    send = input.readLine();
                                    if (!socket.isClosed()) {
                                          AES.encrypt(send, key);
                                          serverStream.write(send.getBytes());
                                    }
                              }
                        } catch (IOException ioe) {
                              System.out.println("Client closed connection");
                        }
                  }
            });

            Thread readMessage = new Thread(new Runnable() {
                  @Override
                  public void run() {
                        try {
                              while (true) {
                                    byte[] msg = new byte[16 * 1024];
                                    int count = clientStream.read(msg);
                                    String s = AES.decrypt(msg, key);
                                    System.out.println("decrypted client: " + s);
                                    if (s.equals("bye")) {
                                          System.out.println("Client closed connection");
                                          disconnect();
                                          connected = false;
                                          break;
                                    }
                              }
                        } catch (IOException ioe) {
                              System.out.println("Client closed connection");
                        }
                  }
            });

            sendMessage.start();
            readMessage.start();
      }

      public static void disconnect() {
            try {
                  serverStream.close();
                  clientStream.close();
                  socket.close();
            } catch (IOException e) {
                  e.printStackTrace();
            }
      }

      public static boolean invalidProtocol(InputStream clientStream, OutputStream serverStream) throws IOException {
            byte[] msg = new byte[16 * 1024];
            int count = clientStream.read(msg);
            String s = new String(msg, 0, count, "US-ASCII");
            String errorLog = "invalid security protocol, dropping connection";
            if ((s.contains("a") && !security.authentication) || (!s.contains("a") && security.authentication)) {
                  serverStream.write("invalid security protocol, authentication not matching. re-establish connection"
                              .getBytes());
                  System.out.println(errorLog);
                  return true;
            }
            if ((s.contains("i") && !security.integrity) || (!s.contains("i") && security.integrity)) {
                  serverStream.write(
                              "invalid security protocol, integrity not matching. re-establish connection".getBytes());
                  System.out.println(errorLog);
                  return true;
            }
            if ((s.contains("c") && !security.confidentiality) || (!s.contains("c") && security.confidentiality)) {
                  serverStream.write("invalid security protocol, confidentiality not matching. re-establish connection"
                              .getBytes());
                  System.out.println(errorLog);
                  return true;
            }
            String reply = "Valid protocol, beginning DH";
            System.out.println(reply);
            serverStream.write(reply.getBytes());
            return false;
      }
}