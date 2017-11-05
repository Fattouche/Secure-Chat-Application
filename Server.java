import java.net.*;
import java.io.*;
import java.util.*;
import java.nio.file.*;
import javax.crypto.Mac;

//Server side of the chat
public class Server {
      //reads users input and listens on the specific port.
      public static void main(String[] args) throws Exception {
            int portNumber = 8080;
            Security security = null;
            if (args.length != 1) {
                  System.out.println("Usage: java server <port>");
                  return;
            }
            security = new Security();

            //If they want authentication, verify their password.
            if (security.authentication) {
                  PasswordTools.verifyPassword(Paths.get("server_private", "pass"));
            }
            portNumber = Integer.parseInt(args[0]);

            //Setup server
            boolean isOver = false;
            BufferedReader input = new BufferedReader(new InputStreamReader(System.in));
            System.out.println("Binding to port " + portNumber);
            ServerSocket server = new ServerSocket(portNumber);
            System.out.println("Server started: " + server);

            //Loops and creates new ClientHandler objects, allows for server to persist even when client closes connection.
            while (!isOver) {
                  Socket socket = server.accept();
                  System.err.println("Open session message recieved, comparing protocol.");
                  ClientHandler handler = new ClientHandler(socket, input, security);
                  handler.handleClient();
            }
            server.close();
            input.close();
      }
}

//Class used to handle new clients accessing the socket
class ClientHandler {
      //Needed variables
      static BufferedReader input;
      static OutputStream serverStream;
      static InputStream clientStream;
      static Socket socket;
      static boolean connected;
      static Security security;
      static byte[] key = null;
      static Cryptography crypto;
      static Communication communication;

      //Constructor for established socket and I/O
      public ClientHandler(Socket socket, BufferedReader input, Security security) {
            this.socket = socket;
            this.input = input;
            this.security = security;
            this.connected = true;
      }

      //Actually read and write to the client
      public static void handleClient() throws IOException {
            serverStream = socket.getOutputStream();
            clientStream = socket.getInputStream();
            crypto = new Cryptography();
            communication = new Communication();

            try {
                  if (invalidProtocol(clientStream, serverStream)) {
                        return;
                  }
            } catch (IOException ioe) {
                  System.out.println("Client closed connection.");
            }
            if (security.confidentiality || security.integrity) {
                  key = ServerDiffie.doDiffie(clientStream, serverStream);
            }

            //Spins up a thread for reading from input and sending to outputstream
            Thread sendMessage = new Thread(new Runnable() {
                  @Override
                  public void run() {
                        String send;
                        byte[] encrypted;
                        try {
                              while (connected) {
                                    send = input.readLine();
                                    if (!socket.isClosed()) {
                                          //Format the message.
                                          byte[] signature = crypto.sign(send.getBytes(),
                                                      Paths.get("server_private", "private.der"),
                                                      security.authentication);
                                          byte[] mac = crypto.generateMAC(send.getBytes(), key, security.integrity);
                                          byte[] message = crypto.encrypt(send.getBytes(), key,
                                                      security.confidentiality);
                                          byte[] finalMessage = communication.format(message, signature, mac);
                                          serverStream.write(finalMessage);
                                    }
                              }
                        } catch (IOException ioe) {
                              System.out.println("Client closed connection.");
                        }
                  }
            });

            //Spin up a thread to read from inputstream and write to command line.
            Thread readMessage = new Thread(new Runnable() {
                  @Override
                  public void run() {
                        try {
                              while (true) {
                                    byte[] msg = new byte[16 * 1024];
                                    int count = clientStream.read(msg);
                                    msg = Arrays.copyOf(msg, count);
                                    String message = communication.handleMessage(msg,
                                                Paths.get("server_private", "publicClient.der"), crypto, key, security);
                                    System.out.println("client: " + message);
                                    if (message.equals("bye")) {
                                          System.out.println("Client closed connection.");
                                          disconnect();
                                          connected = false;
                                          break;
                                    }
                              }
                        } catch (IOException ioe) {
                              System.out.println("Client closed connection.");
                        }
                  }
            });

            sendMessage.start();
            readMessage.start();
      }

      //Clean up streams.
      public static void disconnect() {
            try {
                  serverStream.close();
                  clientStream.close();
                  socket.close();
            } catch (IOException e) {
                  e.printStackTrace();
            }
      }

      //Recieve protocol from client and validate that it is the same as servers.
      public static boolean invalidProtocol(InputStream clientStream, OutputStream serverStream) throws IOException {
            byte[] msg = new byte[16 * 1024];
            int count = clientStream.read(msg);
            String s = new String(msg, 0, count, "US-ASCII");
            String errorLog = "invalid security protocol, dropping connection.";
            if ((s.contains("a") && !security.authentication) || (!s.contains("a") && security.authentication)) {
                  serverStream.write("invalid security protocol, authentication not matching. re-establish connection."
                              .getBytes());
                  System.out.println(errorLog);
                  return true;
            }
            if ((s.contains("i") && !security.integrity) || (!s.contains("i") && security.integrity)) {
                  serverStream.write(
                              "invalid security protocol, integrity not matching. re-establish connection.".getBytes());
                  System.out.println(errorLog);
                  return true;
            }
            if ((s.contains("c") && !security.confidentiality) || (!s.contains("c") && security.confidentiality)) {
                  serverStream.write("invalid security protocol, confidentiality not matching. re-establish connection."
                              .getBytes());
                  System.out.println(errorLog);
                  return true;
            }
            String reply = "Valid protocol.";
            if (security.confidentiality || security.integrity) {
                  reply += "Beginning DH.";
            }
            System.out.println(reply);
            serverStream.write(reply.getBytes());
            return false;
      }
}