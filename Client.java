import java.net.*;
import java.io.*;
import java.util.*;
import java.nio.file.*;

public class Client {
      static Security security;
      static byte[] key = null;

      public static void startClient(String serverName, int serverPort) throws UnknownHostException, IOException {
            System.out.println("Trying to connect to host: " + serverName + ": " + serverPort);
            Socket socket = new Socket(serverName, serverPort);
            System.out.println("Sending open session message");

            BufferedReader input = new BufferedReader(new InputStreamReader(System.in));
            OutputStream clientStream = socket.getOutputStream();
            InputStream serverStream = socket.getInputStream();
            Cryptography crypto = new Cryptography();

            if (invalidProtocol(serverStream, clientStream)) {
                  disconnect(input, serverStream, clientStream, socket);
                  return;
            }

            if (security.confidentiality || security.integrity) {
                  key = DoClientDiffie.doClientDiffie(serverStream, clientStream);
            }

            Thread sendMessage = new Thread(new Runnable() {
                  @Override
                  public void run() {
                        String send;
                        try {
                              while (true) {
                                    send = input.readLine();
                                    byte[] signature =  crypto.sign(send.getBytes(), Paths.get("client_private", "private.der") , security.authentication);
                                    byte[] mac = crypto.generateMAC(send.getBytes(), key, security.integrity);
                                    byte[] message = crypto.encrypt(send.getBytes(), key, security.confidentiality);
                                    byte[] communication = crypto.format(message,signature,mac);
                                    clientStream.write(communication);
                                    if (send.toString().equals("bye")) {
                                          disconnect(input, serverStream, clientStream, socket);
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
                                    int count = serverStream.read(msg);
                                    msg = Arrays.copyOf(msg, count);
                                    //Gurj code here
                                    if(!Cryptography.verify(s, Paths.get("client_private", "p") , security.authentication)){
                                          System.out.println("Signature of client does not match private key!");
                                    }
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

      public static void disconnect(BufferedReader input, InputStream serverStream, OutputStream clientStream,
                  Socket socket) {
            try {
                  input.close();
                  serverStream.close();
                  clientStream.close();
                  socket.close();
            } catch (IOException ioe) {
                  System.out.println("Closed Connection with Server");
            }
      }

      public static boolean invalidProtocol(InputStream serverStream, OutputStream clientStream) {
            String protocol = "N";
            if (security.authentication) {
                  protocol += "a";
            }
            if (security.integrity) {
                  protocol += "i";
            }
            if (security.confidentiality) {
                  protocol += "c";
            }
            String s = "";
            try {
                  clientStream.write(protocol.getBytes());
                  byte[] msg = new byte[16 * 1024];
                  int count = serverStream.read(msg);
                  s = new String(msg, 0, count, "US-ASCII");
            } catch (IOException ioe) {
                  System.out.println("Closed Connection with Server");
            }
            if (s.contains("Valid protocol")) {
                  System.out.println(s);
                  return false;
            } else {
                  System.out.println(s);
                  return true;
            }
      }

      public static void main(String args[]) {
            if (args.length != 2) {
                  System.out.println("Usage: java Client <host> <port>");
                  return;
            }
            security = new Security();

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