import java.net.*;
import java.io.*;
import java.util.*;
import java.nio.file.*;
import javax.crypto.Mac;

//Class that handles client side communication
public class Client {

      //Define needed objects/variables
      static byte[] key = null;
      static Security security;
      static Communication communication;
      static Cryptography crypto;
      static final String closed = "Closed connection with server.";

      //Starts the client and connects to the specific server:port
      public static void startClient(String serverName, int serverPort) throws UnknownHostException, IOException {
            System.out.println("Trying to connect to host: " + serverName + ": " + serverPort);
            Socket socket = new Socket(serverName, serverPort);
            System.out.println("Sending open session message.");

            //Make the socket and get the I/O streams.
            BufferedReader input = new BufferedReader(new InputStreamReader(System.in));
            OutputStream clientStream = socket.getOutputStream();
            InputStream serverStream = socket.getInputStream();
            crypto = new Cryptography();
            communication = new Communication();

            //Send the protocol(CIA) that the client is using, disconnect if not matching.
            if (!verifyProtocol(serverStream, clientStream)) {
                  disconnect(input, serverStream, clientStream, socket);
                  return;
            }

            //If we want encryption or checksum we need to establish a symetric key pair using diffie helmen
            if (security.confidentiality || security.integrity) {
                  key = ClientDiffie.doDiffie(serverStream, clientStream);
            }

            //Spins up a thread for reading from input and sending formatted messages to the server
            Thread sendMessage = new Thread(new Runnable() {
                  @Override
                  public void run() {
                        String send;
                        try {
                              while (true) {
                                    //These functions will only return something useful if we have the respective setting turned on.
                                    send = input.readLine();
                                    //Format the message
                                    byte[] signature = crypto.sign(send.getBytes(),
                                                Paths.get("client_private", "private.der"), security.authentication);
                                    byte[] mac = crypto.generateMAC(send.getBytes(), key, security.integrity);
                                    byte[] message = crypto.encrypt(send.getBytes(), key, security.confidentiality);
                                    byte[] formattedMessage = communication.format(message, signature, mac);
                                    clientStream.write(formattedMessage);

                                    //The client can close the connection by writing bye to the server
                                    if (send.toString().equals("bye")) {
                                          disconnect(input, serverStream, clientStream, socket);
                                          break;
                                    }
                              }
                        } catch (IOException ioe) {
                              System.out.println(closed);
                        }
                  }
            });

            //Spins up a thread for reading from the input socket stream and printing to console.
            Thread readMessage = new Thread(new Runnable() {
                  @Override
                  public void run() {
                        try {
                              while (true) {
                                    byte[] msg = new byte[16 * 1024];
                                    int count = serverStream.read(msg);
                                    msg = Arrays.copyOf(msg, count);
                                    String message = communication.handleMessage(msg,
                                                Paths.get("client_private", "publicServer.der"), crypto, key, security);
                                    System.out.println("server: " + message);
                              }
                        } catch (IOException ioe) {
                              System.out.println(closed);
                        }
                  }
            });

            sendMessage.start();
            readMessage.start();
      }

      //Clean up the connection with the server.
      public static void disconnect(BufferedReader input, InputStream serverStream, OutputStream clientStream,
                  Socket socket) {
            try {
                  input.close();
                  serverStream.close();
                  clientStream.close();
                  socket.close();
            } catch (IOException ioe) {
                  System.out.println(closed);
            }
      }

      //Sends the protocol chosen to the server, acts depending on its reply.
      public static boolean verifyProtocol(InputStream serverStream, OutputStream clientStream) {
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
                  System.out.println(closed);
            }
            if (s.contains("Valid protocol")) {
                  System.out.println(s);
                  return true;
            } else {
                  System.out.println(s);
                  return false;
            }
      }

      //Reads from the command line and starts the client.
      public static void main(String args[]) {
            if (args.length != 2) {
                  System.out.println("Usage: java Client <host> <port>");
                  return;
            }
            security = new Security();

            //If they want authentication, verify their password.
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