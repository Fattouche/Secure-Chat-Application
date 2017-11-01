import java.net.*;
import java.io.*;

public class Server
{  
   public static void startServer(int port) throws IOException {  
      /*BufferedReader input = null;
      BufferedReader clientMessage = null;
      PrintWriter serverMessage = null; 
      Socket socket = null;
      try {  
            System.out.println("Binding to port " + port);
            ServerSocket server = new ServerSocket(port);  
            System.out.println("Server started: " + server);
            System.out.println("Waiting for a client ..."); 
            socket = server.accept();
            System.out.println("Client accepted: " + socket);
            clientMessage = new BufferedReader( new InputStreamReader(socket.getInputStream()));
            input = new BufferedReader(new InputStreamReader(System.in));
            serverMessage = new PrintWriter(socket.getOutputStream(),true);
            String recieve,send;
            while (true) {  
                  if(clientMessage.ready()) {
                              recieve = clientMessage.readLine();
                              System.out.println("client: "+recieve); 
                              if(recieve.toString().equals("bye")){
                                    System.out.println("Client closed connection");
                                    break;
                              }
                  }    
                  if(input.ready()){  //causes us to not be able to see console.
                        send = input.readLine();  
                        serverMessage.println(send);       
                        serverMessage.flush();    
                  }              
            }
            if (input != null){ 
                  input.close();
            }
            if (clientMessage != null){
                  clientMessage.close();
            } 
            if (socket != null){
                  socket.close();
            }  
      }
      catch(IOException ioe){  
            System.out.println(ioe); 
      }*/

      System.out.println("Binding to port " + port);
      ServerSocket server = new ServerSocket(port);  

      System.out.println("Server started: " + server);
      System.out.println("Waiting for a client ..."); 
      Socket socket = server.accept();
      System.out.println("Connected!");

      BufferedReader input = new BufferedReader(new InputStreamReader(System.in));
      PrintWriter serverMessage = new PrintWriter(socket.getOutputStream(),true);
      BufferedReader clientMessage = new BufferedReader( new InputStreamReader(socket.getInputStream()));

      Thread sendMessage = new Thread(new Runnable()
      {
          @Override
          public void run() {
                  String send;
                  try{
                       
                  while (true) {
                        send = input.readLine();  
                        serverMessage.println(send);       
                        serverMessage.flush();    
                  }
            }catch(IOException ioe) {  
                  System.out.println("Error closing ...");
            }
          }
      });

      Thread readMessage = new Thread(new Runnable() 
      {
          @Override
          public void run() {
            String recieve;
            try{
              while (true) {
                  recieve = clientMessage.readLine();
                  System.out.println("client: "+recieve); 
                  if(recieve.toString().equals("bye")){
                        System.out.println("Client closed connection");
                        break;
                  }
              }
            }catch(IOException ioe) {  
                  System.out.println("Error closing ...");
            }
          }
      });

      sendMessage.start();
      readMessage.start();
   }

   public static void main(String args[]) {  
      if (args.length != 1){
            System.out.println("Usage: java server <port>");
      }
      else{
            int portNumber = Integer.parseInt(args[0]);
            try{
                  startServer(portNumber);
            }
            catch(IOException ioe){  
                  System.out.println("Unexpected exception: " + ioe.getMessage());
            }
      }
   }
}