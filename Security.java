import java.util.*;

//Checks the security options that the user wants
public class Security {
      //Fields used for the security object
      public static Boolean confidentiality;
      public static Boolean integrity;
      public static Boolean authentication;

      public Security() {
            checkUserInput();
      }

      //Deals with users inputs and sets the respective field values
      public static void checkUserInput() {
            // Prompt user to enable/disable security properties
            Scanner reader = new Scanner(System.in);
            String c, i, a;

            System.out.println("Require confidentiality? (y or n)");
            while (true) {
                  c = reader.nextLine();
                  if (c.equals("y")) {
                        confidentiality = true;
                        break;
                  } else if (c.equals("n")) {
                        confidentiality = false;
                        break;
                  }
                  System.out.println("Invalid input, try again.");
            }

            System.out.println("Require integrity? (y or n)");
            while (true) {
                  i = reader.nextLine();
                  if (i.equals("y")) {
                        integrity = true;
                        break;
                  } else if (i.equals("n")) {
                        integrity = false;
                        break;
                  }
                  System.out.println("Invalid input, try again.");
            }

            System.out.println("Require authentication? (y or n)");
            while (true) {
                  a = reader.nextLine();
                  if (a.equals("y")) {
                        authentication = true;
                        break;
                  } else if (a.equals("n")) {
                        authentication = false;
                        break;
                  }
                  System.out.println("Invalid input, try again.");
            }
      }
}
