
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.*;
import java.nio.file.*;
import java.security.MessageDigest;

//A helper file for comparing password entered with hashed password stored in secure file.
class PasswordTools {

    //Hash the password and compare it to the hash stored in the file.
    public static boolean validPassword(String password, Path path) {
        byte byteData[] = null;
        byte toCompare[] = null;
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(password.getBytes());
            byteData = md.digest();
            toCompare = Files.readAllBytes(path);
        } catch (Exception e) {
            System.out.println("Failed to read file");
        }
        if (Arrays.equals(toCompare, byteData)) {
            return true;
        }
        return false;
    }

    //Prompts the user to enter their password and then verifies it.
    static void verifyPassword(Path path) {
        Scanner reader = new Scanner(System.in);
        System.out.println("What is your password?");
        while (true) {
            if (validPassword(reader.nextLine(), path)) {
                System.out.println("Authenticated!");
                break;
            } else {
                System.out.println("Incorrect password, try again.");
            }
        }
    }
}
