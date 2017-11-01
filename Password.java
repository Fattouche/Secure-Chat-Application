
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.*;
import java.nio.file.*;
import java.security.MessageDigest;


//A helper file for comparing password entered with hashed password stored in secure file.
class PasswordTools {
    public boolean validPassword(String password, Path path) {
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
}

class ClientPassword extends PasswordTools {
    boolean checkPassword(String password) {
        return validPassword(password, Paths.get("client_private", "pass"));
    }
}

class ServerPassword extends PasswordTools {
    boolean checkPassword(String password) {
        return validPassword(password, Paths.get("server_private", "pass"));
    }
}
