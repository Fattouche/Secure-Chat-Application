import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.io.*;
import java.util.*;

public class AES {
	static private int ivSize = 16;
	static private int keySize = 16;

	public static byte[] digestMessage(String message) {
		try{
			MessageDigest digest = MessageDigest.getInstance("SHA-256");
			digest.update(message.getBytes());
			byte[] messageDigest = digest.digest();
			return messageDigest;
		}
		catch (Exception e) {
			System.out.println("Error in AES.digestMessage: " + e);
			return null;
		}
	}

	public static Boolean compareDigests(byte[] d1, byte[] d2) {
		if (!Arrays.equals(d1, d2)) return false;
		return true;
	}

	public static byte[] encrypt(String message, String key) {
		try {
			// Generating IV Spec
			byte[] iv = new byte[ivSize];
			SecureRandom random = new SecureRandom();
			random.nextBytes(iv);
			IvParameterSpec ivSpec = new IvParameterSpec(iv);

			// Generate keySpec
			SecretKeySpec keySpec = new SecretKeySpec(key.getBytes(), "AES");

			// Create and initialize the cipher for encryption
			Cipher aesCipher;
			aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			aesCipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);

			// Encrypt the cleartext
			byte[] cleartext = message.getBytes();
			byte[] ciphertext = aesCipher.doFinal(cleartext);

			//return IV + ciphertext
			byte[] encryptedMessage = new byte[ivSize + ciphertext.length];
			System.arraycopy(iv, 0, encryptedMessage, 0, ivSize);
			System.arraycopy(ciphertext, 0, encryptedMessage, ivSize, ciphertext.length);
			return encryptedMessage;
		} catch (Exception e) {
			System.out.println("Error in AES.encrypt: " + e);
			return null;
		}
	}

	public static String decrypt(byte[] encryptedMessage, String key) {
		try {
			// Split the encrypted message into IV and Ciphertext
			byte[] iv = new byte[ivSize];
			byte[] ciphertext = new byte[encryptedMessage.length - ivSize];
			System.arraycopy(encryptedMessage, 0, iv, 0, ivSize);
			System.arraycopy(encryptedMessage, ivSize, ciphertext, 0, encryptedMessage.length - ivSize);

			// Create ivSpec and keySpec
			IvParameterSpec ivSpec = new IvParameterSpec(iv);
			SecretKeySpec keySpec = new SecretKeySpec(key.getBytes(), "AES");

			// Create and initialize the cipher for encryption
			Cipher aesCipher;
			aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			aesCipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);

			// Encrypt the cleartext
			byte[] cleartext = aesCipher.doFinal(ciphertext);
			return new String(cleartext);
		} catch (Exception e) {
			System.out.println("Error in AES.decrypt: " + e);
			return null;
		}
	}
	
	/*
	// THIS IS USED FOR TESTING PURPOSED ONLY

	public static void main(String args[]) {
		String message = "HELLO WORLD";
		String key = "0123456789abcdef";
	
		try {
			byte[] d1 = digestMessage(message);
			byte[] d2 = digestMessage(message);
	
			byte[] e = encrypt(message, key);
			String d = decrypt(e, key);
	
			if(!compareDigests(d1, d2)) System.out.println("No Bueno");
	
			if (!message.equals(d)) System.out.println("No bueno");
		
		} catch(Exception e) {}
	}
	*/
}
