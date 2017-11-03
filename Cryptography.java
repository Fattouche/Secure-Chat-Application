import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.spec.*;
import java.security.*;
import java.io.*;
import java.util.*;
import java.nio.file.*;

public class Cryptography {
	static private int ivSize = 16;
	static private int keySize = 16;

	private static PublicKey readPublicKey(Path path) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
	    X509EncodedKeySpec publicSpec = new X509EncodedKeySpec(Files.readAllBytes(path));
	    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
	    return keyFactory.generatePublic(publicSpec);       
	}

	private static PrivateKey readPrivateKey(Path path) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
	    PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(Files.readAllBytes(path));
	    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
	    return keyFactory.generatePrivate(keySpec);     
	}

	public static Boolean compareMAC(byte[] m1, byte[] m2) throws IOException {
		if (!Arrays.equals(m1, m2))
			return false;
		return true;
	}

	public static byte[] generateMAC(String message, String key) throws IOException {
		try {
			//Cast key to a byte array and generate a SecretKeySpec needed for mac.init
			SecretKeySpec keySpec = new SecretKeySpec(key.getBytes(), "AES");

			// Generate MAC
			Mac mac = Mac.getInstance("HmacSHA256");
			mac.init(keySpec);
			byte[] result = mac.doFinal(message.getBytes());
			return result;
		} catch (Exception e) {
			System.out.println("Error in AES.generateMAC: " + e);
			return null;
		}
	}

	public static byte[] digestMessage(byte[] message) {
		try{
			MessageDigest digest = MessageDigest.getInstance("SHA-1");
			digest.update(message);
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

	public static String sign(String plainText, PrivateKey privKey) throws Exception{
		Signature signer = Signature.getInstance("SHA256withRSA");
		signer.initSign(privKey);
		signer.update(plainText.getBytes("UTF8"));

		byte[] sign = signer.sign();

		return Base64.getEncoder().encodeToString(sign);

	}

	public static Boolean verify(String plainText, String signature, PublicKey pubKey) throws Exception {
		Signature verifier = Signature.getInstance("SHA256withRSA");
		verifier.initVerify(pubKey);
		verifier.update(plainText.getBytes("UTF8"));

		byte [] signatureBytes = Base64.getDecoder().decode(signature);

		return verifier.verify(signatureBytes);
	}

	public static byte[] encrypt(byte[] message, byte[] key) {
		try {
			// Generating IV Spec
			byte[] iv = new byte[ivSize];
			SecureRandom random = new SecureRandom();
			random.nextBytes(iv);
			IvParameterSpec ivSpec = new IvParameterSpec(iv);

			// Generate keySpec
			key = Arrays.copyOf(digestMessage(key), 16);
			SecretKeySpec keySpec = new SecretKeySpec(key, "AES");

			// Create and initialize the cipher for encryption
			Cipher aesCipher;
			aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			aesCipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);

			// Encrypt the cleartext
			byte[] cleartext = message;
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

	public static String decrypt(byte[] encryptedMessage, byte[] key) {
		try {
			// Split the encrypted message into IV and Ciphertext
			byte[] iv = new byte[ivSize];

			System.out.println(encryptedMessage.length);
			byte[] ciphertext = new byte[encryptedMessage.length - ivSize];

			System.arraycopy(encryptedMessage, 0, iv, 0, ivSize);
			System.arraycopy(encryptedMessage, ivSize, ciphertext, 0, encryptedMessage.length - ivSize);

			// Create ivSpec and keySpec
			IvParameterSpec ivSpec = new IvParameterSpec(iv);
			key = Arrays.copyOf(digestMessage(key), 16);			
			SecretKeySpec keySpec = new SecretKeySpec(key, "AES");

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
		try {
			byte[] message = "HELLO WORLD".getBytes("UTF8");
			byte[] digest = digestMessage(message);
			// byte[] digest = message;

			Path pvkpath = Paths.get("server_private", "private.der");
			Path pubkpath = Paths.get("client_private", "publicServer.der");

			byte[] a = createSignature(digest, pvkpath);
	
			if(!checkSignature(a, pubkpath, message)) System.out.println("No Bueno");
		
		} catch(Exception e) {}
	}
	*/
}
