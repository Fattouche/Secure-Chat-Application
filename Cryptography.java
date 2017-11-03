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
	static private byte[] privateKey;
	static private byte[] publicKey;

	private static PublicKey readPublicKey(Path path)
			throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
		if (publicKey == null) {
			X509EncodedKeySpec publicSpec = new X509EncodedKeySpec(Files.readAllBytes(path));
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			publicKey = keyFactory.generatePublic(publicSpec);
		}
		return publicKey;
	}

	private static PrivateKey readPrivateKey(Path path)
			throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
		if (privateKey == null) {
			PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(Files.readAllBytes(path));
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			privateKey = keyFactory.generatePrivate(keySpec);
		}
		return privateKey;
	}

	public static Boolean compareMAC(byte[] m1, byte[] m2) throws IOException {
		if (!Arrays.equals(m1, m2))
			return false;
		return true;
	}

	public static byte[] generateMAC(byte[] message, byte[] key, boolean integrity) throws IOException {
		try {
			if(!integrity){
				return "".getBytes();
			}
			//Cast key to a byte array and generate a SecretKeySpec needed for mac.init
			SecretKeySpec keySpec = new SecretKeySpec(key, "AES");

			// Generate MAC
			Mac mac = Mac.getInstance("HmacSHA256");
			mac.init(keySpec);
			byte[] result = mac.doFinal(message);
			return result;
		} catch (Exception e) {
			System.out.println("Error in AES.generateMAC: " + e);
			return null;
		}
	}

	public static byte[] digestMessage(byte[] message) {
		try {
			MessageDigest digest = MessageDigest.getInstance("SHA-1");
			digest.update(message);
			byte[] messageDigest = digest.digest();
			return messageDigest;
		} catch (Exception e) {
			System.out.println("Error in AES.digestMessage: " + e);
			return null;
		}
	}

	public static Boolean compareDigests(byte[] d1, byte[] d2) {
		if (!Arrays.equals(d1, d2))
			return false;
		return true;
	}

	public static byte[] sign(byte[] plainText, Path path, boolean authenticity) throws Exception {
		if (!authenticity) {
			return plainText;
		}
		PrivateKey privKey = readPrivateKey(path);
		Signature signer = Signature.getInstance("SHA256withRSA");
		signer.initSign(privKey);
		signer.update(plainText);

		byte[] sign = signer.sign();
		return sign;
	}

	public static Boolean verify(byte[] plainText, byte[] signature, Path path, boolean authenticity) throws Exception {
		if (!authenticity) {
			return true;
		}
		PublicKey pubKey = readPublicKey(path);
		Signature verifier = Signature.getInstance("SHA256withRSA");
		verifier.initVerify(pubKey);
		verifier.update(plainText);

		byte[] signatureBytes = Base64.getDecoder().decode(signature);

		return verifier.verify(signatureBytes);
	}

	public static byte[] encrypt(byte[] message, byte[] key, boolean encryption) {
		try {
			if (!encryption) {
				return message;
			}
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

	public static String decrypt(byte[] message, byte[] key, boolean decryption) {
		try {
			if (!decryption) {
				return message;
			}
			// Split the encrypted message into IV and Ciphertext
			byte[] iv = new byte[ivSize];

			System.out.println(message.length);
			byte[] ciphertext = new byte[message.length - ivSize];

			System.arraycopy(message, 0, iv, 0, ivSize);
			System.arraycopy(message, ivSize, ciphertext, 0, message.length - ivSize);

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

	public byte[] format(byte[] message, byte[] signature, byte[] mac) {
		String delimeter = ";;;";
		String communication = message.toString()+delimeter+signature.toString()+delimeter+mac.toString();
		return communication.getBytes();
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
