import java.util.*;
import java.security.*;

public class KeyGenerator {
	public static byte[] publicKey;
	public static byte[] privateKey;

	public KeyGenerator() {
		try{
			KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
			keyGen.initialize(512);
			KeyPair pair = keyGen.generateKeyPair();
			this.privateKey = pair.getPrivate().getEncoded();
			this.publicKey = pair.getPublic().getEncoded();
		}
		catch (Exception e) { 
			System.out.println("Error in KeyGenerator: " + e);
		}
	}
	/*
	// THIS WAS USED FOR TESTING
	public static void main(String args[]) {
		KeyGenerator keyGen = new KeyGenerator();
		System.out.println("PUB: " + Arrays.toString(keyGen.publicKey));
		System.out.println("PR: " + Arrays.toString(keyGen.privateKey));
	}
	*/
}