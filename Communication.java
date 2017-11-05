import java.util.*;
import java.math.BigInteger;
import java.nio.file.*;
import java.lang.*;

class Communication {

	public static byte[] message;
	public static byte[] signature;
	public static byte[] mac;

	public static void parse(byte[] com) {
		try {
			String str = new String(com);
			String[] portions = str.split(";;;");

			if (portions.length > 3) {
				System.out.println("The Communication object contains incorrect coding");
			}

			if (portions[0].equals("")) {
				System.out.println("The Communication object does not contain the message");
			} else {
				message = Base64.getDecoder().decode(portions[0].getBytes());
				if (portions.length > 1) {
					signature = Base64.getDecoder().decode(portions[1].getBytes());
				}
				if (portions.length > 2) {
					mac = Base64.getDecoder().decode(portions[2].getBytes());
				}
			}
		} catch (Exception e) {
			System.out.println("Parse error");
		}
	}

	public byte[] format(byte[] message, byte[] signature, byte[] mac) {
		String delimeter = ";;;";
		
		byte[] encodedMessage = Base64.getEncoder().encode(message);
		byte[] encodedSignature = Base64.getEncoder().encode(signature);
		byte[] encodedMac = Base64.getEncoder().encode(mac);

		String messageString = new String(encodedMessage);
		String sigString = new String(encodedSignature);
		String macString = new String(encodedMac);
		String communication = messageString + delimeter + sigString + delimeter + macString;
		return communication.getBytes();
	}

	public static String handleMessage(byte[] information, Path path, Cryptography crypto, byte[] key,
			Security security) {
		parse(information);
		byte[] msg = crypto.decrypt(message, key, security.confidentiality);
		if (!crypto.verify(msg, signature, Paths.get("client_private", "publicServer.der"), security.authentication)) {
			System.out.println("Authentication failed, signature from message does not match");
		}
		byte[] macActual = crypto.generateMAC(msg, key, Security.integrity);
		byte[] macExpected = mac;
		if (!crypto.compareMAC(macActual, macExpected, security.integrity)) {
			System.out.println("Integrity failed, checksum of message does not match expected!");
		}
		String s = "";
		try {
			s = new String(msg);
		} catch (Exception e) {
			System.out.println("byte to string conversion error");
		}
		return s;
	}
}