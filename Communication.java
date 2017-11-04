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
				message = portions[0].getBytes("UTF8");
				if (portions.length > 1) {
					signature = portions[1].getBytes("UTF8");
				}
				if (portions.length > 2) {
					mac = portions[2].getBytes("UTF8");
				}
			}
		} catch (Exception e) {
			System.out.println("Parse error");
		}
	}

	public byte[] format(byte[] message, byte[] signature, byte[] mac) {
		String delimeter = ";;;";
		String messageString = new String(message);
		String sigString = new String(signature);
		String macString = new String(mac);
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
			s = new String(msg, "UTF8");
		} catch (Exception e) {
			System.out.println("byte to string conversion error");
		}
		return s;
	}
}