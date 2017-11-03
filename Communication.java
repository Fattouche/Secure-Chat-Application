import java.util.*;
import java.math.BigInteger;
import java.nio.file.*;
import java.lang.*;



class Communication{
		
		public static byte[] message;
		public static byte[] signature;
		public static byte[] mac;

		public Communication(byte[] com){
			try{
				parse(com);
			}catch (Exception e) {
				System.out.println(e);
			}
		}

		public void parse(byte[] com) throws Exception{
			String str = new String(com);
			String[] portions = str.split(";;;");


			if(portions.length > 3){
				System.out.println("The Communication object contains incorrect coding");
				
			}

			if(portions[0].equals("")){
				System.out.println("The Communication object does not contain the message");
			}else{
				this.message = portions[0].getBytes("UTF8");
				this.signature = portions[1].getBytes("UTF8");
				this.mac = portions[2].getBytes("UTF8");
			}
		}

		public byte[] format(byte[] message, byte[] signature, byte[] mac) {
			String delimeter = ";;;";
			String communication = message.toString() + delimeter + signature.toString() + delimeter + mac.toString();
			return communication.getBytes();
	}
}