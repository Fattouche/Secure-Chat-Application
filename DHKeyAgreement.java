import java.io.*;
import java.util.*;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.*;
import java.security.interfaces.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import javax.crypto.interfaces.*;
import com.sun.crypto.provider.SunJCE;

//Class used to establish symetric keys between client and server.
class DiffieTools {

	//Define needed variables
	public byte[] pubKeyEncoded;
	public final PublicKey pubKey;
	public final KeyPair kPair;
	public final byte[] pubKeyEnc;
	public final int keySize = 2048;

	//Server Constructor
	public DiffieTools(byte[] pubKeyEncoded) {
		this.pubKeyEncoded = pubKeyEncoded;
		this.kPair = genKeyPair();
		this.pubKey = getPubKey(this.kPair);
		this.pubKeyEnc = getPubKeyEncFromDHPublicKey(this.pubKey);
	}

	//Client Constructor
	public DiffieTools() {
		this(null);
	}

	//Takes encoded public key and returns a PublicKey object
	public PublicKey getDHPublicKeyFromEncoded(byte[] pubKeyEncoded)
			throws NoSuchAlgorithmException, InvalidKeyException {
		KeyFactory kf = KeyFactory.getInstance("DH");
		X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(pubKeyEncoded);
		try {
			PublicKey dhPubKey = kf.generatePublic(x509KeySpec);
			return dhPubKey;
		} catch (Exception e) {
			System.out.println("The algorithm specified in the encoded public key does not match any in record");
			return null;
		}
	}

	//Takes PublicKey object and returns encoded version.
	public byte[] getPubKeyEncFromDHPublicKey(PublicKey dhPublicKey) {
		return dhPublicKey.getEncoded();
	}

	//Given keypair returns the public key.
	public PublicKey getPubKey(KeyPair kPair) {
		return kPair.getPublic();
	}

	//Initializes a diffie helmen key agreement instance with private key.
	public KeyAgreement getInitializedKeyAgreement(PrivateKey privKey) {
		KeyAgreement kAgree;
		try {
			kAgree = KeyAgreement.getInstance("DH");
		} catch (Exception e) {
			System.out.println("The algorithm specified in the encoded public key does not match any in record");
			return null;
		}

		try {
			kAgree.init(privKey);
		} catch (Exception e) {
			System.out.println("Invalid Key");
			return null;
		}
		return kAgree;
	}

	//Generates a key pair for diffie helmen.
	public KeyPair genKeyPair() {
		DHParameterSpec dhParamFromSomeonesPubKey = null;
		KeyPairGenerator myKpairGen;
		try {
			myKpairGen = KeyPairGenerator.getInstance("DH");
		} catch (NoSuchAlgorithmException e) {
			System.out.println("The algorithm specified does not match any on record");
			return null;
		}

		//Creates a Keypair using someones encoded pubKeys DH Params
		if (this.pubKeyEncoded != null) {
			byte[] myPubKeyEncoded;
			KeyFactory myKeyFac;
			try {
				myKeyFac = KeyFactory.getInstance("DH");
			} catch (Exception e) {
				System.out.println(e);
				return null;
			}
			X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(pubKeyEncoded);
			PublicKey someonesPubKey;

			try {
				//Get PublicKey Object from Encoded
				someonesPubKey = myKeyFac.generatePublic(x509KeySpec);
				//Extract the DH Params from the PublicKey 
				dhParamFromSomeonesPubKey = ((DHPublicKey) someonesPubKey).getParams();
			} catch (Exception e) {
				System.out.println("The key used by the other person was invalid");
				return null;
			}

			try {
				//Initialize the generator with the same DH parameters as someone.
				myKpairGen.initialize(dhParamFromSomeonesPubKey);
			} catch (Exception e) {
				System.out.println("The algorithm specified does not match any on record");
				return null;
			}

		} else {
			//initialize the generator with a 2048 keysize.
			myKpairGen.initialize(keySize);
		}

		//Generate the KeyPair from the initialized generator.
		KeyPair myKpair;
		try {
			myKpair = myKpairGen.generateKeyPair();
			return myKpair;
		} catch (Exception e) {
			System.out.println("Some error occured in keypair generation");
			return null;

		}
	}
}

//Generates a symetric key pair for the server
class ServerDiffie {
	public static byte[] doDiffie(InputStream in, OutputStream out) {
		byte[] clientPubKeyEnc = new byte[16 * 1024];
		DiffieTools serverTools;
		PublicKey serverPubKey;
		PublicKey clientPubKey;
		KeyPair serverKpair;
		byte[] serverPubKeyEnc;
		int numRead;
		KeyAgreement serverAgree;
		byte[] serverSharedSecret = new byte[256];

		try {
			//Get PubKeyEncoded
			numRead = in.read(clientPubKeyEnc);
			serverTools = new DiffieTools(clientPubKeyEnc);
			serverPubKeyEnc = serverTools.pubKeyEnc;
			serverKpair = serverTools.kPair;
			serverAgree = serverTools.getInitializedKeyAgreement(serverKpair.getPrivate());

			out.write(serverPubKeyEnc);

			clientPubKey = serverTools.getDHPublicKeyFromEncoded(clientPubKeyEnc);
			serverAgree.doPhase(clientPubKey, true);
			numRead = serverAgree.generateSecret(serverSharedSecret, 0);
		} catch (Exception ioe) {
			System.out.println(ioe);
		}
		return serverSharedSecret;
	}
}

//Generates a symetric key pair for the client.
class ClientDiffie {
	public static byte[] doDiffie(InputStream in, OutputStream out) {
		byte[] serverPubKeyEnc = new byte[16 * 1024];
		DiffieTools clientTools;
		PublicKey clientPubKey;
		PublicKey serverPubKey;
		KeyPair clientKpair;
		byte[] clientPubKeyEnc;
		int numRead;
		KeyAgreement clientAgree;
		byte[] clientSharedSecret = new byte[256];

		try {
			clientTools = new DiffieTools();
			clientPubKey = clientTools.pubKey;
			clientPubKeyEnc = clientTools.pubKeyEnc;
			clientKpair = clientTools.kPair;
			clientAgree = clientTools.getInitializedKeyAgreement(clientKpair.getPrivate());

			//Send PubKeyEncoded
			out.write(clientPubKeyEnc);
			numRead = in.read(serverPubKeyEnc);

			serverPubKey = clientTools.getDHPublicKeyFromEncoded(serverPubKeyEnc);
			clientAgree.doPhase(serverPubKey, true);
			numRead = clientAgree.generateSecret(clientSharedSecret, 0);
		} catch (Exception ioe) {
			System.out.println(ioe);
		}
		return clientSharedSecret;
	}
}