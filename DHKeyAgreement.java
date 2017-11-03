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
 
 
class DiffieTools{
	public byte[] pubKeyEncoded;
 	public final PublicKey pubKey;
 	public final KeyPair kPair;
 	public final byte[] pubKeyEnc;
 	public final int keySize = 2048;
 	
 	public DiffieTools(byte[] pubKeyEncoded){ /* Server Constructor */
 		
 			this.pubKeyEncoded = pubKeyEncoded;
 
 			this.kPair = getKeyPair();
 		
 			this.pubKey = getPubKey(this.kPair);
 
 			this.pubKeyEnc = getPubKeyEncFromDHPublicKey(this.pubKey);
 			
 	}
 	public DiffieTools(){	/* Client Constructor */
 			this(null);
 		}	
 
 
 	public PublicKey getDHPublicKeyFromEncoded(byte[] pubKeyEncoded) throws NoSuchAlgorithmException, InvalidKeyException{
 		KeyFactory kf = KeyFactory.getInstance("DH");
 		X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(pubKeyEncoded);
 		try
 		{
 			PublicKey dhPubKey = kf.generatePublic(x509KeySpec);
 			return dhPubKey;
 		} catch (Exception e) {
 			System.out.println("The algorithm specified in the encoded public key does not match any in record");
 			return null;
 		}
 	}
 
 	public byte[] getPubKeyEncFromDHPublicKey(PublicKey dhPublicKey) {
 		return dhPublicKey.getEncoded();
 	}
 
 	public PublicKey getPubKey(KeyPair kPair){
 		return kPair.getPublic();
 	}
 
 	public KeyAgreement getInitializedKeyAgreement(PrivateKey privKey){
 		KeyAgreement kAgree;
 		try
 		{	
 			kAgree = KeyAgreement.getInstance("DH");
 		} catch (Exception e) {
 			System.out.println("The algorithm specified in the encoded public key does not match any in record");
 			return null;
 		}
 
 		try
 		{
 			kAgree.init(privKey);
 		} catch (Exception e) {
 			System.out.println("Invalid Key");
 			return null;
 		}
 		return kAgree;
 	}
 
 	public KeyPair getKeyPair() {
 		DHParameterSpec dhParamFromSomeonesPubKey = null;
 		KeyPairGenerator myKpairGen;
 		try{
 			myKpairGen = KeyPairGenerator.getInstance("DH");
 		} catch (NoSuchAlgorithmException e) {
 			System.out.println("The algorithm specified does not match any on record");
 			return null;
 		}
 
 		if(this.pubKeyEncoded!=null){	/* We are going to be creating a Keypair using someones encoded pubKeys DH Params*/
 			byte[] myPubKeyEncoded;
 			KeyFactory myKeyFac;
 			try
 			{
 				myKeyFac = KeyFactory.getInstance("DH");
 			}catch (Exception e) {
 				System.out.println(e);
 				return null;
 			}
 			X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(pubKeyEncoded);
 			PublicKey someonesPubKey;
 
 			try
 			{
 				someonesPubKey = myKeyFac.generatePublic(x509KeySpec);	/* We get PublicKey Object from Encoded */
 				dhParamFromSomeonesPubKey = ((DHPublicKey)someonesPubKey).getParams();	/* Extract the DH Params from the PublicKey */
 
 			} catch (Exception e) {
 				System.out.println("The key used by the other person was invalid");
 				return null;
 			}
 
 			try
 			{
 				myKpairGen.initialize(dhParamFromSomeonesPubKey);	/* Initialize the generator with the same DH parameters as someone*/
 			} catch (Exception e) {
 				System.out.println("The algorithm specified does not match any on record");
 				return null;
 			}
 
 		} else{
 			myKpairGen.initialize(keySize);		/* Since we are not creating a keypair using someones encoded pubkey DhParams, 
 												 * we initialize the generator with a 2048 keysize */
 		}
 
 		KeyPair myKpair;						/* Generate the KeyPair from the initialized generator*/
 		try
 		{
 			myKpair = myKpairGen.generateKeyPair();
 			return myKpair;
 		} catch (Exception e) {
 			System.out.println("Some error occured in keypair generation");
 			return null;
 
 
 		}
 	}
 }
 
 class DoServerDiffie {
 	void doServerDiffie(InputStream in, OutputStream out) {
 		byte[] clientPubKeyEnc = new byte[16 * 1024];
 		DiffieTools serverTools;
 		PublicKey serverPubKey;
 		PublicKey clientPubKey;
 		KeyPair serverKpair;
 		byte[] serverPubKeyEnc;
 		int numRead;
 		KeyAgreement serverAgree;
 		byte[] serverSharedSecret = new byte[256];
 
 		try
 		{
 			numRead = in.read(clientPubKeyEnc);	//Get PubKeyEncoded
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
 	}
 }
 
 class DoClientDiffie{
 	public void doClientDiffie(InputStream in, OutputStream out){
 		byte[] serverPubKeyEnc = new byte[16 * 1024];
 		DiffieTools clientTools; 
 		PublicKey clientPubKey;
 		PublicKey serverPubKey;
 		KeyPair clientKpair;
 		byte [] clientPubKeyEnc;
 		int numRead;
 		KeyAgreement clientAgree;
 		byte[] clientSharedSecret = new byte[256];
 
 		try
 		{
 			clientTools = new DiffieTools();
 			clientPubKey = clientTools.pubKey;
 			clientPubKeyEnc = clientTools.pubKeyEnc;
 			clientKpair = clientTools.kPair;
 			clientAgree = clientTools.getInitializedKeyAgreement(clientKpair.getPrivate());
 			out.write(clientPubKeyEnc);	// Send PubKeyEncoded
 
 			numRead = in.read(serverPubKeyEnc);
 			serverPubKey = clientTools.getDHPublicKeyFromEncoded(serverPubKeyEnc);
 
 			clientAgree.doPhase(serverPubKey, true);
 			numRead = clientAgree.generateSecret(clientSharedSecret, 0);
 
 			out.write(clientSharedSecret);
 
 
 		} catch (Exception ioe) {
 			System.out.println(ioe);
 		}
 	}
 }