package com.sh.chipher;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;

import org.bouncycastle.util.encoders.Base64;

import com.sh.chipher.config.ConfigBean;
import com.sh.chipher.ex.ShRSAException;
/**
 * RSA Pair generator keys in 2 files,authenticate this keys with a password signed
 * @author shoe011
 * @since 2016-07-03
 *
 */
public class RSAAuth 
{
	/** Public key object **/
	private PublicKey publicKey;
	/** data representation of signed content **/
	private byte[] datagram;
	/** Used algorithm for generation **/
	private static final String ALGORITHM = "RSA";
	/**  Type of encryption **/
	private static final String ALGORITHM_TYPE = "SHA1withRSA";
	/**  extension for private key files **/
	private static final String PRIVATE_KEY_FILE = ".key";
	/** extension for public key files **/
	private static final String PUBLIC_KEY_FILE = ".pub";
	/** extension of signed data file **/
	private static final String DATA_FILE = ".data";
	/** type of method of read, file mode **/
	public static final int MODE_FILE = 0;
	/** type of method of read, external mode **/
	public static final int MODE_EXT = 1;
	
	/** User parameter **/
	private String USR;
	/** Password parameter **/
	private String PWD;
	
	/** Signed data file **/
	private File dataFile;
	/** private key file **/
	private File privateKeyFile;
	/** public key file **/
	private File publicKeyFile;
	/** String representation of a Base64 data signed **/
	private String B64Datagram;
	/** String representation of a Base64 public key **/
	private String B64PublicKey;
	/** Configuration bean parameter **/
	private ConfigBean config;
	

	/**
	 * Constructor for this class have a ConfigBean as parameter with all information used in this class.<br>
	 * Initialize all files based in user parameter
	 * @param config - ConfigBean object with all configuration
	 * @throws ShRSAException 
	 */
	public RSAAuth(ConfigBean config) throws ShRSAException 
	{
		// If we have not installed JCP BouncyCastle we can add the provider here
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		
		this.config = config;
		
		
			
			if(config.getUsr().equals("") || config.getPwd().equals(""))
			{
				throw new ShRSAException("NO USER OR PASSWORD CONFIGURATED");
			}
			USR = config.getUsr();
			PWD = config.getPwd();
			if(config.getMode() == MODE_FILE)
			{
				
				dataFile = new File(config.getDataKeystore()+USR+DATA_FILE);
				privateKeyFile = new File(config.getPrivateKeystore()+USR+PRIVATE_KEY_FILE);
				publicKeyFile = new File(config.getPublicKeystore()+USR+PUBLIC_KEY_FILE);
			}
			else if(config.getMode() == MODE_EXT)
			{
				if(config.getDataSigned().equals("") || config.getPublicKey().equals(""))
				{
					throw new ShRSAException("NO DATA CONFIGURATED FOR MODE_EXT");
				}
			}
			else
			{
				throw new ShRSAException("NO DATA CONFIGURATED.CHECK PARAMETERS");
			}
		
	}
	
	/**
	 * Admits a Base64 string representing the PublicKey object serialized.Need signed data file and private key in host.
	 * @return boolean - if true is authenticated, false not authenticated
	 * @throws Exception
	 */
	public boolean authenticate() throws ShRSAException
	{
		try {
			if(config.getPublicKey() != null && !config.getPublicKey().equals(""))
			{
				ObjectInputStream strPublic = new ObjectInputStream(new ByteArrayInputStream(decodeBase64(config.getPublicKey())));
				publicKey = (PublicKey) strPublic.readObject();
				strPublic.close();
			}
			else if(publicKeyFile != null && publicKeyFile.exists())
			{
				ObjectInputStream strPublic = new ObjectInputStream(new FileInputStream(publicKeyFile));
				publicKey = (PublicKey) strPublic.readObject();
				strPublic.close();
			}
			else
			{
				throw new ShRSAException("NO USER : "+USR+" REGISTRED IN THE SYSTEM");
			}
			
			if(config.getDataSigned() != null && !config.getDataSigned().equals(""))
			{
				datagram = decodeBase64(config.getDataSigned());
			}
			else if(dataFile != null && dataFile.exists())
			{
				FileInputStream dataIstr = new FileInputStream(dataFile);
				datagram = new byte[dataIstr.available()];
				dataIstr.read(datagram);
				dataIstr.close();
			}
			else
			{
				throw new ShRSAException("NO USER : "+USR+" REGISTRED IN THE SYSTEM");
			}
			
			B64PublicKey = convertObjectToBase64(publicKey);
			B64Datagram = convertToBase64(datagram);
			
			//Verifying Signature
			Signature signatureRead = Signature.getInstance(ALGORITHM_TYPE);
			signatureRead.initVerify(publicKey);
			signatureRead.update(PWD.getBytes());
			if(signatureRead.verify(datagram))
			{
				config.setDataSigned(B64Datagram);
				config.setPublicKey(B64PublicKey);
				return true;
			}
			else
			{
				
				return false;
			}
		} catch (InvalidKeyException e) {
			
			throw new ShRSAException("INTERNAL ERROR",e);
			
		} catch (ClassNotFoundException e) {
			
			throw new ShRSAException("INTERNAL ERROR",e);
		
		} catch (FileNotFoundException e) {

			throw new ShRSAException("INTERNAL ERROR",e);
			
		} catch (NoSuchAlgorithmException e) {
			
			throw new ShRSAException("INTERNAL ERROR",e);
			
		} catch (SignatureException e) {
				
			throw new ShRSAException("INTERNAL ERROR",e);
			
		} catch (IOException e) {
			
			throw new ShRSAException("INTERNAL ERROR",e);
			
		} catch (Exception e) {
			
			throw new ShRSAException("INTERNAL ERROR",e);
			
		}
		
	}
	
	/**
	 * Generates a Key Pair, save them into 2 separated files(public and private).<br>
	 * Create a signature with given password and generate signed content data.This signed content is linked to 2 keys.<br>
	 * Always 4 elements are mandatory, a password, a public key, a private key and a signed data.<br>
	 * If mode is MODE_FILE,keys will be saved in keystore location with user name as file name.
	 * @throws ShRSAException
	 */
	public void generatePair() throws ShRSAException
	{
		
		try {
			KeyPairGenerator keyGen = KeyPairGenerator.getInstance(ALGORITHM);
			keyGen.initialize(1024, new SecureRandom());
			KeyPair keyPair = keyGen.generateKeyPair();
			
			Signature signature = Signature.getInstance(ALGORITHM_TYPE);
			signature.initSign(keyPair.getPrivate());
			signature.update(PWD.getBytes());
			
			byte[] sigBytes = signature.sign();
			
			B64PublicKey = convertObjectToBase64(keyPair.getPublic());
			String B64PrivateKey = convertObjectToBase64(keyPair.getPrivate());
			B64Datagram = convertToBase64(sigBytes);
			
			if(config.getMode() == MODE_FILE)
			{
				ObjectOutputStream oStrPublic = new ObjectOutputStream(new FileOutputStream(publicKeyFile));
				oStrPublic.writeObject(keyPair.getPublic());
				oStrPublic.close();
				
				ObjectOutputStream oStrPrivate = new ObjectOutputStream(new FileOutputStream(privateKeyFile));
				oStrPrivate.writeObject(keyPair.getPrivate());
				oStrPrivate.close();
				
				FileOutputStream signedStr = new FileOutputStream(dataFile);
				signedStr.write(sigBytes);
				signedStr.close();
				
			}
			
			config.setDataSigned(B64Datagram);
			config.setPublicKey(B64PublicKey);
			config.setPrivateKey(B64PrivateKey);
		} catch (InvalidKeyException e) {
			
			throw new ShRSAException("INTERNAL ERROR",e);
			
		} catch (NoSuchAlgorithmException e) {
			
			throw new ShRSAException("INTERNAL ERROR",e);
			
		} catch (SignatureException e) {
			
			throw new ShRSAException("INTERNAL ERROR",e);
			
		} catch (FileNotFoundException e) {
			
			throw new ShRSAException("INTERNAL ERROR",e);
			
		} catch (IOException e) {
			
			throw new ShRSAException("INTERNAL ERROR",e);
			
		}
	}
	/**
	 * Get configuration object with keys filled
	 * @return ConfigBean - Configuration properties
	 */
	public ConfigBean getConfig() {
		return config;
	}

	/**
	 * Convert a byte array to base64 
	 * @param k - byte array
	 * @return String - base64 encoded string
	 */
	public String convertToBase64(byte[] k)
	{
		byte[] res = Base64.encode(k);
		String b64Res = new String(res);
		return b64Res;
	}
	/**
	 * Convert a serializable object to base64 encoded string
	 * @param obj - object to convert
	 * @return String - base64 encoded string
	 * @throws IOException
	 */
	public String convertObjectToBase64(Serializable obj) throws IOException
	{
		ByteArrayOutputStream bOstr = new ByteArrayOutputStream();
		ObjectOutputStream oos = new ObjectOutputStream(bOstr);
		oos.writeObject(obj);
		oos.close();
		
		byte[] res = Base64.encode(bOstr.toByteArray());
		String b64Res = new String(res);
		return b64Res;
	}
	/**
	 * Decode Base64 string to byte array
	 * @param encode - base64 encoded String
	 * @return byte[] - byte array
	 */
	public byte[] decodeBase64(String encode)
	{
		byte[] res = Base64.decode(encode);
		return res;
	}
	/**
	 * Return the data signed content in base64 String
	 * @return String - base64 encoded String
	 */
	public String getB64Datagram() {
		return B64Datagram;
	}

	/**
	 * Return public key base64 encoded
	 * @return String - base64 encoded String
	 */
	public String getB64PublicKey() {
		return B64PublicKey;
	}	
	/**
	 * Check if files exists (Only MODE_FILE)
	 * @return boolean - true if exists, false if not exists
	 */
	public boolean existsUser()
	{
		File dataFile = new File(config.getDataKeystore()+USR+DATA_FILE);
		File privateKeyFile = new File(config.getPrivateKeystore()+USR+PRIVATE_KEY_FILE);
		File publicKeyFile = new File(config.getPublicKeystore()+USR+PUBLIC_KEY_FILE);
		if(dataFile.exists() && privateKeyFile.exists() && publicKeyFile.exists())
			return true;
		else
			return false;
					
	}
	
}
