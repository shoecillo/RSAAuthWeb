package com.sh.chipher.config;

import com.sh.chipher.RSAAuth;

public class ConfigBean 
{
	private String usr;
	
	private String pwd;
	
	private String privateKeystore;
	
	private String publicKeystore;
	
	private String dataKeystore;
	
	private String privateKey;
	
	private String publicKey;
	
	private String dataSigned;
	
	private int mode;

	public String getUsr() {
		return usr;
	}

	public void setUsr(String usr) {
		this.usr = usr;
	}

	public String getPwd() {
		return pwd;
	}

	public void setPwd(String pwd) {
		this.pwd = pwd;
	}

	public String getPrivateKeystore() {
		return privateKeystore;
	}

	public void setPrivateKeystore(String privateKeystore) {
		this.privateKeystore = privateKeystore;
	}

	public String getPublicKeystore() {
		return publicKeystore;
	}

	public void setPublicKeystore(String publicKeystore) {
		this.publicKeystore = publicKeystore;
	}

	public String getDataKeystore() {
		return dataKeystore;
	}

	public void setDataKeystore(String dataKeystore) {
		this.dataKeystore = dataKeystore;
	}

	public String getPrivateKey() {
		return privateKey;
	}

	public void setPrivateKey(String privateKey) {
		this.privateKey = privateKey;
	}

	public String getPublicKey() {
		return publicKey;
	}

	public void setPublicKey(String publicKey) {
		this.publicKey = publicKey;
	}

	

	public String getDataSigned() {
		return dataSigned;
	}

	public void setDataSigned(String dataSigned) {
		this.dataSigned = dataSigned;
	}

	public int getMode() {
		return mode;
	}

	public void setMode(int mode) {
		this.mode = mode;
	}
	
	@Override
	public String toString() 
	{
		StringBuffer res = new StringBuffer();
		res.append("************* KEY INFO **************** \n");
		res.append("** USER:"+getUsr()+" ** \n");
		res.append("** PASSWORD:"+getPwd()+" ** \n");
		res.append("** PUBLIC:"+getPublicKey()+" ** \n");
		res.append("** PRIVATE:"+getPrivateKey()+" ** \n");
		res.append("** DATA:"+getDataSigned()+" ** \n");
		if(getMode() == RSAAuth.MODE_FILE)
		{
			res.append("** PUBLIC KEYSTORE: "+getPublicKeystore()+getUsr()+".pub ** \n");
			res.append("** PRIVATE KEYSTORE: "+getPrivateKeystore()+getUsr()+".key ** \n");
			res.append("** DATA KEYSTORE: "+getDataKeystore()+getUsr()+".data ** \n");
		}
		else if(getMode() == RSAAuth.MODE_EXT)
		{
			res.append("** PUBLIC KEYSTORE:  ** \n");
			res.append("** PRIVATE KEYSTORE: ** \n");
			res.append("** DATA KEYSTORE: ** \n");
		}
		res.append("**************************************** \n");
		return res.toString();
	}
	
	
}
