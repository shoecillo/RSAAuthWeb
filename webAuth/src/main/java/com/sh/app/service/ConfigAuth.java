package com.sh.app.service;

import com.sh.chipher.RSAAuth;
import com.sh.chipher.config.ConfigBean;

public class ConfigAuth 
{
	
	

	private ConfigBean config = new ConfigBean();

	public ConfigAuth(String usr, String pwd,String privateKeyStore,String publicKeyStore,String dataKeyStore,String mode) {
		super();
		
		config.setDataKeystore(dataKeyStore);
		config.setPrivateKeystore(privateKeyStore);
		config.setPublicKeystore(publicKeyStore);
		config.setUsr(usr);
		config.setPwd(pwd);
		if(mode.equals("EXT"))
		{
			config.setMode(RSAAuth.MODE_EXT);
		}
		else if(mode.equals("FILE"))
		{
			config.setMode(RSAAuth.MODE_FILE);
		}
		
		
	}
	
	public ConfigBean getConfig() {
		return config;
	}
	
	
	public void paint()
	{
		System.out.println(config.toString());
	}

	public void setConfig(ConfigBean config) {
		this.config = config;
	}
}
