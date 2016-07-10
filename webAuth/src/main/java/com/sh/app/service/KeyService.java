package com.sh.app.service;

import java.util.Date;

import org.bouncycastle.util.encoders.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import com.sh.app.exceptions.ShEncoderException;
import com.sh.chipher.config.ConfigBean;

@Service
public class KeyService 
{
	
	private final static Logger LOGGER = LoggerFactory.getLogger(KeyService.class);
	
	@Value("${token.expiration}")
	private String expiration;
	
	private final static String separator = "##";
	
	@Autowired
	ConfigAuth config;
	
	public String tokenizeKey() throws ShEncoderException
	{
		ConfigBean conf = config.getConfig();
		String usr = conf.getUsr();
		String pwd = conf.getPwd();
		//BigInteger exp = BigInteger.valueOf(Long.valueOf(expiration));
		String t =String.valueOf(new Date().getTime());
		
		String b64 = conf.getPublicKey() + 
				separator+ new String(Base64.encode(usr.getBytes())) +
				separator+ new String(Base64.encode(pwd.getBytes()))+
				separator+new String(Base64.encode(t.getBytes()));   
		
		b64 =new String( Base64.encode(b64.getBytes()));
		LOGGER.info("GENERATING SECURITY TOKEN");
		LOGGER.info(conf.toString());
		LOGGER.info("TOKEN: "+b64);
		return b64;
	}
	
	public ConfigBean decoder(String key) throws ShEncoderException
	{
		LOGGER.info("DECODING TOKEN...");
		String str = new String(Base64.decode(key));
		String[] splitter = str.split(separator);
		
		ConfigBean conf = config.getConfig();
		conf.setPublicKey(splitter[0]);
		conf.setUsr(new String(Base64.decode(splitter[1])));
		conf.setPwd(new String(Base64.decode(splitter[2])));
		String mills = new String(Base64.decode(splitter[3]));
		long exp = Long.valueOf(expiration);
		if(exp>0)
		{
			long time = Long.valueOf(mills);
			long res = new Date().getTime() - time; 
			if(res>=exp)
			{
				LOGGER.error("TOKEN EXPIRED");
				throw new ShEncoderException("TOKEN EXPIRED...");
			}
		}
		LOGGER.info("TOKEN DECODED");
		return conf;
		
	}
}
