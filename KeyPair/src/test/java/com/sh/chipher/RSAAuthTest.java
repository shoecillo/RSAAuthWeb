package com.sh.chipher;

import static org.junit.Assert.assertTrue;

import java.io.File;

import org.junit.BeforeClass;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.sh.chipher.config.ConfigBean;

public class RSAAuthTest 
{
	
	private static ConfigBean conf = new ConfigBean();
	
	private static RSAAuth auth;
	
	private static final String RESOURCES = "src/test/resources/keys";
	
	private final static Logger LOGGER = LoggerFactory.getLogger(RSAAuth.class.getName());
	
	@BeforeClass
	public static void initConfig() throws Exception
	{
		
		File data = new File(RESOURCES+"/crypt/");
		File privateFile = new File(RESOURCES+"/private/");
		File publicFile = new File(RESOURCES+"/public/");
		if(!data.exists())
			data.mkdirs();
		if(!privateFile.exists())
			privateFile.mkdirs();
		if(!publicFile.exists())
			publicFile.mkdirs();
		
		LOGGER.info("******************************************************************************************************");
		LOGGER.info("      #### ######## #   ###### #######                                                                ");
		LOGGER.info("       #      #    # #  #    #    #                                                                   ");
		LOGGER.info("        #     #   ##### #  ##     #                                                                   ");
		LOGGER.info("     #####    #  #     ##    #    #                                                                   ");
		LOGGER.info("******************************************************************************************************");
		LOGGER.info("ALL FOLDERS CREATED");
		for(File f : data.listFiles())
		{
			f.delete();
			LOGGER.info(f.getAbsolutePath()+" DELETED.");
		}
		for(File f : privateFile.listFiles())
		{
			f.delete();
			LOGGER.info(f.getAbsolutePath()+" DELETED.");
		}
		for(File f : publicFile.listFiles())
		{
			f.delete();
			LOGGER.info(f.getAbsolutePath()+" DELETED.");
		}
		LOGGER.info("ALL FILES DELETED");
		
		
		conf.setUsr("shoe");
		conf.setPwd("shoe011");
		conf.setDataKeystore(RESOURCES+"/crypt/");
		conf.setPrivateKeystore(RESOURCES+"/private/");
		conf.setPublicKeystore(RESOURCES+"/public/");
		conf.setMode(RSAAuth.MODE_FILE);
		
		auth = new RSAAuth(conf);
		auth.generatePair();
		LOGGER.info("KEY PAIR GENERATED");
		LOGGER.info("\n"+auth.getConfig().toString());
		
	}
	
	

	@Test
	public void testAuthenticate() throws Exception 
	{
		
		boolean passed = auth.authenticate();
		if(passed)
		{
			LOGGER.info("AUTHENTICATED");
			LOGGER.info("\n"+auth.getConfig().toString());
			assertTrue(true);
		}
		else
		{
			LOGGER.info("NOT AUTHENTICATED");
			assertTrue(false);
		}
	}

	@Test
	public void testAuthenticateBase64() throws Exception 
	{
		ConfigBean bean = auth.getConfig();
		bean.setMode(RSAAuth.MODE_EXT);
		bean.setPwd("shoe011");
		RSAAuth authLocal = new RSAAuth(bean);
		boolean passed = auth.authenticate();
		if(passed)
		{
			LOGGER.info("AUTHENTICATED");
			LOGGER.info("\n"+authLocal.getConfig().toString());
			bean.setUsr("TEST");
			bean.setPwd("PASSWORD");
			bean.setDataKeystore("");
			bean.setPrivateKeystore("");
			bean.setPublicKeystore("");
			
			authLocal = new RSAAuth(bean);
			authLocal.generatePair();
			LOGGER.info("LAST PAIR GENERATION IN MEMORY");
			LOGGER.info("\n"+authLocal.getConfig().toString());
			assertTrue(true);
		}
		else
		{
			LOGGER.info("NOT AUTHENTICATED");
			assertTrue(false);
		}
	}
	
	@Test
	public void testAuthenticateBadPassword() throws Exception 
	{
		ConfigBean bean = auth.getConfig();
		bean.setMode(RSAAuth.MODE_EXT);
		bean.setPwd("shoe012");
		RSAAuth authLocal = new RSAAuth(bean);
		boolean passed = authLocal.authenticate();
		if(passed)
		{
			LOGGER.info("AUTHENTICATED");
			LOGGER.info("\n"+authLocal.getConfig().toString());
			assertTrue(false);
		}
		else
		{
			LOGGER.info("NOT AUTHENTICATED");
			LOGGER.info("\n"+authLocal.getConfig().toString());
			assertTrue(true);
		}
	}

}
