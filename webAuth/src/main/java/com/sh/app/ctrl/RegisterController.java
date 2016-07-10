package com.sh.app.ctrl;

import java.io.File;
import java.io.IOException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import com.sh.app.exceptions.ShEncoderException;
import com.sh.app.exceptions.ShUserExistsException;
import com.sh.app.model.UserDTO;
import com.sh.app.service.ConfigAuth;
import com.sh.app.service.KeyService;
import com.sh.chipher.RSAAuth;
import com.sh.chipher.config.ConfigBean;
import com.sh.chipher.ex.ShRSAException;

@RestController
@RequestMapping("/public")
public class RegisterController 
{
	private final static Logger LOGGER = LoggerFactory.getLogger(RegisterController.class);
	
	@Autowired
	ConfigAuth auth;
	
	@Autowired
	private KeyService keyserv;
	
	@RequestMapping(value = "/generate", method = RequestMethod.POST)
	public String generate(@RequestBody UserDTO dto,HttpServletResponse resp) throws IOException
	{
		LOGGER.info("CREATING NEW USER...");
		ConfigBean conf = auth.getConfig();
		conf.setUsr(dto.getUsr());
		conf.setPwd(dto.getPwd());
		LOGGER.info(conf.toString());
		
		File data = new File(conf.getDataKeystore());
		File privateFile = new File(conf.getPrivateKeystore());
		File publicFile = new File(conf.getPublicKeystore());
		if(!data.exists())
			data.mkdirs();
		if(!privateFile.exists())
			privateFile.mkdirs();
		if(!publicFile.exists())
			publicFile.mkdirs();
		
		LOGGER.info("CHECKED KEYSTORE LOCATIONS");
		
		try {
			RSAAuth gen = new RSAAuth(conf);
			if(gen.existsUser())
				throw new ShUserExistsException("USER EXISTS IN THE SYSTEM");
			
			LOGGER.info("GENERATING KEY PAIR");
			gen.generatePair();
			LOGGER.info("KEY PAIR GENERATED");
			auth.setConfig(conf);
			resp.addHeader("AUTH-SH-TOKEN",keyserv.tokenizeKey());
			LOGGER.info("TOKEN ADDED TO RESPONSE HEADER 'AUTH-SH-TOKEN'");
			
		}
		catch (ShRSAException | ShEncoderException e) 
		{
			LOGGER.error("INTERNAL ERROR",e);
			resp.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
			//resp.getWriter().println("INTERNAL ERROR ENCODING KEY");
			return "INTERNAL ERROR ENCODING KEY";
			
		} catch (ShUserExistsException e) {
			LOGGER.error("INTERNAL ERROR",e);
			resp.setStatus(HttpServletResponse.SC_EXPECTATION_FAILED);
			//resp.getWriter().println("USER EXISTS IN THE SYSTEM");
			return "USER EXISTS IN THE SYSTEM";
			
		}
		
		
		return "HELLO WORLD";
	}
	
	@Deprecated
	@RequestMapping(value = "/logon", method = RequestMethod.POST)
	public String login(@RequestBody UserDTO dto,HttpServletRequest request,HttpServletResponse response) throws Exception
	{
		ConfigBean conf = auth.getConfig();
		conf.setUsr(dto.getUsr());
		conf.setPwd(dto.getPwd());
		conf.setDataSigned("");
		conf.setPrivateKey("");
		conf.setPublicKey("");
		RSAAuth authRSA = new RSAAuth(conf);
		
		if(!authRSA.authenticate())
		{
			response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
			return null;
		}
		else
		{
			response.addHeader("AUTH-SH-TOKEN", authRSA.getB64PublicKey());
			return "AUTHORIZED";
		}
	}
	
	
}
