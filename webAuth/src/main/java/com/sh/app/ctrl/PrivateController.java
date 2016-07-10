package com.sh.app.ctrl;

import java.io.IOException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import com.sh.app.service.ConfigAuth;

@RestController
@RequestMapping("/rest")
public class PrivateController 
{
	@Autowired
	ConfigAuth auth;
	private final static Logger LOGGER = LoggerFactory.getLogger(PrivateController.class);
	
	@RequestMapping(value = "/getPrivateAccess", method = RequestMethod.POST)
	public String getPrivateAccess(HttpServletRequest req,HttpServletResponse resp) throws IOException
	{
		String isOk = resp.getHeader("SH-OK");
		if(isOk.equals("true"))
		{
			LOGGER.info("ACCESS GRANTED TO USER <"+auth.getConfig().getUsr()+">");
			return "ACCESS GRANTED";
		}
		else
		{
			return null;
		}
		
	}
	
	
}
