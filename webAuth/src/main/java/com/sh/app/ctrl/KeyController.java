package com.sh.app.ctrl;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;

import com.sh.app.exceptions.ShEncoderException;
import com.sh.app.model.KeyDTO;
import com.sh.app.service.KeyService;

@Controller
public class KeyController {
	
	private final static Logger LOGGER = LoggerFactory.getLogger(KeyController.class);
	
	@Autowired
	private KeyService service;
	
	@RequestMapping(value = "/getKey", method = RequestMethod.POST, headers = { "Content-type=application/json" })
	@ResponseBody
	public KeyDTO getKey(HttpServletRequest req,HttpServletResponse resp) throws IOException
	{
		LOGGER.info("OBTAINING TOKEN");
		try 
		{
			KeyDTO dto = new KeyDTO();
			dto.setUser(req.getUserPrincipal().getName());
			dto.setKey(service.tokenizeKey());
			LOGGER.info("User: "+dto.getUser());
			LOGGER.info("Token: "+dto.getKey());
			return dto;
		} catch (ShEncoderException e) 
		{
			LOGGER.error("INTERNAL ERROR ENCODING",e);
			resp.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
			resp.getWriter().println("INTERNAL ERROR ENCODING KEY");
			return null;
		}
	}
	
	@RequestMapping(value = "/logout", method = RequestMethod.POST)
	public void logout(HttpServletRequest request,HttpServletResponse response) throws ServletException, IOException
	{
		LOGGER.info("LOGGIN OUT USER <"+request.getUserPrincipal().getName()+">");
		request.logout();
		LOGGER.info("USER LOGGED OUT THE SYSTEM.");
	}
	
}
