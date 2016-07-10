package com.sh.app.filters;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;

import com.sh.app.exceptions.ShEncoderException;
import com.sh.app.service.KeyService;
import com.sh.chipher.RSAAuth;
import com.sh.chipher.config.ConfigBean;
import com.sh.chipher.ex.ShRSAException;



public class AuthFilter implements Filter 
{
	
	private final static Logger LOGGER = LoggerFactory.getLogger(AuthFilter.class);
	
	@Autowired
	private KeyService keyServ;

	@Override
	public void destroy() {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void doFilter(ServletRequest req, ServletResponse resp, FilterChain chain)
			throws IOException, ServletException {
		
		
		HttpServletRequest request = (HttpServletRequest) req;
		HttpServletResponse response = (HttpServletResponse) resp;
		
		String header = request.getHeader("AUTH-SH-TOKEN");
		if(header != null && !header.equals(""))
		{
			
			try {
				ConfigBean conf = keyServ.decoder(header);
				
				RSAAuth auth = new RSAAuth(conf);
				
					if(auth.authenticate())
					{
						LOGGER.info("AUTHENTICATION COMPLETE");
						response.addHeader("SH-OK", "true");
						chain.doFilter(request, response);
					}
					else
					{
						LOGGER.error("NOT AUTHENTICATION VALID FOR USER <"+conf.getUsr()+">");
						response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
						response.getWriter().println("NOT AUTHORIZED");
					}
			}
			catch (ShEncoderException e) 
			{
				response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
				response.getWriter().println("TOKEN EXPIRED");
			}
			catch (ShRSAException e) 
			{
				LOGGER.error("INTERNAL ERROR");
				response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
				response.getWriter().println("INTERNAL ERROR");
			}
		}
		else
		{
			LOGGER.error("NO SECURITY HEADER IN REQUEST");
			response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
			response.getWriter().println("NO SECURITY TOKEN IN REQUEST");
		}
		
	}

	@Override
	public void init(FilterConfig filterConf) throws ServletException {
		// TODO Auto-generated method stub
		
	}

}
