package com.sh.app.security;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;

import com.sh.app.service.ConfigAuth;
import com.sh.chipher.RSAAuth;
import com.sh.chipher.config.ConfigBean;
import com.sh.chipher.ex.ShRSAException;

@Component
public class RSAAuthenticationProvider implements AuthenticationProvider {
	
	private final static Logger LOGGER = LoggerFactory.getLogger(RSAAuthenticationProvider.class);
	
	@Autowired
	ConfigAuth config;


	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		
		final String usr = authentication.getName();
		final String pwd = (String) authentication.getCredentials();
		
		ConfigBean conf = config.getConfig();
		conf.setUsr(usr);
		conf.setPwd(pwd);
		conf.setDataSigned("");
		conf.setPrivateKey("");
		conf.setPublicKey("");
		conf.setMode(RSAAuth.MODE_FILE);
		LOGGER.info("RSA IS MODE_FILE ON");
		
		try 
		{
			RSAAuth auth = new RSAAuth(conf);
			if(auth.authenticate())
			{
				Collection<? extends GrantedAuthority> authorities = buildAuthorities();
				LOGGER.info("AUTHENTICATION COMPLETE IN LOGIN"); 
	            return new UsernamePasswordAuthenticationToken(usr, pwd, authorities);
			}
			else
			{
				LOGGER.error("WRONG CREDENTIALS");
				throw new BadCredentialsException("Wrong credentials");
			}
		}
		catch (ShRSAException e) 
		{
			LOGGER.error("INTERNAL ERROR",e);
			 throw new BadCredentialsException(e.getMessage());
		}
		 
	}

	@Override
	public boolean supports(Class<?> authentication) {
		// TODO Auto-generated method stub
		return true;
	}
	
	private List<Role> buildAuthorities()
	{
		 Role r = new Role();
         r.setName("ROLE_USER");
         List<Role> roles = new ArrayList<Role>();
         roles.add(r);
         return roles;
	}

}
