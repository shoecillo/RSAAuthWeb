package com.sh.app.exceptions;

@SuppressWarnings("serial")
public class ShCredentialsException extends Exception 
{
	public ShCredentialsException() {
		super();
	}
	
	public ShCredentialsException(String msg) {
		super(msg);
	}
	
	public ShCredentialsException(String msg,Throwable ex) {
		super(msg, ex);
	}
}
