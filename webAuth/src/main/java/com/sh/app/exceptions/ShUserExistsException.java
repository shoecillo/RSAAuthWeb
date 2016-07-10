package com.sh.app.exceptions;

@SuppressWarnings("serial")
public class ShUserExistsException extends Exception 
{
	public ShUserExistsException() {
		super();
	}
	
	public ShUserExistsException(String msg) {
		super(msg);
	}
	
	public ShUserExistsException(String msg,Throwable ex) {
		super(msg, ex);
	}
}
