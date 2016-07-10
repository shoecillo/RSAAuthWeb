package com.sh.app.exceptions;

@SuppressWarnings("serial")
public class ShEncoderException extends Exception 
{
	public ShEncoderException() {
		super();
	}
	
	public ShEncoderException(String msg) {
		super(msg);
	}
	
	public ShEncoderException(String msg,Throwable ex) {
		super(msg, ex);
	}
}
