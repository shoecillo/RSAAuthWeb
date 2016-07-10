package com.sh.chipher.ex;

@SuppressWarnings("serial")
public class ShRSAException extends Exception 
{
	public ShRSAException() {
		super();
	}
	
	public ShRSAException(String msg) {
		super(msg);
	}
	
	public ShRSAException(String msg,Throwable ex) {
		super(msg, ex);
	}
}
