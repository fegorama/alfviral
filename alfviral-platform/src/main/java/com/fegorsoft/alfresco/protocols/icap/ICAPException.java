package com.fegorsoft.alfresco.protocols.icap;

@SuppressWarnings("serial")
public class ICAPException extends Exception { 

    /**
     * Accepts a message to be displayed when ICAP server throws an Error
     * @param message
     */
    public ICAPException(String message) {
        super(message);
    }
}

