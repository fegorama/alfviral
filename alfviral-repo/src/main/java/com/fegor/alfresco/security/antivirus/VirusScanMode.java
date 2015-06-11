package com.fegor.alfresco.security.antivirus;

import java.io.IOException;

import org.alfresco.service.cmr.repository.NodeRef;

public interface VirusScanMode {
	
	int scan(NodeRef nodeRef) throws IOException;
	
	int scan() throws IOException;

	int rescan() throws IOException;

	int report() throws IOException;
}
