package com.fegor.alfresco.security.antivirus;

import java.io.IOException;

public interface VirusScanMode {
	int scan() throws IOException;

	int rescan() throws IOException;

	int report() throws IOException;
}
