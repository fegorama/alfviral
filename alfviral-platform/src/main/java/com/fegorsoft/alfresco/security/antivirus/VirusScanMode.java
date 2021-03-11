/*
 * Copyright 2015 Fernando González (fegor@fegor.com)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */
package com.fegorsoft.alfresco.security.antivirus;

import java.io.IOException;

import org.alfresco.service.cmr.repository.NodeRef;

public interface VirusScanMode {
	public final String ScanModeCommand = "COMMAND";
	public final String ScanModeInStream = "INSTREAM";
	public final String ScanModeVirusTotal = "VIRUSTOTAL";
	public final String ScanModeICap = "ICAP";
	
	int scan(NodeRef nodeRef) throws IOException;
	int scan() throws IOException;
	int rescan() throws IOException;
	int report() throws IOException;
}
