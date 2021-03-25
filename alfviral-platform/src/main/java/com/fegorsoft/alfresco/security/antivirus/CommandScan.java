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
import java.util.Arrays;
import java.util.List;

import org.alfresco.service.cmr.repository.NodeRef;
import org.alfresco.service.cmr.repository.NodeService;
import org.apache.log4j.Logger;

import com.fegorsoft.alfresco.model.AlfviralModel;

/**
 * InStreamScan
 * 
 * @author fegor
 * 
 */
public final class CommandScan implements VirusScanMode {
	private final Logger logger = Logger.getLogger(CommandScan.class);

	private List<String> command;

	private String file_to_scan;

	private NodeService nodeService;
	private NodeRef nodeRef;

	/**
	 * Constructor
	 */
	public CommandScan() {
	}

	/* (non-Javadoc)
	 * @see com.fegorsoft.alfresco.security.antivirus.VirusScanMode#scan(org.alfresco.service.cmr.repository.NodeRef)
	 */
	@Override
	public int scan(NodeRef nodeRef) {
		int res = 0;
		this.nodeRef = nodeRef;
		
		try {
			res = scan();
		} 
		
		catch (IOException e) {
			e.printStackTrace();
		}
		
		return res;
	}
	
	/*
	 * (non-Javadoc)
	 * 
	 * @see com.fegorsoft.alfresco.security.antivirus.VirusScanMode#scan()
	 */
	@Override
	public int scan() throws IOException {
		int res = 0;
		try {
			/*
			 * execute command "script/command for file"
			 */
			this.command.add(this.file_to_scan);
			if (logger.isDebugEnabled()) {
				logger.debug("Command: " + Arrays.toString(this.command.toArray()));
			}
			
			ProcessBuilder pb = new ProcessBuilder(this.command);
			Process process = pb.start();
			res = process.waitFor();
		} 
		
		catch (IOException e) {
			logger.error(" Error in execute command.", e);
		} 
		
		catch (InterruptedException e) {
			logger.error(" Error in execute command.", e);
			
		} 
		
		finally {
			this.command.subList(1, this.command.size()).clear();
		}

		if (res != 0) {
			this.addAspect();
		}

		return res;
	}

	/*
	 * Re-scanning
	 * 
	 * @see com.fegorsoft.alfresco.security.antivirus.VirusScanMode#rescan()
	 */
	@Override
	public int rescan() throws IOException {
		return this.scan();
	}

	/*
	 * Report
	 * 
	 * @see com.fegorsoft.alfresco.security.antivirus.VirusScanMode#report()
	 */
	@Override
	public int report() throws IOException {
		int result = 0;
		return result;
	}

	/**
	 * Add aspect Scaned From Command is not assigned
	 */
	private void addAspect() {

		if (!this.nodeService.hasAspect(this.nodeRef,
				AlfviralModel.ASPECT_SCANNED_FROM_COMMAND)) {
			this.nodeService.addAspect(this.nodeRef,
					AlfviralModel.ASPECT_SCANNED_FROM_COMMAND, null);
		}

		if (logger.isInfoEnabled()) {
			logger.info(this.getClass().getName()
					+ ": [Aspect SCANNED_FROM_COMMAND assigned for "
					+ nodeRef.getId() + "]");
		}

	}

	/**
	 * @param nodeService
	 */
	public void setNodeService(NodeService nodeService) {
		this.nodeService = nodeService;
	}

	/**
	 * @param nodeRef
	 */
	public void setNodeRef(NodeRef nodeRef) {
		this.nodeRef = nodeRef;
	}

	/**
	 * @param command
	 */
	public void setCommand(List<String> command) {
		this.command = command;
	}

	/**
	 * @param file
	 */
	public void setFileToScan(String file) {
		this.file_to_scan = file;
	}
}
