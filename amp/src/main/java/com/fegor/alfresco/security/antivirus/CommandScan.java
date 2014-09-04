/*
 * alfviral is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * alfviral is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with Alfresco. If not, see <http://www.gnu.org/licenses/>.
 */
package com.fegor.alfresco.security.antivirus;

import java.io.IOException;
import java.util.List;

import org.alfresco.service.cmr.repository.NodeRef;
import org.alfresco.service.cmr.repository.NodeService;
import org.apache.log4j.Logger;

import com.fegor.alfresco.model.AlfviralModel;

/**
 * InStreamScan
 * 
 * @author fegor
 * 
 */
public class CommandScan implements VirusScanMode {

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

	/*
	 * (non-Javadoc)
	 * 
	 * @see com.fegor.alfresco.security.antivirus.VirusScanMode#scan()
	 */
	@Override
	public int scan() throws IOException {
		int res = 0;
		try {
			/*
			 * execute command "script/command for file"
			 */
			this.command.add(this.file_to_scan);
			ProcessBuilder pb = new ProcessBuilder(this.command);
			Process process = pb.start();
			res = process.waitFor();
		} catch (IOException e) {
			logger.error(" Error in execute command.", e);
		} catch (InterruptedException e) {
			logger.error(" Error in execute command.", e);
		}

		if (res != 0) {
			this.addAspect();
		}

		return res;
	}

	/*
	 * Re-scanning
	 * 
	 * @see com.fegor.alfresco.security.antivirus.VirusScanMode#rescan()
	 */
	@Override
	public int rescan() throws IOException {
		return this.scan();
	}

	/*
	 * Report
	 * 
	 * @see com.fegor.alfresco.security.antivirus.VirusScanMode#report()
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
