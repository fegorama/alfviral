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
package com.fegor.alfresco.action;

import java.io.IOException;
import java.io.Serializable;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.HashMap;
import java.util.List;

import org.alfresco.model.ContentModel;
import org.alfresco.repo.action.executer.ActionExecuterAbstractBase;
import org.alfresco.service.cmr.action.Action;
import org.alfresco.service.cmr.action.ParameterDefinition;
import org.alfresco.service.cmr.repository.ContentIOException;
import org.alfresco.service.cmr.repository.ContentReader;
import org.alfresco.service.cmr.repository.ContentService;
import org.alfresco.service.cmr.repository.NodeRef;
import org.alfresco.service.cmr.repository.NodeService;
import org.alfresco.service.namespace.QName;
import org.apache.log4j.Logger;

import com.fegor.alfresco.model.AlfviralModel;
import com.fegor.alfresco.security.antivirus.CommandScan;
import com.fegor.alfresco.security.antivirus.InStreamScan;
import com.fegor.alfresco.security.antivirus.VirusTotalScan;

/**
 * VirusScan Action
 * 
 * @author fegor
 * 
 */
public class VirusScan extends ActionExecuterAbstractBase {

	private final Logger logger = Logger.getLogger(VirusScan.class);

	/*
	 * Services
	 */
	private ContentService contentService;
	private NodeService nodeService;

	private String mode;

	/*
	 * for mode COMMAND
	 */
	private List<String> command;
	private String store;

	/*
	 * for mode INSTREAM
	 */
	public int chunk_size = 4096;
	private int port;
	private String host;
	private int timeout;

	/*
	 * for mode VIRUSTOTAL
	 */
	private String vt_key;
	private String vt_url;

	/*
	 * Generic
	 */
	private String file_exceptions;

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * org.alfresco.repo.action.executer.ActionExecuterAbstractBase#executeImpl
	 * (org.alfresco.service.cmr.action.Action,
	 * org.alfresco.service.cmr.repository.NodeRef)
	 */
	@Override
	protected void executeImpl(Action action, NodeRef actionedUponNodeRef) {
		if (actionedUponNodeRef != null)
			this.scanFile(actionedUponNodeRef);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.alfresco.repo.action.ParameterizedItemAbstractBase#
	 * addParameterDefinitions(java.util.List)
	 */
	@Override
	protected void addParameterDefinitions(List<ParameterDefinition> arg0) {
	}

	/**
	 * Scan file for nodeRef
	 * 
	 * @param nodeRef
	 */
	public void scanFile(NodeRef nodeRef) {
		int res = 0;

		ContentReader contentReader = this.contentService.getReader(nodeRef,
				ContentModel.PROP_CONTENT);

		if ((contentReader != null)
				&& (this.file_exceptions.indexOf(contentReader.getMimetype()) == -1)) {
			String contentUrl = contentReader.getContentUrl();
			String contentPath = contentUrl.replaceFirst("store:/", this.store);

			if (logger.isDebugEnabled()) {
				logger.debug(this.getClass().getName() + ": [NodeRef: "
						+ nodeRef.getId() + "]");
				logger.debug(this.getClass().getName() + ": [File: "
						+ contentPath + "]");
				logger.debug(this.getClass().getName() + ": [Type: "
						+ contentReader.getMimetype() + "]");
				logger.debug(this.getClass().getName() + ": [Mode: "
						+ mode.toUpperCase() + "]");
			}

			/*
			 * if mode is COMMAND
			 */
			if (mode.toUpperCase().equals("COMMAND")) {

				try {
					CommandScan commandScan = new CommandScan();
					commandScan.setFileToScan(contentPath);
					commandScan.setNodeService(this.nodeService);
					commandScan.setNodeRef(nodeRef);
					commandScan.setCommand(this.command);
					res = commandScan.scan();

				} catch (IOException e) {
					logger.error("Error in instream operation.", e);
				}
			}
			/*
			 * if mode is INSTREAM
			 */
			else if (mode.toUpperCase().equals("INSTREAM")) {
				try {
					InStreamScan inStreamScan = new InStreamScan();
					inStreamScan.setData(contentReader.getContentString()
							.getBytes());
					inStreamScan.setHost(this.host);
					inStreamScan.setPort(this.port);
					inStreamScan.setTimeout(this.timeout);
					inStreamScan.setNodeService(this.nodeService);
					inStreamScan.setNodeRef(nodeRef);
					inStreamScan.setChunkSize(this.chunk_size);
					res = inStreamScan.scan();

				} catch (ContentIOException e) {
					logger.info("Not found content for nodeRef: "
							+ nodeRef.getId() + " of "
							+ contentReader.getContentUrl()
							+ ". ¿Is closed?: " + contentReader.isClosed());
				} catch (IOException e) {
					logger.error("Error in instream operation.", e);
				}
			}
			/*
			 * if mode is VIRUSTOTAL
			 */
			else if (mode.toUpperCase().equals("VIRUSTOTAL")) {
				try {
					VirusTotalScan virusTotalScan = new VirusTotalScan(
							this.vt_key, this.vt_url);
					virusTotalScan.setNodeService(this.nodeService);
					virusTotalScan.setNodeRef(nodeRef);
					virusTotalScan.setFileToScan(contentPath);
					res = virusTotalScan.scan();

				} catch (ContentIOException e) {
					logger.info("Not found content for nodeRef: "
							+ nodeRef.getId() + " of "
							+ contentReader.getContentUrl()
							+ ". ¿Is closed?: " + contentReader.isClosed());
				} catch (IOException e) {
					logger.error("Error in virustotal operation.", e);
				}
			} else {
				if (logger.isDebugEnabled())
					logger.info(this.getClass().getName()
							+ ": [No config action: {COMMAND|INSTREAM|VIRUSTOTAL}]");
			}

			/*
			 * if res not zero then infected!!
			 */
			if (res != 0) {
				if (logger.isInfoEnabled() || logger.isDebugEnabled()) {
					logger.info(this.getClass().getName() + ": [ALERT File: "
							+ contentReader.getContentUrl() + " is infected!]");
				}
				this.addAspect(nodeRef);
			} else {
				if (logger.isDebugEnabled())
					logger.debug("[File: " + contentReader.getContentUrl()
							+ " is clean");
			}
		}
	}

	/**
	 * Add aspect Infected is not assigned
	 * 
	 * @param nodeRef
	 */
	private void addAspect(NodeRef nodeRef) {
		Calendar cal = GregorianCalendar.getInstance();
		Date dt = cal.getTime();
		String df = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssZ").format(dt);

		HashMap<QName, Serializable> properties = new HashMap<QName, Serializable>(
				1, 1.0f);
		properties.put(AlfviralModel.PROP_INFECTED_DATE, df.substring(0, 22)
				+ ":" + df.substring(22));
		properties.put(AlfviralModel.PROP_INFECTED_CLEAN, false);

		if (!nodeService.hasAspect(nodeRef, AlfviralModel.ASPECT_INFECTED)) {
			nodeService.addAspect(nodeRef, AlfviralModel.ASPECT_INFECTED,
					properties);
		} else {
			if (logger.isDebugEnabled())
				logger.debug("Este fichero se detectó como infectado anteriormente, se actualiza el aspecto.");
			nodeService.addProperties(nodeRef, properties);
		}
	}

	/**
	 * @param contentService
	 */
	public void setContentService(ContentService contentService) {
		this.contentService = contentService;
	}

	/**
	 * @param nodeService
	 */
	public void setNodeService(NodeService nodeService) {
		this.nodeService = nodeService;
	}

	/**
	 * @param store
	 */
	public void setStore(String store) {
		this.store = store;
	}

	/**
	 * @param command
	 */
	public void setCommand(List<String> command) {
		this.command = command;
	}

	/**
	 * @param mode
	 */
	public void setMode(String mode) {
		this.mode = mode;
	}

	/**
	 * @param host
	 */
	public void setHost(String host) {
		this.host = host;
	}

	/**
	 * @param port
	 */
	public void setPort(int port) {
		this.port = port;
	}

	/**
	 * @param timeout
	 */
	public void setTimeout(int timeout) {
		this.timeout = timeout;
	}

	/**
	 * @param chunk_size
	 */
	public void setChunkSize(int chunk_size) {
		this.chunk_size = chunk_size;
	}

	/**
	 * @param key
	 */
	public void setKey(String key) {
		this.vt_key = key;
	}

	/**
	 * @param url
	 */
	public void setUrl(String url) {
		this.vt_url = url;
	}

	/**
	 * @param file_exceptions
	 */
	public void setFileExceptions(String file_exceptions) {
		this.file_exceptions = file_exceptions;
	}
}
