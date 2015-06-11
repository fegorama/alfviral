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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import org.alfresco.service.cmr.repository.NodeRef;
import org.alfresco.service.cmr.repository.NodeService;
import org.apache.log4j.Logger;

import com.fegor.alfresco.model.AlfviralModel;
import com.fegor.alfresco.protocols.icap.ICAP;
import com.fegor.alfresco.protocols.icap.ICAPException;

/**
 * ICAPScan
 * 
 * @author fegor
 *
 */
public class ICAPScan implements VirusScanMode {

	private final Logger logger = Logger.getLogger(ICAPScan.class);

	private byte[] data;
	private int port;
	private String host;
	private String service;
	private NodeService nodeService;
	private NodeRef nodeRef;

	/**
	 * Constructor
	 */
	public ICAPScan() {
	}

	/**
	 * Test connection
	 * 
	 * @return test of connection
	 */
	public boolean testConnection() {
		boolean result = true;
		
		logger.info(getClass().getName() + "Testing connect to " + host.toString() + ":" + port);
		Socket socket = new Socket();
		try {
			socket.connect(new InetSocketAddress(host, port));
		} catch (IOException ioe) {
			logger.error(getClass().getName() + "Error connecting to " + host.toString() + ":" + port);
			ioe.printStackTrace();
			result = false;
		} finally {
			if (socket.isConnected()) {
				try {
					socket.close();
				} catch (IOException e) {
					logger.error(getClass().getName() + "Error closing to " + host.toString() + ":" + port);
					e.printStackTrace();
					result = false;
				}
			}
		}
		
		if (result == true) {
			logger.info(getClass().getName() + "Connect to ICAP is OK");
		}
		
		return result;
	}
	
	/* (non-Javadoc)
	 * @see com.fegor.alfresco.security.antivirus.VirusScanMode#scan(org.alfresco.service.cmr.repository.NodeRef)
	 */
	@Override
	public int scan(NodeRef nodeRef) {
		int res = 0;
		this.nodeRef = nodeRef;
		try {
			res = scan();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return res;
	}
	
	/*
	 * (non-Javadoc)
	 * 
	 * @see com.fegor.alfresco.security.antivirus.VirusScanMode#scan()
	 */
	@Override
	public int scan() throws IOException {
		int result = 0;
		boolean res = true;
		
		InputStream inputStream = null;
		
		try { 
			if (logger.isDebugEnabled()) {
				logger.debug(getClass().getName() + "Connect to " + host + ":" + port);
			}
		    
			ICAP icap = new ICAP(host, port, service);	      
			inputStream = new  ByteArrayInputStream (data);
			
			if (logger.isDebugEnabled()) {
				logger.debug(getClass().getName() + "Send document as  " + data.length + " bytes");
			}

			res = icap.scanStream(inputStream);

			if (logger.isDebugEnabled()) {
				logger.debug(getClass().getName() + "Result of scan is:  " + res);
			}
        } catch (ICAPException ex) {
            System.err.println("Could not scan document: " + ex.getMessage());
            ex.printStackTrace();
		} finally {
			if (inputStream != null)
				inputStream.close();
		}

		/*
		 * if is OK then not infected, else, infected...
		 */
		if (res == false) {
			result = 1;
			addAspect();
		}

		return result;
	}

	/*
	 * Re-scanning
	 * 
	 * @see com.fegor.alfresco.security.antivirus.VirusScanMode#rescan()
	 */
	@Override
	public int rescan() throws IOException {
		return scan();
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
	 * Add aspect Scaned From ICAP is not assigned
	 */
	private void addAspect() {
		
		if (logger.isDebugEnabled()) {
			logger.debug(getClass().getName() + "Adding aspect if not exist");
		}
		
		if (!nodeService.hasAspect(nodeRef,
				AlfviralModel.ASPECT_SCANNED_FROM_ICAP)) {
			nodeService.addAspect(nodeRef,
					AlfviralModel.ASPECT_SCANNED_FROM_ICAP, null);
		}

		if (logger.isInfoEnabled()) {
			logger.info(getClass().getName()
					+ ": [Aspect SCANNED_FROM_ICAP assigned for "
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
	 * @param data
	 */
	public void setData(byte[] data) {
		this.data = data;
	}

	/**
	 * @param port
	 */
	public void setPort(int port) {
		this.port = port;
	}

	/**
	 * @param host
	 */
	public void setHost(String host) {
		this.host = host;
	}

	/**
	 * @param service
	 */
	public void setService(String service) {
		this.service = service;
	}
}
