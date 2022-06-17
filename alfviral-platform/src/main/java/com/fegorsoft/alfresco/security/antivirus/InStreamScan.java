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

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketException;

import org.alfresco.service.cmr.repository.ContentReader;
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
public final class InStreamScan implements VirusScanMode {

	private final Logger logger = Logger.getLogger(InStreamScan.class);

	private ContentReader dataReader;
	private int chunkSizeInBytes = 4096;
	private int port;
	private String host;
	private int timeout;
	private NodeService nodeService;
	private NodeRef nodeRef;

	/**
	 * Constructor
	 */
	public InStreamScan() {
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
			logger.info(getClass().getName() + "Connect to INSTREAM is OK");
		}
		
		return result;
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
		} catch (IOException e) {
			logger.error("Error while scanning NodeRef: " + nodeRef, e);
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
		int i = 0;
		int result = 0;

		/*
		 * create socket
		 */
		if (logger.isDebugEnabled()) {
			logger.debug(getClass().getName() + "Connect to " + host + ":" + port);
		}
		
		Socket socket = new Socket();
		socket.connect(new InetSocketAddress(host, port));

		try {
			socket.setSoTimeout(timeout);
		} catch (SocketException e) {
			logger.error("Error in timeout: " + timeout + "ms", e);
		}

		DataOutputStream dataOutputStream = null;
		BufferedReader bufferedReader = null;
		InputStream inputStream = dataReader.getContentInputStream();

		String res = null;
		try {
			if (logger.isDebugEnabled()) {
				logger.debug(getClass().getName() + "Send zINSTREAM");
			}

			dataOutputStream = new DataOutputStream(socket.getOutputStream());
			bufferedReader = new BufferedReader(new InputStreamReader(socket.getInputStream(), "ASCII"));
			dataOutputStream.writeBytes("zINSTREAM\0");

			if (logger.isDebugEnabled()) {
				logger.debug(getClass().getName() + "Send stream for  " + inputStream.available() + " bytes");
			}

			byte[] chunk = new byte[chunkSizeInBytes];
			int length = inputStream.read(chunk);
			while (length >= 0) {
				dataOutputStream.writeInt(length);
				dataOutputStream.write(chunk, 0, length);
				if (bufferedReader.ready()) {
					res = bufferedReader.readLine();
					throw new IOException(res);
				}
				length = inputStream.read(chunk);
			}

			dataOutputStream.writeInt(0);
			dataOutputStream.write('\0');
			dataOutputStream.flush();

			res = bufferedReader.readLine();
			
			if (logger.isDebugEnabled()) {
				logger.debug(getClass().getName() + "Result of scan is:  " + res);
			}
			
		} finally {
			if (bufferedReader != null)
				bufferedReader.close();
			
			if (dataOutputStream != null)
				dataOutputStream.close();

			if (inputStream != null)
				inputStream.close();
			
			if (socket != null)
				socket.close();
		}

		res = res.trim();
		if (res.startsWith("INSTREAM size limit exceeded")) {
			throw new IOException(res);
		}

		/*
		 * if is OK then not infected, else, infected...
		 */
		if (!res.equals("stream: OK")) {
			result = 1;
			addAspect();
		}

		return result;
	}

	/*
	 * Re-scanning
	 * 
	 * @see com.fegorsoft.alfresco.security.antivirus.VirusScanMode#rescan()
	 */
	@Override
	public int rescan() throws IOException {
		return scan();
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
	 * Add aspect Scaned From ClamAV is not assigned
	 */
	private void addAspect() {
		
		if (logger.isDebugEnabled()) {
			logger.debug(getClass().getName() + "Adding aspect if not exist");
		}
		
		if (!nodeService.hasAspect(nodeRef,
				AlfviralModel.ASPECT_SCANNED_FROM_CLAMAV)) {
			nodeService.addAspect(nodeRef,
					AlfviralModel.ASPECT_SCANNED_FROM_CLAMAV, null);
		}

		if (logger.isInfoEnabled()) {
			logger.info(getClass().getName()
					+ ": [Aspect SCANNED_FROM_CLAMAV assigned for "
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
	 * @param dataReader
	 */
	public void setDataReader(ContentReader dataReader) {
		this.dataReader = dataReader;
	}

	/**
	 * @param chunkSizeInBytes
	 */
	public void setChunkSizeInBytes(int chunkSizeInBytes) {
		this.chunkSizeInBytes = chunkSizeInBytes;
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
	 * @param timeout
	 */
	public void setTimeout(int timeout) {
		this.timeout = timeout;
	}

}
