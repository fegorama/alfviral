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

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketException;

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
public class InStreamScan implements VirusScanMode {

	private final Logger logger = Logger.getLogger(InStreamScan.class);

	private byte[] data;
	private int chunk_size = 4096;
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

	/*
	 * (non-Javadoc)
	 * 
	 * @see com.fegor.alfresco.security.antivirus.VirusScanMode#scan()
	 */
	@Override
	public int scan() throws IOException {
		int i = 0;
		int result = 0;

		/*
		 * create socket
		 */
		Socket socket = new Socket();
		socket.connect(new InetSocketAddress(this.host, this.port));

		try {
			socket.setSoTimeout(this.timeout);
		} catch (SocketException e) {
			logger.error("Error in timeout: " + this.timeout + "ms", e);
		}

		DataOutputStream dataOutputStream = null;
		BufferedReader bufferedReader = null;

		String res = null;
		try {
			dataOutputStream = new DataOutputStream(socket.getOutputStream());
			dataOutputStream.writeBytes("zINSTREAM\0");

			while (i < data.length) {
				if (i + this.chunk_size >= data.length) {
					this.chunk_size = data.length - i;
				}
				dataOutputStream.writeInt(chunk_size);
				dataOutputStream.write(data, i, chunk_size);
				i += chunk_size;
			}

			dataOutputStream.writeInt(0);
			dataOutputStream.write('\0');
			dataOutputStream.flush();

			bufferedReader = new BufferedReader(new InputStreamReader(
					socket.getInputStream(), "ASCII"));

			res = bufferedReader.readLine();
		} finally {
			if (bufferedReader != null)
				bufferedReader.close();
			if (dataOutputStream != null)
				dataOutputStream.close();
			if (socket != null)
				socket.close();
		}

		/*
		 * if is OK then not infected, else, infected...
		 */
		if (!res.trim().equals("stream: OK")) {
			result = 1;
			this.addAspect();
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
	 * Add aspect Scaned From ClamAV is not assigned
	 */
	private void addAspect() {

		if (!this.nodeService.hasAspect(this.nodeRef,
				AlfviralModel.ASPECT_SCANNED_FROM_CLAMAV)) {
			this.nodeService.addAspect(this.nodeRef,
					AlfviralModel.ASPECT_SCANNED_FROM_CLAMAV, null);
		}

		if (logger.isInfoEnabled()) {
			logger.info(this.getClass().getName()
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
	 * @param data
	 */
	public void setData(byte[] data) {
		this.data = data;
	}

	/**
	 * @param chunk_size
	 */
	public void setChunk_size(int chunk_size) {
		this.chunk_size = chunk_size;
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
