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

import java.io.File;
import java.io.IOException;
import java.io.Serializable;
import java.util.HashMap;

import org.alfresco.service.cmr.repository.NodeRef;
import org.alfresco.service.cmr.repository.NodeService;
import org.alfresco.service.namespace.QName;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.HttpStatus;
import org.apache.commons.httpclient.methods.PostMethod;
import org.apache.commons.httpclient.methods.multipart.FilePart;
import org.apache.commons.httpclient.methods.multipart.MultipartRequestEntity;
import org.apache.commons.httpclient.methods.multipart.Part;
import org.apache.commons.httpclient.methods.multipart.StringPart;
import org.apache.log4j.Logger;
import org.json.JSONException;
import org.json.JSONObject;

import com.fegor.alfresco.model.AlfviralModel;

/**
 * VirusTotalScan
 * 
 * @author fegor
 * 
 */
public class VirusTotalScan implements VirusScanMode {

	private final Logger logger = Logger.getLogger(VirusTotalScan.class);

	private NodeService nodeService;
	private NodeRef nodeRef;

	private String key = "";
	private String url_scan = "https://www.virustotal.com/vtapi/v2/file/scan";
	private String url_report = "https://www.virustotal.com/vtapi/v2/file/report";
	private String file_to_scan = "";
	private String resource;

	private JSONObject jso;
	private JSONObject jsoReport;

	/*
	 * Constructor
	 */
	public VirusTotalScan() {
		
	}
	
	/**
	 * Constructor
	 * 
	 * @param key
	 * @param url
	 */
	public VirusTotalScan(String key, String url) {
		if (logger.isDebugEnabled()) {
			logger.debug(this.getClass().getName() + ": [Api Key: " + key + "]");
			logger.debug(this.getClass().getName() + ": [URL: " + url + "]");
		}

		this.key = key;
		this.url_scan = url;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see com.fegor.alfresco.security.antivirus.VirusScanMode#scan()
	 */
	@Override
	public int scan() throws IOException {
		int result = 0;
		int resultHTTP = 0;
		int resultReport = 0;
		File targetFile = new File(this.file_to_scan);

		PostMethod postMethod = new PostMethod(this.url_scan);

		try {
			Part[] parts = { new StringPart("apikey", this.key),
					new FilePart("file", targetFile.getName(), targetFile) };

			postMethod.setRequestEntity(new MultipartRequestEntity(parts,
					postMethod.getParams()));

			HttpClient httpclient = new HttpClient();

			httpclient.getHttpConnectionManager().getParams()
					.setConnectionTimeout(8000);

			resultHTTP = httpclient.executeMethod(postMethod);
			if (logger.isDebugEnabled()) {
				logger.debug(this.getClass().getName() + ": [HTTP Result: "
						+ resultHTTP + "]");
			}

			if (resultHTTP == HttpStatus.SC_OK) {
				this.jso = new JSONObject(new String(
						postMethod.getResponseBodyAsString()));

				this.resource = this.jso.getString("resource");
				resultReport = this.report();

				/*
				 * Si el informe es positivo se asigna el aspecto.
				 */
				if (resultReport != 0) {
					this.addAspect();
					result = 1;
				}

			} else {
				logger.debug("Send fail, response="
						+ HttpStatus.getStatusText(resultHTTP));
			}

		} catch (JSONException jsoex) {
			logger.error("VirusScan.VirusTotalScan: ERROR "
					+ jsoex.getClass().getName() + " " + jsoex.getMessage());
			jsoex.printStackTrace();
		}

		finally {
			postMethod.releaseConnection();
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
		// TODO Implement POST method to rescan
		return this.scan();
	}

	/*
	 * Report
	 * 
	 * @see com.fegor.alfresco.security.antivirus.VirusScanMode#report()
	 */
	@Override
	public int report() throws IOException {
		int result = -1;
		PostMethod postMethod = new PostMethod(this.url_report);
		postMethod.addParameter("apikey", this.key);
		postMethod.addParameter("resource", this.resource);

		if (logger.isDebugEnabled()) {
			logger.debug(this.getClass().getName() + ": [URL: "
					+ this.url_report + "]");
			logger.debug(this.getClass().getName() + ": [Resource (report): "
					+ this.resource + "]");
		}

		try {
			HttpClient httpclient = new HttpClient();

			int i = 0;
			int response_code = 0;
			int positives = 0;
			do {
				result = httpclient.executeMethod(postMethod);

				if (logger.isDebugEnabled()) {
					logger.debug(this.getClass().getName()
							+ ": [HTTP Coonect (report) try: " + i + "]");
				}

				this.jsoReport = new JSONObject(
						postMethod.getResponseBodyAsString());

				if (result == HttpStatus.SC_OK) {
					
					response_code = this.jsoReport.getInt("response_code");
					if (logger.isDebugEnabled()) {
						logger.debug(this.getClass().getName()
								+ ": [response_code: " + response_code + "]");
						logger.debug(this.getClass().getName()
								+ ": [positives: " + positives + "]");
					}
					
					if (this.jsoReport.has("positives")) { 
						positives = this.jsoReport.getInt("positives");
						if (positives > 0) {
							result = 1;
						} else if (positives == 0) {
							result = 0;
						}
					} else {
						result = 0;
					}
				} else {
					logger.debug(this.getClass().getName()
							+ ": [Send fail, response="
							+ HttpStatus.getStatusText(result) + "]");
					result = 0;
				}
				i++;
			} while (i < 5 && response_code != 1);

		} catch (JSONException jsoex) {
			logger.error(this.getClass().getName() + ": [Error: "
					+ jsoex.getMessage() + "]");
			jsoex.printStackTrace();
		} catch (IOException ioe) {
			logger.error(this.getClass().getName() + ": [Error: "
					+ ioe.getMessage() + "]");
		} finally {
			postMethod.releaseConnection();
		}

		return result;
	}

	/**
	 * Add aspect Scaned From VirusTotal is not assigned
	 */
	private void addAspect() {

		try {
			HashMap<QName, Serializable> properties = new HashMap<QName, Serializable>(
					1, 1.0f);
			properties.put(AlfviralModel.PROP_VT_RESPONSE_CODE,
					this.jsoReport.getString("response_code"));
			properties.put(AlfviralModel.PROP_VT_VERBOSE_MSG,
					this.jsoReport.getString("verbose_msg"));
			properties.put(AlfviralModel.PROP_VT_RESOURCE,
					this.jsoReport.getString("resource"));
			properties.put(AlfviralModel.PROP_VT_SCAN_ID,
					this.jsoReport.getString("scan_id"));
			properties.put(AlfviralModel.PROP_VT_PERMALINK,
					this.jsoReport.getString("permalink"));
			properties.put(AlfviralModel.PROP_VT_SHA256,
					this.jsoReport.getString("sha256"));
			properties.put(AlfviralModel.PROP_VT_POSITIVES,
					this.jsoReport.getString("positives"));

			if (!this.nodeService.hasAspect(this.nodeRef,
					AlfviralModel.ASPECT_SCANNED_FROM_VIRUSTOTAL)) {
				this.nodeService.addAspect(this.nodeRef,
						AlfviralModel.ASPECT_SCANNED_FROM_VIRUSTOTAL,
						properties);
			} else {
				this.nodeService.addProperties(this.nodeRef, properties);
			}

			if (logger.isInfoEnabled()) {
				logger.info(this.getClass().getName()
						+ ": [Aspect SCANNED_FROM_VIRUSTOTAL assigned for "
						+ nodeRef.getId() + "]");
			}

		} catch (JSONException e) {
			logger.error("Error parsing JSON: " + e.getMessage());
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
	 * @param key
	 */
	public void setKey(String key) {
		this.key = key;
	}

	/**
	 * @param url_scan
	 */
	public void setUrlScan(String url_scan) {
		this.url_scan = url_scan;
	}

	/**
	 * @param url_report
	 */
	public void setUrlReport(String url_report) {
		this.url_report = url_report;
	}

	/**
	 * @param file
	 */
	public void setFileToScan(String file) {
		this.file_to_scan = file;
	}
}
