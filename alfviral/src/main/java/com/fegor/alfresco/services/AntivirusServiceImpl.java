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
package com.fegor.alfresco.services;

import java.io.Serializable;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.alfresco.model.ContentModel;
import org.alfresco.repo.action.executer.MailActionExecuter;
import org.alfresco.repo.action.scheduled.CronScheduledQueryBasedTemplateActionDefinition;
import org.alfresco.service.ServiceRegistry;
import org.alfresco.service.cmr.action.Action;
import org.alfresco.service.cmr.action.ActionService;
import org.alfresco.service.cmr.repository.ContentIOException;
import org.alfresco.service.cmr.repository.ContentReader;
import org.alfresco.service.cmr.repository.ContentService;
import org.alfresco.service.cmr.repository.InvalidNodeRefException;
import org.alfresco.service.cmr.repository.NodeRef;
import org.alfresco.service.cmr.repository.NodeService;
import org.alfresco.service.cmr.repository.StoreRef;
import org.alfresco.service.cmr.search.ResultSet;
import org.alfresco.service.cmr.search.SearchService;
import org.alfresco.service.cmr.security.AuthenticationService;
import org.alfresco.service.cmr.security.PersonService;
import org.alfresco.service.namespace.QName;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import com.fegor.alfresco.behavior.OnUpdateReadScan;
import com.fegor.alfresco.model.AlfviralModel;
import com.fegor.alfresco.security.antivirus.CommandScan;
import com.fegor.alfresco.security.antivirus.ICAPScan;
import com.fegor.alfresco.security.antivirus.InStreamScan;
import com.fegor.alfresco.security.antivirus.VirusScanMode;
import com.fegor.alfresco.security.antivirus.VirusTotalScan;

/**
 * @author Fernando.Gonzalez
 *
 */
public class AntivirusServiceImpl implements AntivirusService {
	private static final Log logger = LogFactory.getLog(AntivirusServiceImpl.class);
	private static final String FILE_ONLY = "only";
	private static final String FILE_EXCEPTIONS = "exceptions";
	private static final String EMAIL_TEMPLATES_PATH = "PATH:\"/app:company_home/app:dictionary/app:email_templates/cm:Alfviral";

	/*
	 * Services
	 */
	private ContentService contentService;
	private NodeService nodeService;
	private ContentReader contentReader;
	private ActionService actionService;
	private PersonService personService;
	private AuthenticationService authenticationService;

	private ServiceRegistry serviceRegistry;

	private OnUpdateReadScan onUpdateReadScan;

	/*
	 * Refs to beans
	 */
	private ICAPScan icapScan;
	private CommandScan commandScan;
	private InStreamScan inStreamScan;
	private VirusTotalScan virusTotalScan;

	/*
	 * Config
	 */
	private String mode;
	private boolean notifyAdmin;
	private boolean notifyUser;
	private String notifyAdminTemplate;
	private String notifyUserTemplate;
	private boolean notifyAsynchronously;

	private int icapPort;
	private String icapHost;
	private String icapService;

	private int inStreamChunkSize = 4096;
	private int inStreamPort;
	private String inStreamHost;
	private int inStreamTimeout;

	private List<String> commandExec;

	private String vtKey = "";
	private String vtUrl = "https://www.virustotal.com/vtapi/v2/file/scan";

	// private boolean onUpdate;
	// private boolean onRead;

	private CronScheduledQueryBasedTemplateActionDefinition runScriptScanFolder;

	/*
	 * for mode COMMAND
	 */
	private String store;

	/*
	 * Generic
	 */
	private String fileExceptions;
	private String fileOnly;
	private String fileOnlyOrExceptions;

	/**
	 * Scan file for nodeRef
	 * 
	 * @param nodeRef
	 */
	public void scanFile(NodeRef nodeRef) throws InvalidNodeRefException {
		int res = 0;

		nodeService = serviceRegistry.getNodeService();
		contentService = serviceRegistry.getContentService();
		actionService = serviceRegistry.getActionService();
		personService = serviceRegistry.getPersonService();
		authenticationService = serviceRegistry.getAuthenticationService();

		if (nodeService.exists(nodeRef)) {
			contentReader = contentService.getReader(nodeRef, ContentModel.PROP_CONTENT);

			if (shouldScan(contentReader)) {
				String contentUrl = contentReader.getContentUrl();
				String contentPath = contentUrl.replaceFirst("store:/", this.store);

				if (logger.isDebugEnabled()) {
					logger.debug(this.getClass().getName() + ": [NodeRef: " + nodeRef.getId() + "]");
					logger.debug(this.getClass().getName() + ": [File: " + contentPath + "]");
					logger.debug(this.getClass().getName() + ": [Type: " + contentReader.getMimetype() + "]");
					logger.debug(this.getClass().getName() + ": [Mode: " + mode.toUpperCase() + "]");
				}

				else if (contentReader != null) {
					if (logger.isDebugEnabled()) {
						logger.debug("File/Document is excluded for virus scan.");
					}
				}

				/*
				 * if mode is COMMAND
				 */
				if (mode.toUpperCase().equals(VirusScanMode.ScanModeCommand)) {
					commandScan.setCommand(commandExec);
					commandScan.setFileToScan(contentPath);
					res = commandScan.scan(nodeRef);
				}
				/*
				 * if mode is INSTREAM
				 */
				else if (mode.toUpperCase().equals(VirusScanMode.ScanModeInStream)) {

					try {
						inStreamScan.setChunkSize(inStreamChunkSize);
						inStreamScan.setHost(inStreamHost);
						inStreamScan.setPort(inStreamPort);
						inStreamScan.setTimeout(inStreamTimeout);
						inStreamScan.setData(contentReader.getContentString().getBytes());
						res = inStreamScan.scan(nodeRef);
					}

					catch (ContentIOException e) {
						logger.info("Not found content for nodeRef: " + nodeRef.getId() + " of "
								+ contentReader.getContentUrl() + ". ¿Is closed?: " + contentReader.isClosed());
					}
				}
				/*
				 * if mode is VIRUSTOTAL
				 */
				else if (mode.toUpperCase().equals(VirusScanMode.ScanModeVirusTotal)) {

					try {
						virusTotalScan.setKey(vtKey);
						virusTotalScan.setUrlScan(vtUrl);
						virusTotalScan.setFileToScan(contentPath);
						res = virusTotalScan.scan(nodeRef);
					}

					catch (ContentIOException e) {
						logger.info("Not found content for nodeRef: " + nodeRef.getId() + " of "
								+ contentReader.getContentUrl() + ". ¿Is closed?: " + contentReader.isClosed());
					}
				}
				/*
				 * if mode is ICAP
				 */
				else if (mode.toUpperCase().equals(VirusScanMode.ScanModeICap)) {
					try {
						icapScan.setHost(icapHost);
						icapScan.setPort(icapPort);
						icapScan.setService(icapService);
						icapScan.setData(contentReader.getContentString().getBytes());
						res = icapScan.scan(nodeRef);
					}

					catch (ContentIOException e) {
						logger.info("Not found content for nodeRef: " + nodeRef.getId() + " of "
								+ contentReader.getContentUrl() + ". ¿Is closed?: " + contentReader.isClosed());
					}
				}
				/*
				 * if none
				 */
				else {
					logger.info(this.getClass().getName() + ": [No config action: {COMMAND|INSTREAM|ICAP|VIRUSTOTAL}]");
				}

				/*
				 * if res not zero then infected!!
				 */
				if (res != 0) {

					if (logger.isInfoEnabled() || logger.isDebugEnabled()) {
						logger.info(this.getClass().getName() + ": [ALERT File: " + contentReader.getContentUrl()
								+ " is infected!]");
					}
					this.addAspect(nodeRef);

				} else {
					if (logger.isDebugEnabled())
						logger.debug("[File: " + contentReader.getContentUrl() + " is clean");
				}
			}
		}
	}

	private boolean shouldScan(final ContentReader contentReader) {
		if ((!(fileOnlyOrExceptions.toLowerCase()).equals(FILE_ONLY))
				&& (!(fileOnlyOrExceptions.toLowerCase()).equals(FILE_EXCEPTIONS))) {
			logger.error("Property alfviral.file.only_or_exceptions not is '" + FILE_ONLY + "' or '" + FILE_EXCEPTIONS
					+ "'");
			return false;
		}
		if (contentReader != null) {
			final boolean fileExceptionsMatches = fileExceptions.indexOf(contentReader.getMimetype()) == -1
					&& (fileOnlyOrExceptions.toLowerCase()).equals(FILE_EXCEPTIONS);
			final boolean fileOnlyMatches = fileOnly.indexOf(contentReader.getMimetype()) != -1
					&& (fileOnlyOrExceptions.toLowerCase()).equals(FILE_ONLY);
			return fileExceptionsMatches || fileOnlyMatches;
		}
		return false;
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

		HashMap<QName, Serializable> properties = new HashMap<QName, Serializable>(1, 1.0f);
		properties.put(AlfviralModel.PROP_INFECTED_DATE, df.substring(0, 22) + ":" + df.substring(22));
		properties.put(AlfviralModel.PROP_INFECTED_CLEAN, false);

		if (!nodeService.hasAspect(nodeRef, AlfviralModel.ASPECT_INFECTED)) {

			nodeService.addAspect(nodeRef, AlfviralModel.ASPECT_INFECTED, properties);

			// If notify is true
			if (notifyUser == true || notifyAdmin == true) {
				notifyForInfected(nodeRef);
			}

			// TODO Add deleted file possibility if is infected

		} else {

			if (logger.isDebugEnabled())
				logger.debug("Este fichero se detectó como infectado anteriormente, se actualiza el aspecto.");
			nodeService.addProperties(nodeRef, properties);
		}
	}

	/**
	 * Notify
	 */
	private void notifyForInfected(NodeRef nodeRef) {
		NodeRef nrCurrentUser = personService.getPerson(authenticationService.getCurrentUserName());
		String currentUserMail = (String) nodeService.getProperty(nrCurrentUser, ContentModel.PROP_EMAIL);

		if (notifyUser) {
			final String subject = "Document infected!";
			final String alternativeText = "File infected as NodeRef: " + nodeRef + ". Contacting with your administrator ASAP!";
			sendMailNotification(currentUserMail, subject, alternativeText, notifyUserTemplate, nodeRef);
		}

		if (notifyAdmin) {
			final String subject = "File infected!";
			final String alternativeText = "File infected as NodeRef: " + nodeRef + " upload to user: " + currentUserMail;

			NodeRef nrAdmin = personService.getPerson("admin");
			String userAdminMail = (String) nodeService.getProperty(nrAdmin, ContentModel.PROP_EMAIL);
			sendMailNotification(userAdminMail, subject, alternativeText, notifyAdminTemplate, nodeRef);
		}
	}

	private void sendMailNotification(String mailTo, String subject, String alternativeText, String templateName, NodeRef nodeRef) {
		Action mailAction = actionService.createAction(MailActionExecuter.NAME);
		Map<String, Object> model = new HashMap<>();
		model.put("dateEpoch", new Date(0));
		String templatePATH = EMAIL_TEMPLATES_PATH + "/cm:";
		
		mailAction.setParameterValue(MailActionExecuter.PARAM_TO, mailTo);
		mailAction.setParameterValue(MailActionExecuter.PARAM_SUBJECT, subject);

		if (StringUtils.isEmpty(templateName)) {
			mailAction.setParameterValue(MailActionExecuter.PARAM_TEXT, alternativeText);
		}

		else {
			templatePATH += templateName + "\"";
			ResultSet resultSet = serviceRegistry.getSearchService().query(
					new StoreRef(StoreRef.PROTOCOL_WORKSPACE, "SpacesStore"), SearchService.LANGUAGE_LUCENE,
					templatePATH);

			if (resultSet.length() == 0) {
				logger.error("Template " + templatePATH + " not found.");
				return;
			}

			mailAction.setParameterValue(MailActionExecuter.PARAM_TEMPLATE, resultSet.getNodeRef(0));
			mailAction.setParameterValue(MailActionExecuter.PARAM_TEMPLATE_MODEL, (Serializable) model);
		}

		logger.info(
				this.getClass().getName() + ": [Sending notify mail notify of infected to " + mailTo + "]");
		mailAction.setExecuteAsynchronously(notifyAsynchronously);
		actionService.executeAction(mailAction, nodeRef);
	}

	/**
	 * @param icapScan
	 */
	public void setIcapScan(ICAPScan icapScan) {
		this.icapScan = icapScan;
	}

	/**
	 * @param commandScan
	 */
	public void setCommandScan(CommandScan commandScan) {
		this.commandScan = commandScan;
	}

	/**
	 * @param inStreamScan
	 */
	public void setInStreamScan(InStreamScan inStreamScan) {
		this.inStreamScan = inStreamScan;
	}

	/**
	 * @param virusTotalScan
	 */
	public void setVirusTotalScan(VirusTotalScan virusTotalScan) {
		this.virusTotalScan = virusTotalScan;
	}

	/**
	 * @param mode
	 */
	public void setMode(String mode) {
		this.mode = mode;
	}

	/**
	 * @param store
	 */
	public void setStore(String store) {
		this.store = store;
	}

	/**
	 * @param notifyAdmin
	 */
	public void setNotifyAdmin(boolean notifyAdmin) {
		this.notifyAdmin = notifyAdmin;
	}

	/**
	 * @param notifyUser
	 */
	public void setNotifyUser(boolean notifyUser) {
		this.notifyUser = notifyUser;
	}

	public boolean isNotifyAsynchronously() {
		return notifyAsynchronously;
	}

	public void setNotifyAsynchronously(boolean notifyAsynchronously) {
		this.notifyAsynchronously = notifyAsynchronously;
	}

	/**
	 * @param notifyAdminTemplate
	 */
	public void setNotifyAdminTemplate(String notifyAdminTemplate) {
		this.notifyAdminTemplate = notifyAdminTemplate;
	}

	/**
	 * @param notifyUserTemplate
	 */
	public void setNotifyUserTemplate(String notifyUserTemplate) {
		this.notifyUserTemplate = notifyUserTemplate;
	}

	/**
	 * @param serviceRegistry
	 */
	public void setServiceRegistry(ServiceRegistry serviceRegistry) {
		this.serviceRegistry = serviceRegistry;
	}

	/**
	 * @return
	 */
	public ICAPScan getIcapScan() {
		return icapScan;
	}

	/**
	 * @return
	 */
	public InStreamScan getInStreamScan() {
		return inStreamScan;
	}

	/**
	 * @param icapPort
	 */
	public void setIcapPort(int icapPort) {
		this.icapPort = icapPort;
	}

	/**
	 * @param icapHost
	 */
	public void setIcapHost(String icapHost) {
		this.icapHost = icapHost;
	}

	/**
	 * @param icapService
	 */
	public void setIcapService(String icapService) {
		this.icapService = icapService;
	}

	/**
	 * @param inStreamChunkSize
	 */
	public void setInStreamChunkSize(int inStreamChunkSize) {
		this.inStreamChunkSize = inStreamChunkSize;
	}

	/**
	 * @param inStreamPort
	 */
	public void setInStreamPort(int inStreamPort) {
		this.inStreamPort = inStreamPort;
	}

	/**
	 * @param inStreamHost
	 */
	public void setInStreamHost(String inStreamHost) {
		this.inStreamHost = inStreamHost;
	}

	/**
	 * @param inStreamTimeout
	 */
	public void setInStreamTimeout(int inStreamTimeout) {
		this.inStreamTimeout = inStreamTimeout;
	}

	/**
	 * @param commandExec
	 */
	public void setCommandExec(List<String> commandExec) {
		this.commandExec = commandExec;
	}

	/**
	 * @param vtKey
	 */
	public void setVtKey(String vtKey) {
		this.vtKey = vtKey;
	}

	/**
	 * @param vtUrl
	 */
	public void setVtUrl(String vtUrl) {
		this.vtUrl = vtUrl;
	}

	/**
	 * @param onUpdateReadScan
	 */
	public void setOnUpdateReadScan(OnUpdateReadScan onUpdateReadScan) {
		this.onUpdateReadScan = onUpdateReadScan;
	}

	/**
	 * @param onUpdate
	 */
	public void setOnUpdate(boolean onUpdate) {
		this.onUpdateReadScan.setOnUpdate(onUpdate);
		// this.onUpdateReadScan.init();
	}

	/**
	 * @param onRead
	 */
	public void setOnRead(boolean onRead) {
		this.onUpdateReadScan.setOnRead(onRead);
		// this.onUpdateReadScan.init();
	}

	/**
	 * @param fileExceptions
	 */
	public void setFileExceptions(String fileExceptions) {
		this.fileExceptions = fileExceptions;
	}

	/**
	 * @param fileOnly
	 */
	public void setFileOnly(String fileOnly) {
		this.fileOnly = fileOnly;
	}

	/**
	 * @param fileOnlyOrExceptions
	 */
	public void setFileOnlyOrExceptions(String fileOnlyOrExceptions) {
		this.fileOnlyOrExceptions = fileOnlyOrExceptions;
	}

	/**
	 * @param runScriptScanFolder
	 */
	public void setRunScriptScanFolder(CronScheduledQueryBasedTemplateActionDefinition runScriptScanFolder) {
		this.runScriptScanFolder = runScriptScanFolder;
	}

	/**
	 * @param queryTemplate
	 */
	public void setQueryTemplate(String queryTemplate) {
		this.runScriptScanFolder.setQueryTemplate(queryTemplate);
	}

	/**
	 * @param cronExpression
	 */
	public void setCronExpression(String cronExpression) {
		this.runScriptScanFolder.setCronExpression(cronExpression);
	}
}
