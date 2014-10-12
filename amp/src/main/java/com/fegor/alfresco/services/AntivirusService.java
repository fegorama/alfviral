package com.fegor.alfresco.services;

import java.io.Serializable;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.HashMap;
import java.util.Map;

import org.alfresco.model.ContentModel;
import org.alfresco.repo.action.executer.MailActionExecuter;
import org.alfresco.service.cmr.action.Action;
import org.alfresco.service.cmr.action.ActionService;
import org.alfresco.service.cmr.repository.ContentIOException;
import org.alfresco.service.cmr.repository.ContentReader;
import org.alfresco.service.cmr.repository.ContentService;
import org.alfresco.service.cmr.repository.NodeRef;
import org.alfresco.service.cmr.repository.NodeService;
import org.alfresco.service.cmr.security.AuthenticationService;
import org.alfresco.service.cmr.security.PersonService;
import org.alfresco.service.namespace.QName;
import org.apache.log4j.Logger;

import com.fegor.alfresco.model.AlfviralModel;
import com.fegor.alfresco.security.antivirus.CommandScan;
import com.fegor.alfresco.security.antivirus.ICAPScan;
import com.fegor.alfresco.security.antivirus.InStreamScan;
import com.fegor.alfresco.security.antivirus.VirusTotalScan;

/**
 * @author Fernando.Gonzalez
 *
 */
/**
 * @author Fernando.Gonzalez
 *
 */
/**
 * @author Fernando.Gonzalez
 *
 */
/**
 * @author Fernando.Gonzalez
 *
 */
public class AntivirusService {
	private final Logger logger = Logger.getLogger(AntivirusService.class);

	/*
	 * Services
	 */
	private ContentService contentService;
	private NodeService nodeService;
	private ContentReader contentReader;
	private ActionService actionService;
	private PersonService personService;
	private AuthenticationService authenticationService;

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

	/*
	 * for mode COMMAND
	 */
	private String store;

	/*
	 * Generic
	 */
	private String file_exceptions;

	/**
	 * Scan file for nodeRef
	 * 
	 * @param nodeRef
	 */
	public void scanFile(NodeRef nodeRef) {
		int res = 0;

		contentReader = this.contentService.getReader(nodeRef,
				ContentModel.PROP_CONTENT);

		// TODO Include for files_for_scan, in option to file_exception

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

				commandScan.setFileToScan(contentPath);
				res = commandScan.scan(nodeRef);
			}
			/*
			 * if mode is INSTREAM
			 */
			else if (mode.toUpperCase().equals("INSTREAM")) {

				try {

					inStreamScan.setData(contentReader.getContentString()
							.getBytes());
					res = inStreamScan.scan(nodeRef);

				} catch (ContentIOException e) {

					logger.info("Not found content for nodeRef: "
							+ nodeRef.getId() + " of "
							+ contentReader.getContentUrl() + ". ¿Is closed?: "
							+ contentReader.isClosed());
				}
			}
			/*
			 * if mode is VIRUSTOTAL
			 */
			else if (mode.toUpperCase().equals("VIRUSTOTAL")) {

				try {

					virusTotalScan.setFileToScan(contentPath);
					res = virusTotalScan.scan(nodeRef);

				} catch (ContentIOException e) {

					logger.info("Not found content for nodeRef: "
							+ nodeRef.getId() + " of "
							+ contentReader.getContentUrl() + ". ¿Is closed?: "
							+ contentReader.isClosed());
				}
			}
			/*
			 * if mode is ICAP
			 */
			else if (mode.toUpperCase().equals("ICAP")) {

				try {

					icapScan.setData(contentReader.getContentString()
							.getBytes());
					res = icapScan.scan(nodeRef);

				} catch (ContentIOException e) {
					logger.info("Not found content for nodeRef: "
							+ nodeRef.getId() + " of "
							+ contentReader.getContentUrl() + ". ¿Is closed?: "
							+ contentReader.isClosed());
				}
			}
			/*
			 * if none
			 */
			else {

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

		// TODO Add other admin and templates of use new class Notify()...

		Action mailAction = actionService.createAction(MailActionExecuter.NAME);

		// Map<String, Object> model = new HashMap<String, Object>();
		// model.put("dateEpoch", new Date(0));

		NodeRef nrCurrentUser = personService.getPerson(authenticationService
				.getCurrentUserName());

		String currentUser = (String) nodeService.getProperty(nrCurrentUser,
				ContentModel.PROP_EMAIL);

		if (notifyUser == true) {
			mailAction.setParameterValue(MailActionExecuter.PARAM_TO,
					currentUser);
			mailAction.setParameterValue(MailActionExecuter.PARAM_SUBJECT,
					"Document infected!");
			mailAction.setParameterValue(MailActionExecuter.PARAM_TEXT,
					"File infected as NodeRef: " + nodeRef
							+ ". Contacting with your administrator ASAP!");
			// mailAction.setParameterValue(MailActionExecuter.PARAM_TEMPLATE,
			// "alfresco/extension/mail" + notifyUserTemplate);
			// mailAction.setParameterValue(
			// MailActionExecuter.PARAM_TEMPLATE_MODEL,
			// (Serializable) model);
			logger.info(this.getClass().getName()
					+ ": [Sending notify mail notify of infected to "
					+ currentUser + "]");
			actionService.executeAction(mailAction, null);
		}

		if (notifyAdmin == true) {
			NodeRef nrAdmin = personService.getPerson("admin");
			String userAdmin = (String) nodeService.getProperty(nrAdmin,
					ContentModel.PROP_EMAIL);
			mailAction
					.setParameterValue(MailActionExecuter.PARAM_TO, userAdmin);
			mailAction.setParameterValue(MailActionExecuter.PARAM_SUBJECT,
					"File infected!");
			mailAction.setParameterValue(MailActionExecuter.PARAM_TEXT,
					"File infected as NodeRef: " + nodeRef
							+ " upload to user: " + currentUser);
			// mailAction.setParameterValue(MailActionExecuter.PARAM_TEMPLATE,
			// "alfresco/extension/mail" + notifyAdminTemplate);
			// mailAction.setParameterValue(
			// MailActionExecuter.PARAM_TEMPLATE_MODEL,
			// (Serializable) model);
			logger.info(this.getClass().getName()
					+ ": [Sending mail notify of infected to admin]");
			actionService.executeAction(mailAction, null);
		}
	}

	/**
	 * @param icapScan
	 */
	public void setIcapScan(ICAPScan icapScan) {
		this.icapScan = icapScan;
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
	 * @param file_exceptions
	 */
	public void setFileExceptions(String file_exceptions) {
		this.file_exceptions = file_exceptions;
	}

	/**
	 * @param store
	 */
	public void setStore(String store) {
		this.store = store;
	}

	/**
	 * @param actionService
	 */
	public void setActionService(ActionService actionService) {
		this.actionService = actionService;
	}

	/**
	 * @param personService
	 */
	public void setPersonService(PersonService personService) {
		this.personService = personService;
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

	/**
	 * @param authenticationService
	 */
	public void setAuthenticationService(
			AuthenticationService authenticationService) {
		this.authenticationService = authenticationService;
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

}
