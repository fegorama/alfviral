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
package com.fegor.alfresco.behavior;

import java.util.List;

import org.alfresco.model.ContentModel;
import org.alfresco.repo.content.ContentServicePolicies;
import org.alfresco.repo.policy.Behaviour;
import org.alfresco.repo.policy.Behaviour.NotificationFrequency;
import org.alfresco.repo.policy.JavaBehaviour;
import org.alfresco.repo.policy.PolicyComponent;
import org.alfresco.service.cmr.action.ActionService;
import org.alfresco.service.cmr.repository.NodeRef;
import org.alfresco.service.cmr.repository.NodeService;
import org.alfresco.service.namespace.NamespaceService;
import org.alfresco.service.namespace.QName;
import org.alfresco.util.ApplicationContextHelper;
import org.apache.log4j.Logger;
import org.springframework.beans.BeansException;
import org.springframework.context.ApplicationContext;

import com.fegor.alfresco.action.VirusScan;
import com.fegor.alfresco.model.AlfviralModel;
import com.fegor.alfresco.security.antivirus.InStreamScan;

/**
 * Integrates antivirus scanning documents for alfresco
 * <p>
 * Implements the policies of "OnContentUpdate" and "OnContentRead".
 * <p>
 * The project is in: {@link} http://code.google.com/p/alfviral/
 * 
 * @author Fernando González (skype://fegorama)
 * @version 0.1
 */
public class OnUpdateReadScan implements
		ContentServicePolicies.OnContentUpdatePolicy,
		ContentServicePolicies.OnContentReadPolicy {
	private final Logger logger = Logger.getLogger(OnUpdateReadScan.class);

	private NodeService nodeService;
	private String mode;

	/*
	 * behaviours
	 */
	private Behaviour onContentUpdate;
	private Behaviour onContentRead;

	/*
	 * dependencies
	 */
	private PolicyComponent policyComponent;
	private ActionService actionService;

	/*
	 * configuration
	 */
	private boolean on_update;
	private boolean on_read;

	/**
	 * Init method; policies definitions and bindings
	 */
	public void init() {
		if (logger.isDebugEnabled())
			logger.debug(this.getClass().getName() + ": [init]");
		
		// create behavior and binding for updates
		if (this.on_update) {
			this.onContentUpdate = new JavaBehaviour(this, "onContentUpdate",
					NotificationFrequency.TRANSACTION_COMMIT);

			this.policyComponent.bindClassBehaviour(QName.createQName(
					NamespaceService.ALFRESCO_URI, "onContentUpdate"),
					ContentModel.TYPE_CMOBJECT, this.onContentUpdate);

		}

		// create behavior and binding for read
		if (this.on_read) {
			this.onContentRead = new JavaBehaviour(this, "onContentRead",
					NotificationFrequency.TRANSACTION_COMMIT);

			this.policyComponent.bindClassBehaviour(QName.createQName(
					NamespaceService.ALFRESCO_URI, "onContentRead"),
					ContentModel.TYPE_CMOBJECT, this.onContentRead);
		}

	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * org.alfresco.repo.content.ContentServicePolicies.OnContentUpdatePolicy
	 * #onContentUpdate(org.alfresco.service.cmr.repository.NodeRef, boolean)
	 */
	@Override
	public void onContentUpdate(NodeRef nodeRef, boolean flag) {	
		this.actionService.executeAction(
				actionService.createAction("alfviral.virusscan.action"),
				nodeRef);

		if (nodeService.hasAspect(nodeRef, AlfviralModel.ASPECT_INFECTED)) {
			if (logger.isDebugEnabled()) {
				logger.debug(this.getClass().getName()
						+ ": [In onContentUpdate: " + nodeRef + " is infected]");
			}
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * org.alfresco.repo.content.ContentServicePolicies.OnContentReadPolicy#
	 * onContentRead(org.alfresco.service.cmr.repository.NodeRef)
	 */
	@Override
	public void onContentRead(NodeRef nodeRef) {
		VirusScan virusScan = new VirusScan();
		virusScan.init();
		virusScan.execute(null, nodeRef);

		// this.actionService.executeAction(actionService.createAction("alfviral.virusscan.action"),
		// nodeRef);
		if (nodeService.hasAspect(nodeRef, AlfviralModel.ASPECT_INFECTED)) {
			if (logger.isDebugEnabled()) {
				logger.debug(this.getClass().getName()
						+ ": [In onContentRead: " + nodeRef + " is infected]");
			}
		}
	}

	/**
	 * Visualize message "loaded"
	 */
	public void loaded() {
		logger.info(this.getClass().getName() + " Alfresco Virus Alert AMP has been loaded in the behaviour");
	}

	public void setPolicyComponent(PolicyComponent policyComponent) {
		this.policyComponent = policyComponent;
	}

	/**
	 * @param nodeService
	 */
	public void setNodeService(NodeService nodeService) {
		this.nodeService = nodeService;
	}

	/**
	 * @param actionService
	 */
	public void setActionService(ActionService actionService) {
		this.actionService = actionService;
	}

	/**
	 * @param on_update
	 */
	public void setOnUpdate(boolean on_update) {
		this.on_update = on_update;
	}

	/**
	 * @param on_read
	 */
	public void setOnRead(boolean on_read) {
		this.on_read = on_read;
	}
	
	/**
	 * @param mode
	 */
	public void setMode(String mode) {
		this.mode = mode;
	}
}
