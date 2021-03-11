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
package com.fegorsoft.alfresco.behavior;

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
import org.apache.log4j.Logger;

import com.fegorsoft.alfresco.model.AlfviralModel;

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
	private boolean deleteOnUpdate;

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

		if (logger.isDebugEnabled()) {
			logger.debug("NodeRef Id: " + nodeRef.getId().toString());
		}

		if (nodeService.exists(nodeRef)) {
			actionService.executeAction(
					actionService.createAction("alfviral.virusscan.action"),
					nodeRef);

			if (nodeService.hasAspect(nodeRef, AlfviralModel.ASPECT_INFECTED)) {

				if (logger.isDebugEnabled()) {

					logger.debug(this.getClass().getName()
							+ ": [In onContentUpdate: " + nodeRef
							+ " is infected]");
				}

				if (deleteOnUpdate) {
					deleteInfectedNode(nodeRef);
				}
			}
		}

		else {
			logger.debug("NodeRef Id: " + nodeRef.getId().toString()
					+ " has deleted (update event)");
		}
	}

	private void deleteInfectedNode(final NodeRef nodeRef) {
		logger.info("Delete infected node " + nodeRef);
		nodeService.addAspect(nodeRef, ContentModel.ASPECT_TEMPORARY, null);
		nodeService.deleteNode(nodeRef);
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
		actionService.executeAction(
				actionService.createAction("alfviral.virusscan.action"),
				nodeRef);

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
		logger.info(this.getClass().getName()
				+ " Alfresco Virus Alert AMP has been loaded in the behaviour");
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
	 * @return deleteOnUpdate
	 */
	public boolean isDeleteOnUpdate() {
		return deleteOnUpdate;
	}

	/**
	 * @param deleteOnUpdate
	 */
	public void setDeleteOnUpdate(boolean deleteOnUpdate) {
		this.deleteOnUpdate = deleteOnUpdate;
	}
}
