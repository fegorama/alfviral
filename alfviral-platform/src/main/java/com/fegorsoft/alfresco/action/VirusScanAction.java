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
package com.fegorsoft.alfresco.action;

import java.util.List;

import org.alfresco.repo.action.executer.ActionExecuterAbstractBase;
import org.alfresco.repo.security.authentication.AuthenticationUtil;
import org.alfresco.service.cmr.action.Action;
import org.alfresco.service.cmr.action.ParameterDefinition;
import org.alfresco.service.cmr.repository.InvalidNodeRefException;
import org.alfresco.service.cmr.repository.NodeRef;
import org.apache.log4j.Logger;

import com.fegorsoft.alfresco.services.AntivirusService;

/**
 * VirusScan Action
 * 
 * @author Fernando González (fegor@fegor.com)
 *
 */
public class VirusScanAction extends ActionExecuterAbstractBase {

	private final Logger logger = Logger.getLogger(VirusScanAction.class);

	/*
	 * Services
	 */
	private AntivirusService antivirusService;

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * org.alfresco.repo.action.executer.ActionExecuterAbstractBase#executeImpl
	 * (org.alfresco.service.cmr.action.Action,
	 * org.alfresco.service.cmr.repository.NodeRef)
	 */
	@Override
	protected void executeImpl(Action action, final NodeRef actionedUponNodeRef) {

		if (AuthenticationUtil.getRunAsUser() != null) {
			run(actionedUponNodeRef);
		}

		else {
			if (logger.isDebugEnabled()) {
				logger.debug("Run action as system user for node '" + actionedUponNodeRef + "'");
			}
			
			AuthenticationUtil.runAsSystem(new AuthenticationUtil.RunAsWork<Void>() {
				@Override
				public Void doWork() throws Exception {
					try {
						run(actionedUponNodeRef);
					}

					catch (Exception e) {
						logger.error(e);
					}
					return null;
				}
			});
		}
	}

	protected void run(NodeRef actionedUponNodeRef) {
		if (actionedUponNodeRef != null) {
			try {
				antivirusService.scanFile(actionedUponNodeRef);
			}

			catch (InvalidNodeRefException inre) {

				// TODO In Share (version 4.2), update of document produce the
				// Node not found error

				logger.warn(this.getClass().getName() + ": NodeRef: " + actionedUponNodeRef.getId()
						+ " not found. This node has changed in transaction.");
			}

			catch (net.sf.acegisecurity.AuthenticationCredentialsNotFoundException acnfe) {
				logger.error("Not credentials.");
			}
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.alfresco.repo.action.ParameterizedItemAbstractBase#
	 * addParameterDefinitions(java.util.List)
	 */
	@Override
	protected void addParameterDefinitions(List<ParameterDefinition> arg0) {
		// do not
	}

	/**
	 * @param antivirusService
	 */
	public void setAntivirusService(AntivirusService antivirusService) {
		this.antivirusService = antivirusService;
	}
}
