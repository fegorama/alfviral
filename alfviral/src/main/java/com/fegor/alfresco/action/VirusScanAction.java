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

import java.util.List;

import org.alfresco.repo.action.executer.ActionExecuterAbstractBase;
import org.alfresco.service.cmr.action.Action;
import org.alfresco.service.cmr.action.ParameterDefinition;
import org.alfresco.service.cmr.repository.NodeRef;
import org.apache.log4j.Logger;
import com.fegor.alfresco.services.AntivirusService;

/**
 * VirusScan Action
 * 
 * @author fegor
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
	protected void executeImpl(Action action, NodeRef actionedUponNodeRef) {
		if (actionedUponNodeRef != null) {
			if (logger.isDebugEnabled()) {
				logger.debug(getClass().getName() + " scanFile for " + actionedUponNodeRef.getId());
			}
			antivirusService.scanFile(actionedUponNodeRef);
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
