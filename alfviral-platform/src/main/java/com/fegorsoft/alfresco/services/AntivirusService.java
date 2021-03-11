package com.fegorsoft.alfresco.services;

import org.alfresco.service.cmr.repository.InvalidNodeRefException;
import org.alfresco.service.cmr.repository.NodeRef;

/**
 * @author fegor
 *
 */
public interface AntivirusService {
	void scanFile(NodeRef nodeRef) throws InvalidNodeRefException;
}
