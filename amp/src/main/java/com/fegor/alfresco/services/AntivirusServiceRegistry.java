package com.fegor.alfresco.services;

import org.alfresco.service.NotAuditable;
import org.alfresco.service.namespace.NamespaceService;
import org.alfresco.service.namespace.QName;

public interface AntivirusServiceRegistry {

	static final QName ANTIVIRUS_SERVICE = QName.createQName(NamespaceService.ALFRESCO_URI, "AntivirusService");

    @NotAuditable
    AntivirusService getAntivirusService();
}
