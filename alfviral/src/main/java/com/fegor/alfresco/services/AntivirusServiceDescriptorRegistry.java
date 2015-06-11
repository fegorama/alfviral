package com.fegor.alfresco.services;

import org.alfresco.repo.service.ServiceDescriptorRegistry;

public class AntivirusServiceDescriptorRegistry extends ServiceDescriptorRegistry implements AntivirusServiceRegistry {

	@Override
	public AntivirusService getAntivirusService() {
		return (AntivirusService)getService(ANTIVIRUS_SERVICE);
	}
}
