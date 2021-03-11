package com.fegorsoft.alfresco.services;

import static org.junit.Assert.fail;
import static org.mockito.Mockito.when;

import org.alfresco.service.ServiceRegistry;
import org.alfresco.service.cmr.repository.ContentService;
import org.alfresco.service.cmr.repository.NodeRef;
import org.alfresco.service.cmr.repository.NodeService;
import org.alfresco.service.namespace.QName;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.MockitoJUnitRunner;

import com.fegorsoft.alfresco.services.AntivirusServiceImpl;

@RunWith(MockitoJUnitRunner.class)
public class AntivirusServiceImplTest {
	
	private AntivirusServiceImpl service;
	private NodeRef testNode;

	@Mock
	private ServiceRegistry serviceRegistry;
	@Mock
	private NodeService nodeService;
	@Mock
	private ContentService contentService;

	@Before
	public void setup() {
		service = new AntivirusServiceImpl();
		service.setServiceRegistry(serviceRegistry);
		testNode = new NodeRef("workspace://TestStore/test");
		service.setFileExceptions("text/html|text/xml|application/pdf|image/jpeg|image/png|image/giftext/plain");
		service.setFileOnly("application/octet-stream|application/x-dosexec|application/bat|application/x-bat|application/x-msdos-program|application/textedit|application/cmd|application/x-ms-dos-executable");
		service.setFileOnlyOrExceptions("exceptions");
	}
	
	@Test
	public void testNullContentReader() {		
		when(serviceRegistry.getNodeService()).thenReturn(nodeService);
		when(serviceRegistry.getContentService()).thenReturn(contentService);
		when(nodeService.exists(testNode)).thenReturn(true);
		when(contentService.getReader(Mockito.any(NodeRef.class), Mockito.any(QName.class))).thenReturn(null);
		
		try {
			service.scanFile(testNode);
		} catch (Exception e) {
			fail("There should be no exception when the content reader is null");
		}
	}
}
