package com.fegor.alfresco.behavior;

import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import org.alfresco.service.cmr.action.ActionService;
import org.alfresco.service.cmr.repository.NodeRef;
import org.alfresco.service.cmr.repository.NodeService;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.MockitoJUnitRunner;

import com.fegor.alfresco.model.AlfviralModel;

@RunWith(MockitoJUnitRunner.class)
public class OnUpdateReadScanTest {

	private OnUpdateReadScan onUpdateReadScan;

	private NodeRef testNode;

	@Mock
	private ActionService actionService;
	@Mock
	private NodeService nodeService;

	@Before
	public void setup() {
		onUpdateReadScan = new OnUpdateReadScan();
		onUpdateReadScan.setActionService(actionService);
		onUpdateReadScan.setNodeService(nodeService);
		testNode = new NodeRef("workspace://TestStore/test");
	}

	@Test
	public void testDeleteOnContentUpdate() {
		onUpdateReadScan.setDeleteOnUpdate(true);

		when(nodeService.exists(testNode)).thenReturn(true);
		when(nodeService.hasAspect(testNode, AlfviralModel.ASPECT_INFECTED)).thenReturn(true);

		onUpdateReadScan.onContentUpdate(testNode, true);

		verify(nodeService).deleteNode(testNode);
	}

	@Test
	public void testDeleteOnContentUpdateDeactivated() {
		onUpdateReadScan.setDeleteOnUpdate(false);

		when(nodeService.exists(testNode)).thenReturn(true);
		when(nodeService.hasAspect(testNode, AlfviralModel.ASPECT_INFECTED)).thenReturn(true);

		onUpdateReadScan.onContentUpdate(testNode, true);

		verify(nodeService, Mockito.never()).deleteNode(testNode);
	}

	@Test
	public void doNotDeleteNonInfectedOnContentUpdate() {
		onUpdateReadScan.setDeleteOnUpdate(true);

		when(nodeService.exists(testNode)).thenReturn(true);
		when(nodeService.hasAspect(testNode, AlfviralModel.ASPECT_INFECTED)).thenReturn(false);

		onUpdateReadScan.onContentUpdate(testNode, true);

		verify(nodeService, Mockito.never()).deleteNode(testNode);
	}
}
