package com.fegor.alfresco.evaluator;

import org.alfresco.web.action.evaluator.BaseActionEvaluator;
import org.alfresco.web.bean.repository.Node;

import com.fegor.alfresco.model.AlfviralModel;

public class VirusScanEvaluator extends BaseActionEvaluator {
	
	private static final long serialVersionUID = 1L;

	/* (non-Javadoc)
	 * @see org.alfresco.web.action.evaluator.BaseActionEvaluator#evaluate(org.alfresco.web.bean.repository.Node)
	 */
	public boolean evaluate(Node node) {
		return !(node.hasAspect(AlfviralModel.ASPECT_INFECTED));
	}

}