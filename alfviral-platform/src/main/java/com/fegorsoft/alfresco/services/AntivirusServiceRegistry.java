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
package com.fegorsoft.alfresco.services;

import org.alfresco.service.NotAuditable;
import org.alfresco.service.namespace.NamespaceService;
import org.alfresco.service.namespace.QName;

public interface AntivirusServiceRegistry {

	static final QName ANTIVIRUS_SERVICE = QName.createQName(NamespaceService.ALFRESCO_URI, "AntivirusService");

    @NotAuditable
    AntivirusServiceImpl getAntivirusService();
}
