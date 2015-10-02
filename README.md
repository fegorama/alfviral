alfviral (Alfresco Virus Alert)
===============================

Alfresco's Module for Enterprise and Community versions to scan documents using every antivirus engine. Verifying documents with ClamAV, Symantec, McAfee, Sophos, [...] using some mechanisms as sending datastream to a TCP port, execute command with parameters, sending to www.virustotal.com or using ICAP protocol.

Features:
  - Detection through 4 modes (for command, clamav data stream, http for virustotal.com and ICAP protocol)
  - Use of "policies" to scan uploaded and/or read content
  - Use of "scheduler" to scan spaces/folders programmatically
  - Use of action "scan" in user interfaces (Explorer and Share)
  - File exceptions
  - Notification by email
  - Assignment of "aspects" (subtypes) to classify infections
  - ICAP (Internet Content Adaptation Protocol) for scanning many antivirus engines: Symantec, McAfee, Sophos, ...
  - Email notify to user and admin in case of infection
  - Arquitecture has service: AntivirusService
  
For 4.2.x before versions go to https://code.google.com/p/alfviral/

Alfresco Summit 2013: https://github.com/fegorama/alfviral/blob/master/docs/Alfviral_Alfresco_Summit_2013_v1.pdf

