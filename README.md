# Alfviral (Alfresco Virus Alert)

_Alfresco's Module for Enterprise and Community versions to scan documents using every antivirus engine. Verifying documents with ClamAV, Symantec, McAfee, Sophos, [...] using some mechanisms as sending datastream to a TCP port, execute command with parameters, sending to www.virustotal.com or using ICAP protocol._

## Begining 🚀

_This version is for Alfresco 6.x and including Docker deploy_

### Pre-requisites 📋

_Antivirus software as McAfee, Symantec or ClamAV or nothing if you use alfviral-antivirus docker_

```
cd alfviral-antivirus\docker
docker-compose -f docker-compose.yml up --build
```

## Features ⚙️

* Detection through 4 modes (for command, clamav data stream, http for virustotal.com and ICAP protocol)
* Use of "policies" to scan uploaded and/or read content
* Use of "scheduler" to scan spaces/folders programmatically
* Use of action "scan" in user interfaces (Explorer and Share)
* File exceptions
* Notification by email
* Assignment of "aspects" (subtypes) to classify infections
* ICAP (Internet Content Adaptation Protocol) for scanning many antivirus engines: Symantec, McAfee, Sophos, ...
* Email notify to user and admin in case of infection
* Arquitecture has service: AntivirusService
* For package installation (JAR) or Docker

### Deploy 🔧

To deploy in package version copy JAR files with platform and share Alfresco. 

See [Alfresco docs for extension-packaging](https://docs.alfresco.com/content-services/latest/develop/extension-packaging/)

## Contributing 🖇️

Please, see the [CONTRIBUTING.md](CONTRIBUTING.md) for details of our code of conduct, and the process for submitting pull requests.

## Versions 📌

See [tags in this repository](tags).

## License 📄

This project is under Apache License - see [LICENSE.md](LICENSE.md) for more details.

## Thanks to 🎁

* [Alfresco](https://www.alfresco.com)
* [Order of the bee](https://orderofthebee.net/)

## Other information ✒️

For Alfresco 4.2.x before versions go to [Google Code](https://code.google.com/p/alfviral/)

Alfresco Summit 2013: [Presentation in PDF](https://github.com/fegorama/alfviral/blob/master/docs/Alfviral_Alfresco_Summit_2013_v1.pdf)
