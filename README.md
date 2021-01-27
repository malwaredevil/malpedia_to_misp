# Malpedia to MISP ingestor

1. [Malpedia to MISP ingestor](#malpedia-to-misp-ingestor)
	1. [About](#about)
	2. [Automatic setup with Docker and Docker Compose (Easy mode)](#automatic-setup-with-docker-and-docker-compose-easy-mode)

## About

The Malpedia to MISP ingestor gathers data from various sources to catalog malware and store the data in a MISP instance you provide. The project:

1) Downloads:
   1) The Malpedia malware corpus
   2) The Malpedia Client
   3) The Malpedia threat actor and malware family metadata
   4) MITRE CTI Attack Matrix
   5) MISP Galaxies
2) Builds an incident tree in MISP:
   1) Threat Actor => Malware Family => Version => Specimen
3) Creates tags that identify various aspects of each of the tiers of the tree including but not limited to:
   1) Country
   2) Types of Incidents
   3) Synonyms
4) Associates all known MITRE ATT&CK Matrix codes

## Automatic setup with Docker and Docker Compose (Easy mode)

1) [See instructions on Malpedia to MISP Docker Project.](https://github.com/malwaredevil/malpedia_to_misp_docker)

