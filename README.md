# **cvechecker**
This Python script is designed to enhance security assessments by integrating Common Vulnerabilities and Exposures (CVEs) identification into the network scanning process. Specifically, the script parses the output of the Nmap tool, extracts Common Platform Enumeration (CPE) identifiers, and utilizes them to identify associated CVEs. This automated approach helps security professionals quickly identify known vulnerabilities within their network infrastructure.

**Key Features:**
Nmap Output Parsing: The script accepts Nmap scan results in XML format, which typically contain detailed information about the network services, including discovered CPEs.
CPE Extraction: It systematically extracts CPE identifiers from the Nmap output. CPEs are standardized identifiers used to describe software, hardware, and firmware.
CVE Database Query: Using the extracted CPEs, the script queries a CVE database (NVD CVE repository) to find relevant vulnerabilities.

**Script Workflow:**
Input Handling: The script takes an Nmap XML output file as input.
XML Parsing: It parses the XML file to locate CPE entries for the discovered services.
CPE Querying: Each CPE is used to query a CVE database, retrieving relevant CVE records.
Report Generation: The script compiles the CVEs into a structured report includes CVE identifiers

**Prerequisites:**
Python 3.x: The script is written in Python and requires a compatible Python environment.
Nmap: The network scanning tool Nmap must be installed and used to generate the XML output.
Libraries: The script uses several Python libraries, including _xml.etree.ElementTree_ for XML parsing and _requests_ for making HTTP requests to CVE databases.

**Usage Example:**
python3 cvechecker.py nmap_output.xml

**Benefits:**
Automated CVE Identification: Saves time by automating the process of identifying known vulnerabilities from Nmap scan results.
Integration with Existing Tools: Enhances the capabilities of Nmap by adding a vulnerability analysis layer, making it a more powerful tool for security professionals.
