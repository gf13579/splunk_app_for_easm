[easminput://<name>]
*Submits a request to an external REST API to perfom recon and post results back via HEC.
interval = <value>
discovery_type = <value>
entity = <value>
take_screenshots = <value>

[easm_vuln_scan_input://<name>]
*Submits a request to an external REST API to perfom a web vuln scan and post results back via HEC. Please ensure you have permission to scan the targets, be aware that scans may generate a lot of traffic and take some time to complete.
urls = <value>
interval = <value>
entity = <value>

[easm_web_spider_input://<name>]
*Submits a request to an external REST API to perfom a web spider and post results back via HEC. Please ensure you have permission to scan the targets, be aware that scans may take some time to complete.
urls = <value>
interval = <value>
entity = <value>

[easm_active_port_scan_input://<name>]
*Submits a request to an external REST API to perfom an active port scan and post results back via HEC. Please ensure you have permission to scan the targets, be aware that scans may generate a lot of traffic and take some time to complete.
targets = <value>
interval = <value>
entity = <value>
host_filter = <value>