# Splunk App for External Attack Surface Management

## Overview

The App for External Attack Surface Management (EASM) is intended to:
- Discover your internet-facing assets and services, starting with nothing more than your domain name
- Alert on new subdomains, newly exposed ports and web app vulnerabilities
- Integrate with vulnerability management to patch and harden

The App for EASM makes use of open-source recon tools from ProjectDiscovery.io, wrapped in a REST API that runs on a worker server external to Splunk. The worker has been designed to be easy to stand up - using Docker - is stateless and secured via HTTPS and API key-based auth.

Requirements:
1. Splunk
2. Somewhere to run the EASM Worker server (“worker”) as a container
3. Some way of letting Splunk talk HTTPS to the worker, e.g. a reverse proxy terminating TLS and proxying traffic to the worker’s ASGI web server

For further details around standing up a worker, refer to [gf13579/splunk_easm_worker (github.com)](https://github.com/gf13579/splunk_easm_worker).

## Installation and Configuration Overview

1. Install the App for External Attack Surface Management from Splunk or a tgz release from github
2. Create an index e.g. 'easm' or pick an existing index to use and update the `easm_index` macro as required, e.g. `index=your_index_here`
3. Setup a HEC input - and ensure port 8088 is accessible by our EASM worker. Leave the sourcetype set to Automatic and specify your target index (e.g. easm) as the default.
4. Make a note of the HEC token and confirm that HEC is enabled, globally (by default it isn’t).
2. Use the app's setup page to configure details of your external worker - the base url:port and API key, along with a HEC URL and token to be passed to the worker during discovery
3. Edit the app's lookups - via the app's UI - to configure your seeds i.e apex domains, IPs, IP ranges and known subdomains
4. Create discovery jobs - modular inputs - again, via the app's UI for convenience
5. Wait for results

## App Configuration Steps

Use the setup page to configure the application

|**Field**|**Description**|**Example**|
|---|---|---|
|Base URL of EASM Worker|The URL of our EASM worker - starting with https, followed by the FQDN of our host.|https://some-easm-worker-host.spinningplates.net|
|API Key|The value we configured in the .env file earlier|some_super_secure_string|
|HEC URL|The URL of our HEC endpoint - which could be on this Splunk server, or another one|http://3.25.119.19:8088/services/collector/event|
|HEC Token|The HEC token shown by Splunk when setting up a HEC input|dd8f39b4-a93e-4d07-9a94-2128c4bcd0ab|

Now we can setup our seeds - typically one or more apex domains e.g. example.com and example.org.

Seeds are managed via lookups. The EASM App’s navigation menu includes links to edit those lookups using the Lookup Editor (“Splunk App for Lookup File Editing“) - if installed.

Configuration → Seed Items → Edit Seed Domains

Populate apex_domains.csv, for example:

|entity|target|description|out_of_scope|
|---|---|---|---|
|example|example.com|||
|example|example.org|||
|portswigger|ginandjuice.shop|||
|acunetix|vulnweb.com|||

Now we’ll setup a basic discovery job - again, using the menu:

Configuration → Data Inputs → Edit Discovery Jobs

Give the discovery input a name, specify the types of discovery - or * for all basic discovery types. Specify an entity - which relates back to the entity field in the seed lookups and use the More settings option to specify a target index and the interval. As with all modular inputs, leave the interval blank to run the input a single time, or specify either a cron string or the number of seconds between inputs.

On saving the input, Splunk will run it based on the schedule. If the schedule was left blank, Splunk will run it immediately and once only - which is handy for testing.

The app typically needs to run discovery at least twice to start getting interesting data - the first time to discover an initial set of subdomains, which will be used in subsequent discovery of open ports, web services etc.

## Troubleshooting

In the app, check the EASM Logs dashboard (Advanced -> EASM Logs) to see Splunk invoking the modular inputs, and output from those inputs.

On the worker node, you can view live log activity (stdout) using `docker-compose logs --follow --timestamps`.