# Splunk App for External Attack Surface Management

## Overview

The App for External Attack Surface Management (EASM) is intended to:
- Discover your internet-facing assets and services, starting with nothing more than your domain name
- Alert on new subdomains, newly exposed ports and web app vulnerabilities
- Integrate with vulnerability management to patch and harden

The App for EASM makes use of open-source recon tools from ProjectDiscovery.io, wrapped in a REST API that runs on a worker server external to Splunk. The worker has been designed to be easy to stand up - using Docker - is stateless and secured via HTTPS and API key-based auth.

## Installation and Configuration

1. Install the App for External Attack Surface Management from Splunk or a tgz release from github
2. Use the app's setup page to configure details of your external worker - the base url:port and API key, along with a HEC URL and token to be passed to the worker during discovery
3. Edit the app's lookups - via the app's UI - to configure your seeds i.e apex domains, IPs, IP ranges and known subdomains
4. Create discovery jobs - modular inputs - again, via the app's UI for convenience
5. Wait for results

A more detailed guide with screenshots will follow. For now, check out the overview of the companion tool required for the EASM App: [gf13579/splunk_easm_worker (github.com)](https://github.com/gf13579/splunk_easm_worker)