import json
import os
import sys
from loguru import logger
import requests
# import splunklib.results as results
import easm_consts
from requests.adapters import HTTPAdapter, Retry
import easm_helper

# sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))

from splunklib.modularinput import Scheme, Argument, Event, Script

# sys.path.append(
#     os.path.join(os.environ["SPLUNK_HOME"], "etc", "apps", "SA-VSCode", "bin")
# )
# import splunk_debug as dbg  # noqa: E402 "# type: ignore

# dbg.enable_debugging(timeout=10)

# dbg.set_breakpoint()

log_file = os.environ["SPLUNK_HOME"] + "/var/log/splunk/app_for_easm.log"
logger.remove()
logger.add(sink=log_file, level="INFO")
logger.add(sink=sys.stderr, level="ERROR")

# for development
logger.add(sink=log_file, level="DEBUG")


def flatten_list(list_of_lists):
    return [item for sublist in list_of_lists for item in sublist]


class MyScript(Script):
    def get_scheme(self):
        # "EASM Input" is the name Splunk will display to users for this input.
        scheme = Scheme("EASM Input")

        scheme.description = (
            "Submits a query to an external REST API "
            "to perfom recon and post results back via HEC."
        )
        scheme.use_external_validation = False

        # Set to false so each input can have an optional interval parameter
        scheme.use_single_instance = False

        discovery_type_argument = Argument("discovery_type")
        discovery_type_argument.title = "Discovery Types"
        discovery_type_argument.data_type = Argument.data_type_string
        discovery_type_argument.description = (
            "* or comma-separated subset of [subdomains,open_ports,http_services,"
            "dns_records,tls_certs,web_tech]"
        )
        scheme.add_argument(discovery_type_argument)

        entity_argument = Argument("entity")
        entity_argument.title = "Entity"
        entity_argument.data_type = Argument.data_type_string
        entity_argument.description = (
            "Entity e.g. organisation name"
            " - as used in EASM app lookup files. Wildcard (*) is supported"
        )
        scheme.add_argument(entity_argument)

        take_screenshots_argument = Argument("take_screenshots")
        take_screenshots_argument.title = "Take Screenshots When Scanning Web Services"
        take_screenshots_argument.data_type = Argument.data_type_boolean
        take_screenshots_argument.description = (
            "Enable screenshots using a headless browser when doing http service discovery."
            " This increases the time taken for scans and the size of ingested data."
        )
        scheme.add_argument(take_screenshots_argument)

        return scheme

    def validate_input(self, validation_definition):
        """If validate_input does not raise an Exception, the input is
        assumed to be valid. Otherwise it prints the exception as an error message
        when telling splunkd that the configuration is invalid.

        :param validation_definition: a ValidationDefinition object
        """
        # Get the parameters from the ValidationDefinition object,

        discovery_type = str(validation_definition.parameters["discovery_type"])

        for dt in discovery_type.replace(" ", "").split(","):
            if dt not in [
                "*",
                "subdomains",
                "open_ports",
                "http_services",
                "dns_records",
                "tls_certs",
                "web_tech",
            ]:
                raise ValueError("discovery_type must be a valid discovery type")

    def stream_events(self, inputs, ew):
        """
        :param inputs: an InputDefinition object
        :param ew: an EventWriter object
        """

        # there should only be one input as we're setting scheme.use_single_instance = False
        stanza = list(inputs.inputs.keys())[0]
        logger.debug(f"stanza name is {stanza}")

        # Get mod input params
        discovery_type = str(inputs.inputs[stanza]["discovery_type"])
        entity = str(inputs.inputs[stanza]["entity"])
        take_screenshots = bool(int(inputs.inputs[stanza].get("take_screenshots", False)))

        settings = easm_helper.get_password(self.service, "app_for_easm_realm")
        if settings is None:
            message = "No settings defined. Exiting"
            logger.error(message)
            return

        worker_url, hec_url, hec_token, api_key = settings.split("___")

        if api_key is None:
            message = "No api_key defined - none will be sent with API request"
            logger.warning(message)

        if not worker_url.lower().startswith("https://"):
            message = "Worker URL must use HTTPS"
            logger.error(message)
            return

        apex_domains = [
            item
            for item in easm_helper.read_lookup_file("apex_domains.csv")
            if item["out_of_scope"] != "true" and item["entity"] in (entity, "*")
        ]
        ip_ranges = [
            item
            for item in easm_helper.read_lookup_file("ip_ranges.csv")
            if item["out_of_scope"] != "true" and item["entity"] in (entity, "*")
        ]
        known_subdomains = [
            item
            for item in easm_helper.read_lookup_file("known_subdomains.csv")
            if item["out_of_scope"] != "true" and item["entity"] in (entity, "*")
        ]
        discovered_subdomains = [
            item for item in easm_helper.read_lookup_file("discovered_subdomains.csv")
        ]
        discovered_open_ports = [
            item for item in easm_helper.read_lookup_file("discovered_open_ports.csv")
        ]
        discovered_web_services = [
            item for item in easm_helper.read_lookup_file("discovered_web_services.csv")
        ]

        headers = {
            "Content-Type": "application/json",
            "Authorization": "Bearer " + api_key,
        }

        if api_key:
            headers["api_key"] = api_key

        json_data = {
            "entity": entity,
            "callback_type": "splunk",
            "callback_url": hec_url,  # '   ',
            "callback_auth": "Splunk " + hec_token,
            "callback_verify": False,
            "take_screenshots": take_screenshots
        }

        if worker_url.endswith("/"):
            worker_url = worker_url[:-1]

        if discovery_type == "*":
            discovery_types = [
                "subdomains",
                "open_ports",
                "http_services",
                "dns_records",
                "tls_certs",
                "web_tech",
            ]
        else:
            discovery_types = discovery_type.replace(" ", "").split(",")

        logger.debug("Starting queries")

        for dt in discovery_types:
            if dt == "web_tech":
                target_list = [target["url"] for target in discovered_web_services]
            elif dt == "subdomains":
                # Just apex domains
                target_list = [target["target"] for target in apex_domains]
            elif dt in ("dns_records"):
                # All hostnames
                target_list = (
                    [target["target"] for target in apex_domains]
                    + [target["target"] for target in known_subdomains]
                    + [target["hostname"] for target in discovered_subdomains]
                )
            elif dt in ("open_ports", "http_services", "tls_certs"):
                # All potential hostnames and IPs
                target_list = (
                    [target["target"] for target in apex_domains]
                    + [target["target"] for target in ip_ranges]
                    + [target["target"] for target in known_subdomains]
                    + [target["hostname"] for target in discovered_subdomains
                        if target["ip"] != "127.0.0.1"]
                    + flatten_list(
                        [target["ip"].split(",") for target in discovered_subdomains
                         if target["ip"] != "127.0.0.1"]
                    )
                )

            if dt == "http_services":
                target_list += [
                    str(target["ip"] + ":" + target["port"])
                    for target in discovered_open_ports
                    if target["port"] not in easm_consts.COMMON_NON_HTTP_PORTS
                ]

            json_data["target_list"] = target_list
            # TESTING
            # json_data["target_list"] = target_list[:5]

            session = requests.Session()
            retries = Retry(
                total=5,
                backoff_factor=0.1,
            )
            session.mount("http://", HTTPAdapter(max_retries=retries))

            try:
                logger.info("Trying to POST to " + worker_url + f"/discovery/{dt}/")
                response = session.post(
                    worker_url + f"/discovery/{dt}/", headers=headers, json=json_data
                )
            except Exception as e:
                logger.error(
                    "Exception occured calling "
                    + worker_url
                    + f"/discovery/{dt}/"
                    + " - "
                    + str(e)
                )
                return

            event = Event()
            event.stanza = stanza
            event.data = json.dumps(
                {
                    "response": {
                        "discovery_type": dt,
                        "text": response.text,
                        "status_code": response.status_code,
                    }
                }
            )
            ew.write_event(event)

        logger.debug("Finished queries")


if __name__ == "__main__":
    sys.exit(MyScript().run(sys.argv))
