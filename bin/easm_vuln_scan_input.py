import json
import os
import sys
from loguru import logger
import requests

# import splunklib.results as results
from requests.adapters import HTTPAdapter, Retry
import easm_helper

# sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))

from splunklib.modularinput import Scheme, Argument, Event, Script


# sys.path.append(
#     os.path.join(os.environ["SPLUNK_HOME"], "etc", "apps", "SA-VSCode", "bin")
# )
# try:
#     import splunk_debug as dbg  # noqa: E402 "# type: ignore
#     dbg.enable_debugging(timeout=10)
#     dbg.set_breakpoint()
# except ImportError as error:
#     print("Failed to import splunk_debug", file=sys.stderr)


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
        """ "EASM Vuln Scan Input" is the name Splunk will
        display to users for this input."""
        scheme = Scheme("EASM Vuln Scan Input")

        scheme.description = (
            "Submits a query to an external REST API "
            "to perfom vuln scan and post results back via HEC."
            " Ensure you have permission to scan targets."
            " Scans may generate a lot of traffic and take some time to complete."
        )
        scheme.use_external_validation = False

        # Set to false so each input can have an optional interval parameter
        scheme.use_single_instance = False

        url_argument = Argument("urls")
        url_argument.title = "URLs"
        url_argument.data_type = Argument.data_type_string
        url_argument.description = "Comma-separated list of URLs"
        scheme.add_argument(url_argument)

        entity_argument = Argument("entity")
        entity_argument.title = "Entity"
        entity_argument.data_type = Argument.data_type_string
        entity_argument.description = "Entity e.g. organisation name (lower case)"
        scheme.add_argument(entity_argument)

        return scheme

    def validate_input(self, validation_definition):
        urls = str(validation_definition.parameters["urls"])
        # useless line just to avoid linting issues:
        urls += ""
        # if urls not ...
        #     raise ValueError("urls must be...")

    def stream_events(self, inputs, ew):
        """there should only be one input as we're setting
        scheme.use_single_instance = False"""
        stanza = list(inputs.inputs.keys())[0]
        logger.debug(f"stanza name is {stanza}")

        # Get mod input params
        entity = str(inputs.inputs[stanza]["entity"])
        target_list = str(inputs.inputs[stanza]["urls"]).split(",")

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

        logger.debug("Starting queries")

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
        }

        if worker_url.endswith("/"):
            worker_url = worker_url[:-1]

        json_data["target_list"] = target_list

        session = requests.Session()
        retries = Retry(
            total=5,
            backoff_factor=0.1,
        )
        session.mount("http://", HTTPAdapter(max_retries=retries))

        try:
            logger.info("Trying to POST to " + worker_url + "/discovery/web_vuln_scan/")
            response = session.post(
                worker_url + "/discovery/web_vuln_scan/",
                headers=headers,
                json=json_data,
            )
        except Exception as e:
            logger.error(
                "Exception occured calling "
                + worker_url
                + "/discovery/web_vuln_scan/"
                + " - "
                + str(e)
            )
            return

        event = Event()
        event.stanza = stanza
        event.data = json.dumps(
            {
                "response": {
                    "discovery_type": "web_vuln_scan",
                    "text": response.text,
                    "status_code": response.status_code,
                }
            }
        )
        ew.write_event(event)


if __name__ == "__main__":
    sys.exit(MyScript().run(sys.argv))
