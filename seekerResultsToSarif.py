# -*- coding: utf-8 -*-
import json
import logging
import argparse
import sys
from timeit import default_timer as timer
import requests
from operator import itemgetter
import urllib.parse
import traceback

__author__ = "Jouni Lehto"
__versionro__="0.1.0"

#Global variables
args = None 

def getHeader():
    global args
    return {
            'Authorization': args.token, 
            'Accept': 'text/plain',
            'Content-Type': '*/*'
        }

def getVulnerabilities():
    global args
    parameters = {'format': 'JSON', 'language': 'en', 'projectKeys': args.project, 'includeStacktrace': args.stacktrace,
                    'includeHttpHeaders': False, 'includeHttpParams': False, 'includeDescription': True, 
                    'includeRemediation': True, 'includeSummary': True, 'includeVerificationProof': False,
                    'includeTriageEvents': False, 'includeComments': False}
    if args.codeLocationTypeKeys: parameters['codeLocationTypeKeys'] = args.codeLocationTypeKeys.upper()
    if args.minSeverity: parameters['minSeverity'] = args.minSeverity.upper()
    if args.onlySeekerVerified: parameters['onlySeekerVerified'] = args.onlySeekerVerified
    if args.customTagNames: parameters['codeLocationTypeKeys'] = args.customTagNames

    endpoint = "/rest/api/latest/vulnerabilities" + get_parameter_string(parameters)
    logging.debug(endpoint)
    response = requests.get(args.url+endpoint, headers=getHeader())
    rules, results, ruleIds = [], [], []
    if response.status_code == 200:
        for vulnerability in response.json():
            rule, result = {}, {}
            rulesId = getValue(vulnerability, 'ItemKey')
            ## Adding vulnerabilities as a rule
            if not rulesId in ruleIds:
                fullDescription = getValue(vulnerability, "Description")[:1000]
                rule = {"id":rulesId, "name": getValue(vulnerability, "VulnerabilityName"), "helpUri": getValue(vulnerability, 'SeekerServerLink'), "shortDescription":{"text":f'{getValue(vulnerability, "Summary")}'}, 
                    "fullDescription":{"text": fullDescription, "markdown": fullDescription},
                    "help":{"text":fullDescription, "markdown":fullDescription},
                    "properties": {"security-severity": nativeSeverityToNumber(getValue(vulnerability, "Severity").lower()), "tags": getTags(vulnerability)},
                    "defaultConfiguration": {"level" : nativeSeverityToLevel(getValue(vulnerability, "Severity").lower())}}
                rules.append(rule)
                ruleIds.append(rulesId)
            #Create a new result
            result = {}
            fullDescription = ""
            fullDescription += f'Description: {getValue(vulnerability, "Description")}\n\n'
            fullDescription += f'Remediation Advice: {getValue(vulnerability, "Remediation")}\n\n'
            fullDescription += f'{ ",".join(parseCWEs(getValue(vulnerability, "CWE-SANS")))}\n\n'
            if getValue(vulnerability, 'SourceType') == "CVE": fullDescription += getValue(vulnerability, 'SourceName') + "\n"
            result['message'] = {"text": f'{fullDescription if not fullDescription == "" else "N/A"}'}
            result['ruleId'] = rulesId
            #If CodeLocation has linenumber then it is used otherwise linenumber is 1
            lineNumber = 1
            artifactLocation = ""
            if getValue(vulnerability, 'CodeLocation'):
                locationAndLinenumber = getValue(vulnerability, 'CodeLocation').split(":")
                if len(locationAndLinenumber) > 1:
                    lineNumber = int(locationAndLinenumber[1])
                artifactLocation = locationAndLinenumber[0]
            elif getValue(vulnerability, 'LastDetectionURL'):
                artifactLocation = getValue(vulnerability, 'LastDetectionURL')

            result['locations'] = [{"physicalLocation":{"artifactLocation":{"uri": artifactLocation},"region":{"startLine":int(lineNumber)}}}]
            result['partialFingerprints'] = {"primaryLocationLineHash": getValue(vulnerability, "SeekerServerLink").split("/")[-1]}
            #Adding analysis steps to result if stacktrace is true
            if args.stacktrace:
                locations = []
                if getValue(vulnerability, 'StackTrace'):
                    for event in sorted(parseStacktrace(getValue(vulnerability, 'StackTrace')), key=lambda x: x['event-number']):
                        locations.append({"location":{"physicalLocation":{"artifactLocation":{"uri":event["path"]},
                            "region":{"startLine": int(event['linenumber']), "endLine": int(event['linenumber'])}}, 
                            "message" : {"text": f'Event step {event["event-number"]}: {event["message"]}'}}})
                    codeFlowsTable, loctionsFlowsTable = [], []
                    threadFlows, loctionsFlows = {}, {}
                    loctionsFlows['locations'] = locations
                    loctionsFlowsTable.append(loctionsFlows)
                    threadFlows['threadFlows'] = loctionsFlowsTable
                    codeFlowsTable.append(threadFlows)
                    result['codeFlows'] = codeFlowsTable
            results.append(result)
        return results, rules
    elif response.status_code == 400:
        logging.info("No vulnerabilities found!")
        return results, rules
    else:
        logging.error("Seeker response code: " + response.status_code)

def getTags(dict):
    tags = ["security"]
    verification_tag = getValue(dict, "VerificationTag")
    custon_tags = getValue(dict, "CustomTags")
    if verification_tag and not verification_tag == "Untagged":
        tags.append(verification_tag)
    if custon_tags:
        tags.extend(custon_tags.split(";"))
    return tags

def getValue(dict, key):
    return f'{dict[key] if key in dict and dict[key] else ""}'

def nativeSeverityToLevel(argument): 
    switcher = { 
        "informative": "note", 
        "high": "error", 
        "low": "note", 
        "medium": "warning",
        "critical": "error"
    }
    return switcher.get(argument, "warning")

def nativeSeverityToNumber(argument): 
    switcher = { 
        "informative": "3.8", 
        "high": "8.9", 
        "low": "3.8", 
        "medium": "6.8",
        "critical": "9.1"
    }
    return switcher.get(argument, "6.8")

def parseCWEs(vulnerabilityCodes):
    if vulnerabilityCodes:
        indicators = []
        for indicator in vulnerabilityCodes.split(';'):
            indicators.append(indicator.split(':')[0])
        return indicators

def parseStacktrace(stacktrace):
    if stacktrace:
        sub_events = []
        stacktraceLines = stacktrace.split('\n')
        eventNumber = 1
        for sourceCodeFile in stacktraceLines:
            if sourceCodeFile:
                sub_event = {}
                sub_event['event-number'] = eventNumber
                sub_event['message'] = sourceCodeFile[0:sourceCodeFile.index('(')]
                sourceWithLinenumber = sourceCodeFile[sourceCodeFile.index('(')+1:sourceCodeFile.index(')')].split(':')
                if sourceWithLinenumber:
                    sub_event['path'] = sourceWithLinenumber[0]
                    if len(sourceWithLinenumber) > 1:
                        sub_event['linenumber'] = sourceWithLinenumber[1]
                    else:
                        sub_event['linenumber'] = 1
                sub_events.append(sub_event)
                eventNumber += 1
        return sub_events

def get_parameter_string(parameters={}):
    parameter_string = "&".join(["{}={}".format(k,urllib.parse.quote(str(v))) for k,v in sorted(parameters.items(), key=itemgetter(0))])
    return "?" + parameter_string

def getSarifJsonHeader():
    return {"$schema":"https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json","version":"2.1.0"}

def getSarifJsonFooter(toolDriverName, rules):
    global args
    return {"driver":{"name":toolDriverName,"informationUri": f'{args.url if args.url else ""}',"version":__versionro__,"organization":"Synopsys","rules":rules}}

def writeToFile(findingsInSarif):
    f = open(args.outputFile, "w")
    f.write(json.dumps(findingsInSarif, indent=3))
    f.close()

def str2bool(v):
  return v.lower() in ("yes", "true", "t", "1")

def main():
    try:
        global args
        start = timer()
        #Initialize the parser
        parser = argparse.ArgumentParser(
            description="Seeker results to SARIF format."
        )
        #Parse commandline arguments
        parser.add_argument('--url', help="Baseurl for Seeker server", required=True)
        parser.add_argument('--token', help="Seeker Access token", required=True)
        parser.add_argument('--project', help="Seeker project name", required=True)
        parser.add_argument('--version', help="Seeker project version name", required=True)
        parser.add_argument('--outputFile', help="Filename with path where it will be created, example: /tmp/seekerFindings.sarif.json \
                                                if outputfile is not given, then json is printed stdout.", required=False)
        parser.add_argument('--log_level', help="Will print more info... default=INFO", default="INFO")
        parser.add_argument('--codeLocationTypeKeys', help="Options are: CUSTOMER_CODE_DIRECT_CALLS, CUSTOMER_CODE_NESTED_CALLS and THIRD_PARTY_CODE.", required=False)
        parser.add_argument('--minSeverity', help="Options are: INFORMATIVE, LOW, MEDIUM, HIGH, CRITICAL", required=False)
        parser.add_argument('--onlySeekerVerified', help="Options are: true or false", required=False, type=str2bool)
        parser.add_argument('--stacktrace', help="Options are: true or false", required=False, default=False, type=str2bool)
        parser.add_argument('--customTagNames', help="Comma separated list of tag names", required=False)

        args = parser.parse_args()
        #Initializing the logger
        logging.basicConfig(format='%(asctime)s:%(levelname)s:%(module)s: %(message)s', stream=sys.stderr, level=args.log_level)
        logging.getLogger("requests").setLevel(logging.WARNING)
        logging.getLogger("urllib3").setLevel(logging.WARNING)
        #Printing out the version number
        logging.info("Seeker results to SARIF formatter version: " + __versionro__)
        if logging.getLogger().isEnabledFor(logging.DEBUG): logging.debug(f'Given params are: {args}')
        findings, rules = getVulnerabilities()
        sarif_json = getSarifJsonHeader()
        results = {}
        results['results'] = findings
        results['tool'] = getSarifJsonFooter("Synopsys Seeker", rules)
        runs = []
        runs.append(results)
        sarif_json['runs'] = runs
        if args.outputFile:
            writeToFile(sarif_json)
        else:
            print(json.dumps(sarif_json, indent=3))
        end = timer()
        logging.info(f"Creating SARIF format took: {end - start} seconds.")
        logging.info("Done")
    except Exception as e:
        logging.exception(e)
        traceback.print_exc()
    
if __name__ == '__main__':
    sys.exit(main())
