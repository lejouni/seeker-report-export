# -*- coding: utf-8 -*-
import json
import logging
import argparse
import sys
import os
import fnmatch
from timeit import default_timer as timer
import requests
from operator import itemgetter
import urllib.parse
import traceback
import hashlib

__author__ = "Jouni Lehto"
__versionro__="0.1.0"

filepaths={}
triedToFind=[]
exclude_folders=["target,bin"]

#Global variables
args = None 

def getHeader():
    global args
    return {
            'Authorization': args.token, 
            'Accept': 'text/plain',
            'Content-Type': '*/*'
        }

def find_file(fileToSearch):
    if not filepaths.get(fileToSearch) and fileToSearch not in triedToFind:
        triedToFind.append(fileToSearch)
        for dirpath, dirnames, filenames in os.walk(os.getcwd()):
             # Check if dirpath contains any of the excluded folders
            if exclude_folders and any(ext in dirpath for ext in exclude_folders):
                logging.debug("SKIPPING: " + dirpath)
                continue
            for basename in filenames:
                if fnmatch.fnmatch(basename, fileToSearch):
                    filename = os.path.join(dirpath, basename)
                    if filename:
                        filepaths[fileToSearch]=filename[len(os.getcwd())+1::].replace("\\","/")
                        return filepaths[fileToSearch]
    elif filepaths.get(fileToSearch):
        return filepaths[fileToSearch]

def getVulnerabilities():
    global args
    parameters = {'format': 'JSON', 'language': 'en', 'projectKeys': args.project, 'includeStacktrace': True,
                    'includeHttpHeaders': True, 'includeHttpParams': True, 'includeDescription': True, 
                    'includeRemediation': True, 'includeSummary': True, 'includeVerificationProof': True,
                    'includeTriageEvents': True, 'includeComments': True}
    if args.codeLocationTypeKeys: parameters['codeLocationTypeKeys'] = args.codeLocationTypeKeys.upper()
    if args.minSeverity: parameters['minSeverity'] = args.minSeverity.upper()
    if args.onlySeekerVerified: parameters['onlySeekerVerified'] = args.onlySeekerVerified
    if args.customTagNames: parameters['codeLocationTypeKeys'] = args.customTagNames
    if args.version: parameters['projectVersions'] = args.version
    if args.statuses: parameters['statuses'] = args.statuses    
    
    endpoint = "/rest/api/latest/vulnerabilities" + get_parameter_string(parameters)
    response = requests.get(args.url+endpoint, headers=getHeader())
    rules, results, ruleIds = [], [], []
    if response.status_code == 200:
        for vulnerability in response.json():
            rule, result = {}, {}
            rulesId = getValue(vulnerability, 'ItemKey')
            ## Adding vulnerabilities as a rule
            description = getValue(vulnerability, "Description")[:1000]
            if not rulesId in ruleIds:
                descriptionMarkdown = getHelpMarkdown(vulnerability)
                rule = {"id":rulesId, "name": getValue(vulnerability, "VulnerabilityName"), "shortDescription":{"text":f'{getValue(vulnerability, "VulnerabilityName")[:1000]}'}, 
                    "fullDescription":{"text": description, "markdown": description},
                    "help":{"text":description, "markdown":descriptionMarkdown},
                    "properties": {"security-severity": nativeSeverityToNumber(getValue(vulnerability, "Severity").lower()), "tags": getTags(vulnerability)},
                    "defaultConfiguration": {"level" : nativeSeverityToLevel(getValue(vulnerability, "Severity").lower())}}
                rules.append(rule)
                ruleIds.append(rulesId)
            #Create a new result
            result = {}
            result['message'] = {"text": f'{description if not description == "" else "N/A"}'}
            result['ruleId'] = rulesId
            #If CodeLocation has linenumber then it is used otherwise linenumber is 1
            lineNumber = 1
            artifactLocation = ""
            codeLocation = getValue(vulnerability, 'CodeLocation')
            if codeLocation:
                locationAndLinenumber = codeLocation.split(":")
                if len(locationAndLinenumber) > 1:
                    lineNumber = int(locationAndLinenumber[1])
                if not getValue(vulnerability, "SourceType") == "CVE":
                    artifactLocation = locationAndLinenumber[0].split("(")[0].replace(".", "/")
                    filepath=find_file(f'*{artifactLocation.split("/")[-2]}*')
                    if filepath:
                        artifactLocation = filepath
                else:
                    artifactLocation = locationAndLinenumber[0]
            if not artifactLocation:
                artifactLocation = getValue(vulnerability, 'LastDetectionURL')
                if artifactLocation:
                    filepath=find_file(f'{artifactLocation.split("/")[-1]}')
                    if filepath:
                        artifactLocation = filepath
            if not artifactLocation:
                lastDetectionCodeLocation = getValue(vulnerability, 'LastDetectionCodeLocation')
                if lastDetectionCodeLocation:
                    artifactLocation = lastDetectionCodeLocation.split("(")[0].replace(".", "/")
                    filepath=find_file(f'*{artifactLocation.split("/")[-2]}*')
                    if filepath:
                        artifactLocation = filepath
            if not artifactLocation:
                artifactLocation = getValue(vulnerability, "CheckerKey")
            if artifactLocation.startswith('/'):
                artifactLocation = artifactLocation[1::]
            result['locations'] = [{"physicalLocation":{"artifactLocation":{"uri": artifactLocation.replace(" ", "_")},"region":{"startLine":int(lineNumber)}}, "message": {"text": getValue(vulnerability, 'SeekerServerLink')}}]
            result['partialFingerprints'] = {"primaryLocationLineHash": hashlib.sha256((f'{getValue(vulnerability, "SeekerServerLink").split("/")[-1]}').encode(encoding='UTF-8')).hexdigest()}
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
    elif response.status_code == 404:
        logging.info("Project keys or version names not found.")
        return results, rules
    else:
        logging.error("Seeker response code: " + response.status_code)


def getHelpMarkdown(vulnerability):
    messageText = ""
    #Description
    messageText += f'## Description'
    messageText += f'\n{getValue(vulnerability, "Description")}'
    #Common info
    messageText += f'\n\n## {getValue(vulnerability, "ItemKey")} - {getValue(vulnerability,"VulnerabilityName")}'
    messageText += f'\n|       |         |'
    messageText += f'\n| :---- |  :----  |'
    messageText += f'\n| Status: | {getValue(vulnerability, "Status")} |'
    verified = getValue(vulnerability, "VerificationTag")
    if not verified == "Untagged":
        messageText += f'\n| Verification: | {verified} |'
    messageText += f'\n| Severity: | {getValue(vulnerability, "Severity")} |'
    messageText += f'\n| Detections: | {getValue(vulnerability, "DetectionCount")} |'
    messageText += f'\n| First seen: | {getValue(vulnerability, "FirstDetectionTime")} |'
    messageText += f'\n| Last seen: | {getValue(vulnerability, "LastDetectionTime")} |'
    messageText += f'\n| Project: | {getValue(vulnerability, "ProjectKey")} |'
    url = getValue(vulnerability, "URL")
    if url:
        messageText += f'\n| URL: | {url} |'

    codelocation = getValue(vulnerability, "CodeLocation")
    if codelocation:
        messageText += f'\n| Code location: | {codelocation} |'
    lastDetectionSourceType = getValue(vulnerability, "LastDetectionSourceType")
    if lastDetectionSourceType:
        lastDetectionSourceName = getValue(vulnerability, "LastDetectionSourceName")
        if lastDetectionSourceName:
            messageText += f'\n| {lastDetectionSourceType}: | {lastDetectionSourceName} |'
    messageText += f'\n| See in Seeker: | [{getValue(vulnerability, "SeekerServerLink")}]({getValue(vulnerability, "SeekerServerLink")}) |'
    #Classification
    messageText += f'\n\n## Classification'
    messageText += f'\n|       |         |'
    messageText += f'\n| :---- |  :----  |'
    OWASP2021 = getValue(vulnerability, "OWASP2021")
    if OWASP2021:
        messageText += f'\n| OWASP Top 10 2021: | {OWASP2021} |'
    OWASP2017 = getValue(vulnerability, "OWASP2017")
    if OWASP2017:
        messageText += f'\n| OWASP Top 10 2017: | {OWASP2017} |'
    OWASP2013 = getValue(vulnerability, "OWASP2013")
    if OWASP2013:
        messageText += f'\n| OWASP Top 10 2013: | {OWASP2013} |'
    PCIDSS = getValue(vulnerability, "PCI-DSS")
    if PCIDSS:
        messageText += f'\n| PCI-DSS v3.2.1: | {PCIDSS} |'
    CWE = getValue(vulnerability, "CWE-SANS")
    if CWE:
        messageText += f'\n| CWE: | {CWE} |'
    GDPR = getValue(vulnerability, "GDPR")
    if GDPR:
        messageText += f'\n| GDPR: | {GDPR} |'
    CAPEC = getValue(vulnerability, "CAPEC")
    if CAPEC:
        messageText += f'\n| CAPEC: | {CAPEC} |'
    #Summary
    messageText += f'\n\n## Summary'
    messageText += f'\n{getValue(vulnerability, "Summary")}'
    #Verification proof
    verficationProof = getValue(vulnerability, "VerificationProof")
    if verficationProof:
        messageText += f'\n\n## Verification proof'
        messageText += f'\n{verficationProof}'
    #HTTP context
    lastDetectionHttpHeaders = getValue(vulnerability, "LastDetectionHttpHeaders")
    if lastDetectionHttpHeaders:
        messageText += f'\n\n## HTTP context'
        messageText += f'\n**HTTP headers**'
        messageText += f"\n```html"
        for httpHeader in lastDetectionHttpHeaders:
            messageText += f"\n{httpHeader}"
        messageText += f"\n```"
        lastDetectionHttpParams = getValue(vulnerability, "LastDetectionHttpParams")
        if lastDetectionHttpParams:
            messageText += f'\n**HTTP parameters**'
            messageText += f"\n```html"
            for httpParam in lastDetectionHttpParams:
                messageText += f"\n{httpParam}"
            messageText += f"\n```"
    #Remediation
    messageText += f'\n\n## Remediation'
    remediation = getValue(vulnerability, "Remediation")
    if remediation:
        messageText += f'\n{remediation}'
    else:
        messageText += "\nNo remediation"
    #Triage history
    messageText += f'\n\n## Triage history'
    triageEvents = getValue(vulnerability, "TriageEvents")
    if triageEvents:
        messageText += f'\n*Triage events are ordered from newest to oldest*\n'
        for event in triageEvents:
            messageText += f'\n{event}'
    else:
        messageText += f'\nNo triage events yet'
    #Comments
    messageText += f'\n\n## Comments'
    comments = getValue(vulnerability, "Comments")
    if comments:
        messageText += f'\n*Comments are ordered from newest to oldest*\n'
        for comment in comments:
            messageText += f'\n{comment}'
    else:
        messageText += f'\nNo comments yet'
    return messageText


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
    if dict:
        if key in dict:
            return dict[key]
    return ""

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
                    sub_event['path'] = sourceWithLinenumber[0].replace(" ", "_")
                    filepath=find_file(f'{sub_event["path"].split(".")[0]}')
                    if filepath:
                        sub_event['path'] = filepath
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
        parser.add_argument('--version', help="Seeker project version name", required=False)
        parser.add_argument('--outputFile', help="Filename with path where it will be created, example: /tmp/seekerFindings.sarif.json \
                                                if outputfile is not given, then json is printed stdout.", required=False)
        parser.add_argument('--log_level', help="Will print more info... default=INFO", default="INFO")
        parser.add_argument('--codeLocationTypeKeys', help="Comma-separated list of code location type keys to be included in the report. Code location keys include CUSTOMER_CODE_DIRECT_CALLS, CUSTOMER_CODE_NESTED_CALLS and THIRD_PARTY_CODE.", required=False)
        parser.add_argument('--minSeverity', help="Options are: INFORMATIVE, LOW, MEDIUM, HIGH, CRITICAL", required=False)
        parser.add_argument('--onlySeekerVerified', help="Options are: true or false", required=False, default=False, type=str2bool)
        parser.add_argument('--stacktrace', help="Options are: true or false", required=False, default=False, type=str2bool)
        parser.add_argument('--customTagNames', help="Comma separated list of tag names", required=False)
        parser.add_argument('--statuses', help='Comma-separated list of vulnerability status keys to be included', default='Detected,Reviewed', required=False)

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
