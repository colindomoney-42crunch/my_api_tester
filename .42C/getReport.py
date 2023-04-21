import base64
import json
import requests
import sys
import time
import yaml
import os
from decouple import config
from tabulate import tabulate
from datetime import datetime

# Set vars
if len(sys.argv) > 1: # Used for github actions env
    x42confPath = '42c-conf.yaml'
    apikey = sys.argv[2]
    oasFile = 'Pixi/pixi.json'
    reportPath = 'Audit/report.rtf'
else: # Local
    x42confPath = '../42c-conf.yaml'
    apikey = config('42C_API_TOKEN')
    oasFile = '../Pixi/pixi.json'
    reportPath = 'report.rtf'

# Open 42c-conf.yaml
with open(x42confPath, 'r') as file:
    confYaml = yaml.safe_load(file)

# Get API uuid from 42c-conf.yaml
uuid = confYaml['audit']['branches']['main']['mapping']['Pixi/pixi.json']

# Set authentication header
headers = {'X-API-KEY': apikey}

# Prepare spec for upload
with open(oasFile,'r') as jsonFile:
    data = json.load(jsonFile)
    datastr = json.dumps(data)
    encodedSpec = base64.b64encode(datastr.encode('utf-8'))

body = {
    'name': data['info']['title'],
    'technicalName': data['info']['description'],
    'specfile': str(encodedSpec,'utf-8'),
    'yaml': False
    }

# Upload API
url = 'https://demolabs.42crunch.cloud/api/v1/apis/'+uuid
r = requests.put(url, data=json.dumps(body), headers=headers)

# Run audit
url = 'https://demolabs.42crunch.cloud/api/v1/apis/'+uuid+'/assess'
r = requests.get(url, headers=headers)
jsonResponse = r.json()

# Get taskId
taskId = jsonResponse['id']
time.sleep(2)

# Get audit report
url = 'https://demolabs.42crunch.cloud/api/v1/apis/'+uuid+'/assessmentreport'
r = requests.get(url, headers=headers)
jsonResponse = r.json()

# Decode response
decodedBytes = base64.b64decode(jsonResponse['data'])
decodedStr = decodedBytes.decode('ascii')

# Get audit scores
auditScore = json.loads(decodedStr)['score']
securityScore = json.loads(decodedStr)['security']['score']
dataScore = json.loads(decodedStr)['data']['score']

# Get SQG approval report using taskId
url = 'https://demolabs.42crunch.cloud/api/v2/sqgs/reportComplianceStatus?reportType=audit&taskId='+taskId
r = requests.get(url, headers=headers)
jsonResponse = r.json()
print(jsonResponse)

# Add 42c logo
fileString = '<img src=https://42crunch.com/wp-content/uploads/2022/02/LogoCr1.png width="200" height="57"/>'

# Parse response
if jsonResponse['acceptance'] == 'no':
    sqgPassed = False
    fileString += '\n\n# Security Quality Gate(s) - FAILED :red_circle:'
else:
    sqgPassed = True
    fileString += '\n\n# Security Quality Gate(s) - PASSED :green_circle:'

fileString += '\nTimestamp: '+str(datetime.fromtimestamp(int(jsonResponse['date'])))

fileString += '\n\n[<kbd> <br> Report <br><br> </kbd>][Link]'

fileString += '\n\n[Link]: https://demolabs.42crunch.cloud/apis/'+jsonResponse['api']+'/security-audit-report'

# Build summary report table
for sqgReport in jsonResponse['processingDetails']:
    # Get SQG by ID
    url = 'https://demolabs.42crunch.cloud/api/v2/sqgs/audit/'+sqgReport['blockingSqgId']
    r = requests.get(url, headers=headers)
    sqgIdJson = r.json()

    fileString += '\n\n## SQG - '+sqgIdJson['name']

    fileString += '\n\n### Minimum acceptable score:'

    severityMap = {
        "info": "All issues are rejected",
        "low": "Issues up to level Info allowed",
        "medium": "Issues up to level Low allowed",
        "high": "Issues up to level Medium allowed",
        "critical": "Only critical issues are rejected",
        "none": "No restrictions"
    }

    # Assign SQG data
    sqgAuditScore = sqgIdJson['directives']['minimumAssessmentScores']['global']
    sqgSecurityScore = sqgIdJson['directives']['minimumAssessmentScores']['security']
    sqgDataScore = sqgIdJson['directives']['minimumAssessmentScores']['dataValidation']
    authenticationRule = sqgIdJson['directives']['subcategoryRules']['security']['authentication']
    authorizationRule = sqgIdJson['directives']['subcategoryRules']['security']['authorization']
    transportRule = sqgIdJson['directives']['subcategoryRules']['security']['transport']
    parametersRule = sqgIdJson['directives']['subcategoryRules']['dataValidation']['parameters']
    responseHeadersRule = sqgIdJson['directives']['subcategoryRules']['dataValidation']['responseHeaders']
    responseDefinitionRule = sqgIdJson['directives']['subcategoryRules']['dataValidation']['responseDefinition']
    schemaRule = sqgIdJson['directives']['subcategoryRules']['dataValidation']['schema']
    pathsRule = sqgIdJson['directives']['subcategoryRules']['dataValidation']['paths']
    #issueRules =  sqgIdJson['directives']['issueRules']

    # Build audit score table
    scoreTable = []
    head = ['Score','Current','Minimum Acceptable']

    scoreRow = ['Global score', round(float(auditScore)), sqgAuditScore]
    scoreTable.append(scoreRow)
    scoreRow = ['Security score', round(float(securityScore)), sqgSecurityScore]
    scoreTable.append(scoreRow)
    scoreRow = ['Data validation score', round(float(dataScore)), sqgDataScore]
    scoreTable.append(scoreRow)

    fileString += '\n'+tabulate(scoreTable, headers=head, tablefmt='github')
    fileString += '\n'

    severityTable = []
    head = ['Category','Threshold','Issues Found']

    issuesList = ''
    for count, sqgRule in enumerate(sqgReport['blockingRules']):
        blockingRule = sqgRule.split('/')
        if len(blockingRule) > 1:
            categorySeverity = blockingRule[1].split(':')
            if len(categorySeverity) > 1:
                category = categorySeverity[0]
                severity = categorySeverity[1].capitalize()+' and above'
                if category == 'authentication':
                    severityRow = ['Authentication',severityMap[authenticationRule],severity]
                    severityTable.append(severityRow)
                elif category == 'authorization':
                    severityRow = ['Authorization',severityMap[authorizationRule],severity]
                    severityTable.append(severityRow)
                elif category == 'transport':
                    severityRow = ['Transport',severityMap[transportRule],severity]
                    severityTable.append(severityRow)
                elif category == 'parameters':
                    severityRow = ['Parameters',severityMap[parametersRule],severity]
                    severityTable.append(severityRow)
                elif category == 'response_headers':
                    severityRow = ['Response Headers',severityMap[responseHeadersRule],severity]
                    severityTable.append(severityRow)
                elif category == 'response_definition':
                    severityRow = ['Response Definition',severityMap[responseDefinitionRule],severity]
                    severityTable.append(severityRow)
                elif category == 'schema':
                    severityRow = ['Schema',severityMap[schemaRule],severity]
                    severityTable.append(severityRow)
                elif category == 'paths':
                    severityRow = ['Paths',severityMap[pathsRule],severity]
                    severityTable.append(severityRow)
                else:
                    severityRow = []
        else:
            # Print forbidden issues
            issuesList += '\n'+sqgRule

    if len(severityTable) > 0:
        fileString += '\n### Allowed issue severity levels:'
        fileString += '\n'+tabulate(severityTable, headers=head, tablefmt='github')
    
    if issuesList != '':
        fileString += '\n\n### Forbidden issues with problem found:'
        fileString += issuesList

    fileString += '\n'

# Write to file
f = open(reportPath,'w')
f.write(fileString)
