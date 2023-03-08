# seeker-report-export
This Action will export Seeker vulnerabilities in Sarif or Pdf -format.

## Prerequisities
This Github Action expects that you have run the Seeker analysis and you have access to Seeker server.

## Available Options
| Option name | Description | Default value | Required | Available for Sarif | Available for pdf
|----------|----------|---------|----------|----------|----------|
| log_level | Logging level | DEBUG | false | X | X |
| url | Seeker server URL. | - | true | X | X |
| token | Seeker Access token to be used. | - | true | X | X |
| project | Seeker project, which vulnerability report will be exported. | - | true | X | X |
| version | Seeker project version, which vulnerability report will be exported. | - | false | X | X |
| codeLocationTypeKeys | Options are CUSTOMER_CODE_DIRECT_CALLS, CUSTOMER_CODE_NESTED_CALLS and THIRD_PARTY_CODE. All are returned by default. | All | false | X | X |
| minSeverity | Options are INFORMATIVE, LOW, MEDIUM, HIGH, CRITICAL. All are returned by default. | All | false | X | X |
| onlySeekerVerified | Options are true or false. Will return only Seeker Verfied vulnerabilites. | false | false | X | X |
| stacktrace | Options are true or false. If this is set to true, then possible stacktrace is added into the results.  (Works only for Sarif -format output) | false | false | X |  |
| customTagNames | Comma separated list of tag names. If custom tag names are given, then only those vulnerabilities are returned which have given tags.  (Works only for Sarif -format output) | - | false | X |  |
| outputfile | Filename with path where it will be created, example /tmp/SeekerResults.sarif.json. NOTE! Must be given for PDF -format | ${{github.workspace}}/SeekerResults.sarif.json | false | X | X |
| format | Select which format output will be. Options are sarif and pdf | sarif | false | X | X |
| statuses | Comma-separated list of vulnerability status keys to be included | Detected,Reviewed | false | X |  |

## Usage examples
Get Sarif -format report
```yaml
    - name: Get results from Seeker
      uses: lejouni/seeker-report-export@main
      with:
        url: ${{secrets.SEEKER_SERVER_URL}}
        token: ${{secrets.SEEKER_ACCESS_TOKEN}}
        project: ${{github.repository}}
        format: sarif
        stacktrace: true

    - name: Upload SARIF file
      uses: github/codeql-action/upload-sarif@v2
      with:
        # Path to SARIF file
        sarif_file: ${{github.workspace}}/SeekerResults.sarif.json
      continue-on-error: true

    - name: Archive scanning results
      uses: actions/upload-artifact@v3
      with:
        name: seeker-analysis-results
        path: ${{github.workspace}}/SeekerResults.sarif.json
      continue-on-error: true
```
## Usage examples
Get PDF -format report
```yaml
    - name: Get results from Seeker
      uses: lejouni/seeker-report-export@main
      with:
        url: ${{secrets.SEEKER_SERVER_URL}}
        token: ${{secrets.SEEKER_ACCESS_TOKEN}}
        project: ${{github.repository}}
        format: pdf
        outputfile: ${{github.workspace}}/SeekerResults.pdf #With format: pdf, this must be given.

    - name: Archive scanning results
      uses: actions/upload-artifact@v3
      with:
        name: seeker-analysis-results
        path: ${{github.workspace}}/SeekerResults.pdf
      continue-on-error: true
```
