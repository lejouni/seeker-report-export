# seeker-report-export
This Action will export Seeker vulnerabilities in Sarif or Pdf -format.

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
