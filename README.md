# NVD-project
## Background

The National Vulnerability Database (NVD) is administered by NIST. It reports lots of detailed information on software vulnerabilities, assigning each a unique identifier, while documenting the types of harms possible and which software is affected. You can learn about the program here: <https://nvd.nist.gov/>

In this project, you will write a Python program to access the NVD through its API, which is documented here: <https://nvd.nist.gov/developers/vulnerabilities>

Please sign up for an API key: <https://nvd.nist.gov/developers/request-an-api-key>. This ensures you can query the system more frequently (useful while you're debugging).

## Tasks

You have two primary tasks.

### Task 1 - Getting CVEs via API

You will first create the `request_cve_list(year, month)` function. In this function, you will write an API query that will request all vulnerabilities identified in the specified year and month and return the results in the JSON format (often the default for API requests).

*Note, it may be worth caching your JSON results by saving them to a file after initially downloding them (and then reading the file). This way you do not need to redownload the JSON results every single time you debug the next function.*

You will then create the function defined as: `def write_CVEs_to_csv(year, month)`

The original API results come back in JSON format, which contains more information than we need. You will need to extract relevant fields and write the results to a CSV file named `cve-year-month.csv`, where year and month are the arguments supplied to the function. Below are the fields you need to include (use cvssMetricV31 measures):

```
cveid
month
year
publication date
modification date
exploitabilityScore
impactScore
vectorString
attackVector
attackComplexity
privilegesRequired
userInteraction
scope
confidentialityImpact
integrityImpact
availabilityImpact
baseScore
baseSeverity
description
```

The file format, including headers and example entries for 10 CVEs, is in the attached `examples/cve-2022-02-sample.csv`. Please follow that formatting exactly (headers and fields).

### Task 2 - Plotting results

Make plots of the gathered data in the `plot_CVEs(year,month,topnum=40)` function.

You should make two plots:
- The first is a bar chart plot of the top 40 CVEs in terms of highest severity rating identified for the month specified in the method. You should use the CSV generated in Task 1 to make the plot. Plot them in descending order by severity, and include a description of the vulnerability in the text that appears when you hover over the bar.
- The second plot is a scatter plot for each CVE identified that month comparing the overall severity score (CVSS v3) to the exploitability score.

Included below are screenshots of what each plot should look like:

![](examples/cve-barplot.png)

![](examples/cve-scatter.png)

Do not modify the code included in the if `__name__=="__main__"` block (otherwise your results will not match the provided screenshots). You can test your functions individually by importing them into `nvd_cve_testing.py` and running them there

