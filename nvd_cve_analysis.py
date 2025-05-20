'''
This program will download CVEs from the NVD and plot them
'''

# Must install requests: pip install requests
import requests

# Must install plotly: pip install plotly
from plotly.graph_objs import Bar, Scatter
from plotly import offline
# You may alternatively use matplotlib instead of plotly if desired

import urllib.parse
import os.path, hashlib
# For storing the results
import csv


def request_cve_list(year, month):
    API_KEY = "for public github commit reasons will not be sharing my own, so?? add ur own here" 
    start_date = f"{year}-{month:02d}-01T00:00Z" #Set the start date of the request
    if month == 12:
        end_date = f"{year+1}-01-01T00:00Z" #Set the end date for December to the next year's January
    else:
        end_date = f"{year}-{month+1:02d}-01T00:00Z" #end dates for the rest of the months


    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    headers = { 
        "apiKey": API_KEY
    }

    params = {
        "pubStartDate": start_date,
        "pubEndDate": end_date,
        "startIndex": 0,
        "resultsPerPage": 2000
    }
    response = requests.get(url, headers=headers,params=params) #makes a request to the API
    return response.json()


def write_CVEs_to_csv(year, month):
    ''' Task 1: write a CSV with key info in it '''
    filename = f"cve-{year}-{month:02d}.csv" #defining the filename based on given year + month
    if not os.path.isfile(filename):
        cve_json = request_cve_list(year, month) #Get the CVE list from the NVD API
        file = open(filename,"w",newline='', encoding="utf-8")
        writer = csv.writer(file)
        headers = [
                "cveid", "month", "year", "publication date", "modification date",
                "exploitabilityScore", "impactScore", "vectorString", "attackVector",
                "attackComplexity", "privilegesRequired", "userInteraction", "scope",
                "confidentialityImpact", "integrityImpact", "availabilityImpact",
                "baseScore", "baseSeverity", "description"
            ]
        writer.writerow(headers) #make the header row for the CSV file

        for item in cve_json.get("vulnerabilities",[]): #Loop through the CVE data and write it to the CSV file
            cve = item["cve"]
            cve_id = cve["id"]
            pub_date = cve["published"][:16] + "Z"
            mod_date = cve["lastModified"][:16] + "Z"
            description = cve.get("descriptions", [{}])[0].get("value", "") #get them but also if they don't exist just return like an empty field
            metrics = cve.get("metrics", {})
            base_metric = metrics.get("cvssMetricV31", [{}])[0]
            cvss_data = base_metric.get("cvssData", {})
            writer.writerow([
                    cve_id,
                    month,
                    year,
                    pub_date,
                    mod_date,
                    base_metric.get("exploitabilityScore", ""),
                    base_metric.get("impactScore", ""),
                    cvss_data.get("vectorString", ""),
                    cvss_data.get("attackVector", ""),
                    cvss_data.get("attackComplexity", ""),
                    cvss_data.get("privilegesRequired", ""),
                    cvss_data.get("userInteraction", ""),
                    cvss_data.get("scope", ""),
                    cvss_data.get("confidentialityImpact", ""),
                    cvss_data.get("integrityImpact", ""),
                    cvss_data.get("availabilityImpact", ""),
                    cvss_data.get("baseScore", ""),
                    cvss_data.get("baseSeverity", ""),
                    description
                ])

        # Parse the JSON and write to CSV
    else:
        print(f"The following file already exists: {filename}")


def plot_CVEs(year,month,topnum=40):
    filename = f"cve-{year}-{month:02d}.csv" #grabbing only the baseScores and exploitability score and appending it to the row list
    rows = []
    file = open(filename, encoding="utf-8")
    reader = csv.DictReader(file)
    lilfilething = open("list.txt","w",encoding="utf-8") #I'm trying to figure out my graph issue so now i'm just creating another file containing the stuff from row to have a visual looksies
    for row in reader:
        try:
            row["baseScore"] = float(row["baseScore"])
            row["exploitabilityScore"] = float(row["exploitabilityScore"])
            rows.append(row)
            lilfilething.write(f"{row['cveid']}: baseScore={row['baseScore']}, exploitabilityScore={row['exploitabilityScore']}\n")
        except:
            continue  # Skip rows with missing scores
    unsortedfilething = open("list.txt","r",encoding="utf-8")
    lines = unsortedfilething.readlines()
    lines.sort(key=lambda line: float(line.split("baseScore=")[1].split(",")[0]), reverse=True)
    sortedfilething = open("sortedlist.txt","w", encoding="utf-8")
    sortedfilething.writelines(lines) #creating another file with the base score sorted 

    top_cves = sorted(rows, key=lambda x: x["baseScore"], reverse=True)[:topnum] #sorting and then getting the top 40 
    top40file = open("top_40_cves.csv", "w", encoding="utf-8") #my charts look absolutely nothing like the example, getting the top 40 into a different file so I can take a looksies 
    writer = csv.DictWriter(top40file, fieldnames=top_cves[0].keys())
    writer.writeheader()
    writer.writerows(top_cves)

    bar = Bar(
        x=[c["cveid"] for c in top_cves], #grabbing the id for the top40 after we sorted them 
        y=[c["baseScore"] for c in top_cves], #same thing as above but with the severity score instead
        hovertext=[c["description"] for c in top_cves], #lil hover thing for the description,,,, I wonder if we can do something to make the lil boxes smaller tho,,, they take a lot of screen space and I can't read the whole thing most of the time
        marker=dict(color="blue")
    )
    offline.plot({
        "data": [bar],
        "layout": {
            "title": f"Highest-severity CVEs for {year}-{month:02d}", #adding title as well as descriptors for x and y axis
            "xaxis": {"title": "CVE ID"},
            "yaxis": {"title": "Severity Score"}
        }},
        filename="cve_barplot.html"
    )

    # Scatter Plot
    scatter = Scatter( #same thing as the bar but for scatter instead 
        x=[c["baseScore"] for c in rows],
        y=[c["exploitabilityScore"] for c in rows],
        text=[c["description"] for c in rows],
        mode="markers",
        marker=dict(size=8, color="blue")
    )
    offline.plot({
        "data": [scatter],
        "layout": {
            "title": f"CVE severity vs. exploitability for {year}-{month:02d}",
            "xaxis": {"title": "Severity Score"},
            "yaxis": {"title": "Exploitability Score"}
        }},
        filename="cve_scatter.html"
    )

if __name__ =="__main__":
    # Do not modify
    year = 2022
    month = 2

    write_CVEs_to_csv(year, month)
    plot_CVEs(year, month)
    h = hashlib.new('sha1')
    h.update(open("cve-2022-02.csv").read().encode("utf-8"))
    print(h.hexdigest())
