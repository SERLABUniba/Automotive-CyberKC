# import requests
from bs4 import BeautifulSoup
import pandas as pd
from urllib.request import Request, urlopen
import re
import sys

dataframe_nvd_automotive = pd.read_csv(
    "/home/devincentiis/AutomotiveCyberKC/Automotive-CyberKC-lippolis_DEF_improved/cve-nvd-automotive.csv",
    sep=";",
    names=["CVE", "Description", "CVSS", "References", "Label"],
)

tmp_dict = {
    "CVE": [],
    "CVEDescription": [],
    "CVSSv2": [],
    "CVSSv3": [],
    "CWEID": [],
    "CWEDescription": [],
    "CWESite": [],
    "References": [],
    "Label": [],
}

for id, row in dataframe_nvd_automotive.iterrows():
    matching_cve = row.CVE
    if matching_cve != "CVE-2023-21632":
        continue
    print(row.CVE)
    # print(row.References)
    nvd_query_with_cve = f"https://www.cvedetails.com/cve/{matching_cve}/"

    r = (
        urlopen(Request(url=nvd_query_with_cve, headers={"User-Agent": "Mozilla/5"}))
        .read()
        .decode("utf-8")
    )
    cwe_id_re = r">(CWE-\d+ (.*?))</a>"
    cwe_id_match = re.search(cwe_id_re, r)

    if cwe_id_match is None:
        link_cve = f"https://nvd.nist.gov/vuln/detail/{matching_cve}"
        request_nvd = BeautifulSoup(
            urlopen(Request(link_cve, headers={"User-Agent": "Mozilla/5.0"})).read(),
            "html.parser",
        )

        cwe_id = request_nvd.find(
            "td", {"data-testid": "vuln-CWEs-link-0"}
        ).text.strip()

        if "NVD-CWE-noinfo" in cwe_id:
            cwe_id_found = "N/A"
            cwe_description_found = "N/A"
            make_url_cwe_details = "N/A"
        else:
            cwe_description = request_nvd.find_all(
                "td", {"data-testid": "vuln-CWEs-link-0"}
            )[1].text.strip()

            cwe_id_found = f"{cwe_id} {cwe_description}"

            make_url_cwe_details = (
                f"https://cwe.mitre.org/data/definitions/{cwe_id.split('-')[1]}"
            )

            request_cwe_details = BeautifulSoup(
                urlopen(
                    Request(
                        make_url_cwe_details,
                        headers={"User-Agent": "Mozilla/5.0"},
                    )
                ).read(),
                "html.parser",
            )
            cwe_description_found = request_cwe_details.find(
                "div", {"id": f"oc_{cwe_id.split('-')[1]}_Description"}
            ).text.strip()

        # cwe_id_found = "N/A"
        # cwe_description_found = "N/A"
        # make_url_cwe_details = "N/A"
    else:
        cwe_id_found = cwe_id_match.group(1)

        cwe_site_details = (
            re.split(r"CWE-(.*?) ", cwe_id_found)[2].replace(" ", "-") + ".html"
        )

        id = cwe_id_found.split("CWE-")[1].split(" ")[0]

        make_url_cwe_details = (
            f"https://www.cvedetails.com/cwe-details/{id}/{cwe_site_details}"
        )

        req_cwe_details = BeautifulSoup(urlopen(Request(make_url_cwe_details, headers={"User-Agent": "Mozilla/5.0"})).read(), "html.parser")
        cwe_description_found = req_cwe_details.find("div", {"class": "my-2"}).text.strip().replace("\n", "").replace("       ", "")
        # cwe_description_re = r"<div class=\"ms-1\">\n\t(.*?)</div>"
        # cwe_description_found = re.search(cwe_description_re, r).group(1).strip("\n\t")

    nvd_link = f"https://nvd.nist.gov/vuln/detail/{matching_cve}"
    r = BeautifulSoup(
        urlopen(Request(nvd_link, headers={"User-Agent": "Mozilla/5.0"})).read(),
        "html.parser",
    )

    anchor_tag_v3 = r.find("a", {"id": "Cvss3NistCalculatorAnchor"})

    if anchor_tag_v3:
        score_text = anchor_tag_v3.text.strip()
        # Extract the score from the text content
        score = score_text.split()[0]
        cvss_score_v3 = score
    else:
        anchor_tag_v3_na = r.find("a", {"id": "Cvss3NistCalculatorAnchorNA"})
        score_text = anchor_tag_v3_na.text.strip()
        score = score_text.split()[0]
        cvss_score_v3 = score

    # anchor_tag_v2_na = r.find("a", {"id": "Cvss2CalculatorAnchorNA"})

    anchor_tag_v2 = r.find("a", {"id": "Cvss2CalculatorAnchor"})

    if anchor_tag_v2:
        score_text = anchor_tag_v2.text.strip()
        # Extract the score from the text content
        score = score_text.split()[0]
        cvss_score_v2 = score
    else:
        anchor_tag_v2_na = r.find("a", {"id": "Cvss2CalculatorAnchorNA"})
        score_text = anchor_tag_v2_na.text.strip()
        score = score_text.split()[0]
        cvss_score_v2 = score
    
    CVSSScoreV2 = cvss_score_v2,
    CVSSScoreV3 = cvss_score_v3,
    CWE_ID = cwe_id_found,
    CWEDetailsSite = make_url_cwe_details,
    CWEDescription = cwe_description_found,

    tmp_dict["CVE"].append(matching_cve)
    tmp_dict["CVEDescription"].append(row.Description)
    tmp_dict["CVSSv2"].append(CVSSScoreV2[0])
    tmp_dict["CVSSv3"].append(CVSSScoreV3[0])
    tmp_dict["CWEID"].append(CWE_ID[0])
    tmp_dict["CWEDescription"].append(CWEDescription[0])
    tmp_dict["CWESite"].append(CWEDetailsSite[0])
    tmp_dict["References"].append(row.References)
    tmp_dict["Label"].append(row.Label)

    df_new = pd.DataFrame(tmp_dict)
    df_new.to_csv("cve_new.csv", sep=";", index=False)
