!pip install PyMuPDF
!pip install pytesseract
!pip install difflib
!pip install pandas
import os
import requests
from pathlib import Path
import fitz  # PyMuPDF
import re
from PIL import Image
import pytesseract
from difflib import get_close_matches
import pandas as pd

#Main script
valid_levels = ["High", "Medium", "Low", "Info"]

def extract_combined_findings(pdf_path, start_page=6, end_page=10, base_repo_url=None):
    doc = fitz.open(pdf_path)
    full_text = "\n".join(page.get_text() for page in doc)
# Remove headers/footers
    full_text = re.sub(r'Security Audit Report\s+[^\n]+', '', full_text, flags=re.IGNORECASE)
    full_text = re.sub(r'Audit Report\s+[^\n]+', '', full_text, flags=re.IGNORECASE)
    full_text = re.sub(r'Page\s+\d+\s+of\s+\d+', '', full_text, flags=re.IGNORECASE)
    match = re.search(r'5\. Findings(.*?)(?=6\. Appendix|$)', full_text, re.DOTALL)
    if not match:
        return []
    findings_text = match.group(1).strip()
    raw_findings = re.split(r'\n(?=5\.\d+\.)', findings_text)

# OCR
    ocr_levels, ocr_locations = [], []
    for page_num in range(start_page - 1, min(end_page, len(doc))):
        page = doc[page_num]
        pix = page.get_pixmap(dpi=200)
        img = Image.frombytes("RGB", [pix.width, pix.height], pix.samples)
        text = pytesseract.image_to_string(img)
# Risk Level extraction
        risk_matches = re.findall(r'Risk Level:\s*([A-Za-z]+)', text)
        for m in risk_matches:
            value = m.strip().capitalize()
            match_level = get_close_matches(value, valid_levels, n=1, cutoff=0.6)
            if match_level:
                ocr_levels.append(match_level[0])
# Location extraction
        loc_matches = re.findall(r'Location:\s*(Lines:.*?)?(Function:.*?)?(?:Description:|$)', text, re.DOTALL)
        for m in loc_matches:
            parts = " ".join(p.strip() for p in m if p)
            clean = re.sub(r'\s+', ' ', parts).strip()
            ocr_locations.append(clean if clean else "N/A")

    findings = []
    for i, raw in enumerate(raw_findings, start=1):
        entry = {
            "Number": f"Finding #{i}",
            "Title": "N/A",
            "Risk Level": "N/A",
            "Status": "N/A",
            "Contracts": "N/A",
            "Summary": "N/A",
            "Remediation": "N/A",
            "Location": "N/A",
            "Links": []
        }
        lines = raw.strip().splitlines()
        if not lines:
            continue
        first_line = lines[0].strip()
        if len(lines) > 1 and re.match(r'^5\.\d+\.$', first_line):
            entry["Title"] = f"{first_line} {lines[1].strip()}"
            block = "\n".join(lines[2:])
        else:
            entry["Title"] = first_line
            block = "\n".join(lines[1:])

        def extract_optional(label):
            if label.lower() == "location":
                match = re.search(r'Location:\s*(.*?)\n(?:Description|Remediation|$)', block, re.DOTALL | re.IGNORECASE)
            else:
                pattern = rf'{label}:\s*(.*?)(?=\n\S+?:|\n\n|\Z)'
                match = re.search(pattern, block, re.DOTALL | re.IGNORECASE)
            if not match:
                return "N/A"
            content = match.group(1).strip()
            content = re.sub(r'\s+', ' ', content)
            if label.lower() == "risk level":
                for lvl in valid_levels + ["Critical", "Informational"]:
                    if re.search(rf'\b{lvl}\b', content, re.IGNORECASE):
                        return lvl
                return "N/A"
            return content or "N/A"

        entry["Risk Level"] = extract_optional("Risk Level")
        if entry["Risk Level"] == "N/A" and i - 1 < len(ocr_levels):
            entry["Risk Level"] = ocr_levels[i - 1]
        entry["Status"] = extract_optional("Status")
        entry["Contracts"] = extract_optional("Contracts").replace("•", " ")
        desc = extract_optional("Description")
        summ = extract_optional("Summary")
        if desc != "N/A":
            entry["Summary_Label"] = "Description"
            entry["Summary"] = desc
        elif summ != "N/A":
            entry["Summary_Label"] = "Summary"
            entry["Summary"] = summ
        else:
            entry["Summary_Label"] = "Summary"
        entry["Remediation"] = extract_optional("Remediation")
        location_text = extract_optional("Location")
        ocr_fallback = ocr_locations[i - 1] if i - 1 < len(ocr_locations) else "N/A"
        is_placeholder = (
            location_text.strip() in ["N/A", "", "Lines: . Function: .", "Lines: .", "Function: ."]
            or re.fullmatch(r'(Lines:\s*\.\s*)?(Function:\s*\.\s*)?', location_text.strip())
        )
        entry["Location"] = ocr_fallback if is_placeholder and ocr_fallback != "N/A" else location_text
        findings.append(entry)
    doc.close()
    return findings

#Functions-multi-line header

valid_levels_multiline = ["High", "Medium", "Low", "Info", "Critical", "Informational"]

def extract_combined_findings_multiline_header(pdf_path):
    doc = fitz.open(pdf_path)
    full_text = "\n".join(page.get_text() for page in doc)
    doc.close()
# Remove headers/footers
    for hdr in [r'Security Audit Report\s+[^\n]+', r'Audit Report\s+[^\n]+', r'Page\s+\d+\s+of\s+\d+']:
        full_text = re.sub(hdr + r"\n?", '', full_text, flags=re.IGNORECASE)
# Normalize multiline headers
    full_text = re.sub(r'(?<=\n)(\d+)\s*\n(Findings?|Details?)', r'\1. \2', full_text, flags=re.IGNORECASE)
    findings_section = re.search(
        r'(?:\n)?(?P<header>(\d+\.\d+)?\s*(Findings?|Details?))\s*\n+(?P<body>.*?)(?=(?:\n\d+[\.\s]+(Appendix|About|Summary)|\Z))',
        full_text, flags=re.IGNORECASE | re.DOTALL
    )
    if findings_section:
        section_text = findings_section.group('body').strip()
    else:
        section_fallback = re.search(r'\n3\.\s+Findings\s*(.*?)\n4\.', full_text, re.DOTALL | re.IGNORECASE)
        if section_fallback:
            section_text = section_fallback.group(1).strip()
        else:
            print("❌ Could not locate a valid findings section.")
            return []
# Split by numbered entries
    raw_findings = re.split(r'(?=^\d+\.\d+(?:\.\d+)?\s+)', section_text, flags=re.MULTILINE)
    if len(raw_findings) <= 1:
        raw_findings = re.split(r'(?=^Title:\s*)', section_text, flags=re.MULTILINE)
    findings = []
    for raw in raw_findings:
        lines = raw.strip().splitlines()
        if not lines or len(lines[0]) < 3:
            continue
        entry = {"Number": f"Finding #{len(findings)+1}", "Title": "N/A", "Risk Level": "N/A", "Status": "N/A", "Contracts": "N/A", "Summary": "N/A", "Summary_Label": "Summary", "Remediation": "N/A", "Location": "N/A", "Links": []}
        first_line = lines[0].strip()
        second_line = lines[1].strip() if len(lines) > 1 else ""
        if re.match(r'^\d+\.\d+(?:\.\d+)?$', first_line) and second_line:
            entry["Title"] = f"{first_line} {second_line}"
            block = "\n".join(lines[2:])
        else:
            entry["Title"] = first_line
            block = "\n".join(lines[1:])
        def extract_optional_ml(label):
            if label.lower() == "location":
                m = re.search(r'Location:\s*(.*?)\n(?:Description:|Remediation:|$)', block, re.DOTALL | re.IGNORECASE)
                return m.group(1).strip() if m else "N/A"
            pattern = rf'{label}:\s*(.*?)(?=\n\S+?:|\n\n|\Z)'
            m = re.search(pattern, block, re.DOTALL | re.IGNORECASE)
            if not m:
                return "N/A"
            content = re.sub(r'\s+', ' ', m.group(1).strip())
            if label.lower() == "risk level":
                for lvl in valid_levels_multiline:
                    if re.search(rf'\b{lvl}\b', content, re.IGNORECASE):
                        return lvl
                return "N/A"
            return content or "N/A"
        entry["Risk Level"] = extract_optional_ml("Risk Level")
        entry["Status"] = extract_optional_ml("Status")
        entry["Contracts"] = extract_optional_ml("Contracts").replace("•", " ")
        desc = extract_optional_ml("Description")
        summ = extract_optional_ml("Summary")
        if desc != "N/A":
            entry["Summary_Label"] = "Description"
            entry["Summary"] = desc
        elif summ != "N/A":
            entry["Summary"] = summ
        entry["Remediation"] = extract_optional_ml("Remediation")
        entry["Location"] = extract_optional_ml("Location")
        findings.append(entry)
    return findings

#symbiosis-style script

def extract_symbiosis_style_findings(pdf_path: str):
    doc = fitz.open(pdf_path)
    full_text = "\n".join(page.get_text() for page in doc)
    doc.close()
    findings_text = re.search(r'3\.\s+Findings(.*?)4\.\s+Appendix', full_text, re.DOTALL | re.IGNORECASE)
    if not findings_text:
        return []
    findings_body = findings_text.group(1)
    split_entries = re.split(r'(?=\n3\.\d+\.?\s+)', findings_body)
    findings = []
    for entry in split_entries:
        entry = entry.strip()
        if not entry:
            continue
        number = f"Finding #{len(findings)+1}"
        title_match = re.match(r'3\.\d+\.?\s+(.*?)(\n|$)', entry)
        title = title_match.group(1).strip() if title_match else "N/A"
        def extract_label(label):
            match = re.search(rf'{label}:\s*(.*?)(?=\n\S+?:|\Z)', entry, re.IGNORECASE | re.DOTALL)
            return re.sub(r'\s+', ' ', match.group(1).strip()) if match else "N/A"
        findings.append({
            "Number": number,
            "Title": title,
            "Risk Level": extract_label("Risk Level"),
            "Status": extract_label("Status"),
            "Contracts": "N/A",
            "Summary_Label": "Description",
            "Summary": extract_label("Description"),
            "Remediation": extract_label("Remediation"),
            "Location": "N/A",
            "Links": []
        })
    return findings

#Link extraction/matching
def extract_links_from_pdf(pdf_path):
    doc = fitz.open(pdf_path)
    all_links = []
    for page_num, page in enumerate(doc):
        words = page.get_text("words")
        links = page.get_links()
        for link in links:
            if 'uri' in link:
                rect = fitz.Rect(link['from'])
                anchor_text = " ".join(
                    w[4] for w in words if fitz.Rect(w[:4]).intersects(rect)
                ).strip()
                all_links.append({
                    "page": page_num,
                    "url": link['uri'],
                    "anchor_text": anchor_text,
                })
    return all_links


def match_links_to_patch_entries(findings, pdf_links, base_repo_url=None):
    for f in findings:
        combined_text = f.get('Summary', '') + ' ' + f.get('Remediation', '') + ' ' + f.get('Status', '')
        hashes = re.findall(r'\b[a-f0-9]{7,40}\b', combined_text)
        raw_links = re.findall(r'https?://github\.com/[^\s\)]+', combined_text)
        matched_links = list(raw_links)
        for link in pdf_links:
            if 'github.com' in link['url'] and link['url'] not in matched_links:
                if link['anchor_text'] and link['anchor_text'] in combined_text:
                    matched_links.append(link['url'])
                elif any(h in link['anchor_text'] for h in hashes):
                    matched_links.append(link['url'])
                elif link['url'] in combined_text:
                    matched_links.append(link['url'])
        if base_repo_url:
            for h in hashes:
                full_url = f"{base_repo_url}/commit/{h}"
                if full_url not in matched_links:
                    matched_links.append(full_url)
        f['Links'] = list(dict.fromkeys(matched_links))
    return findings

#Processing
def write_findings_to_txt(findings, pdf_path, include_links=True):
    output_path = Path(pdf_path).with_suffix(".clean_final.txt")
    with open(output_path, 'w', encoding='utf-8') as f:
        for item in findings:
            f.write("=" * 80 + "\n")
            f.write(f"{item['Number']}\n")
            for key in ["Title", "Risk Level", "Status", "Contracts"]:
                f.write(f"{key}:\n{item[key]}\n")
            f.write(f"{item.get('Summary_LABEL','Summary')}:\n{item.get('Summary','N/A')}\n")
            for key in ["Remediation", "Location"]:
                f.write(f"{key}:\n{item.get(key,'N/A')}\n")
            if include_links:
                for link in item.get('Links', []):
                    f.write(f"Link: {link}\n")
    return str(output_path)


def process_all_pdfs(folder="public_audit", base_repo_url=None):
    for pdf_path in Path(folder).rglob("*.pdf"):
        print(f"Extracting: {pdf_path}")
        findings = extract_combined_findings(str(pdf_path))
        if not findings:
            print(f"No findings from extract_combined_findings, trying multiline header method for {pdf_path}")
            findings = extract_combined_findings_multiline_header(str(pdf_path))
        if not findings:
            print(f"No findings from multiline method, trying symbiosis style for {pdf_path}")
            findings = extract_symbiosis_style_findings(str(pdf_path))
        pdf_links = extract_links_from_pdf(str(pdf_path))
        findings = match_links_to_patch_entries(findings, pdf_links, base_repo_url)
        output_file = write_findings_to_txt(findings, pdf_path)
        print(f"✅ Findings and links written to: {output_file}")


if __name__ == "__main__":
    owner, repo, branch = "Decurity", "audits", "master"
    base_repo_url = f"https://github.com/{owner}/{repo}"
    print("Collecting all PDFs from GitHub repo...")
    api_url = f"https://api.github.com/repos/{owner}/{repo}/git/trees/{branch}?recursive=1"
    r = requests.get(api_url)
    r.raise_for_status()
    tree = r.json()["tree"]
    pdfs = []
    for file in tree:
        if file["path"].lower().endswith(".pdf"):
            raw_url = f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{file['path']}"
            local_path = os.path.join("public_audit", file["path"])
            pdfs.append((raw_url, local_path))

    print(f"Found {len(pdfs)} PDFs.")
    for url, local_path in pdfs:
        os.makedirs(os.path.dirname(local_path), exist_ok=True)
        if not os.path.exists(local_path):
            print(f"Downloading {url}")
            resp = requests.get(url)
            resp.raise_for_status()
            with open(local_path, "wb") as f:
                f.write(resp.content)
    print("Extracting findings and links from all PDFs...")
    process_all_pdfs("public_audit", base_repo_url)
    print(" All PDFs processed and .txt files saved next to each PDF.")
