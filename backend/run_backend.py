import os
import sys
import yaml
from firefind.loaders.csv_xlsx_loader import load_table
from firefind.vendors.fortinet import map_row_fortinet
from firefind.model import Rule
from firefind.rules_engine import run_checks
from firefind.reporters.csv_report import write_findings_csv
from firefind.reporters.pdf_report import generate_pdf

def main():
    # Define paths relative to the current script's directory
    script_dir = os.path.dirname(os.path.abspath(__file__))
    samples_dir = os.path.join(script_dir, "samples")
    out_dir = os.path.join(script_dir, "out")
    rules_file = os.path.join(script_dir, "rules", "rules.yaml")
    mappings_file = os.path.join(script_dir, "rules", "vendor_mappings.yaml")

    # Ensure output directory exists
    os.makedirs(out_dir, exist_ok=True)

    # List available files in the samples directory
    try:
        sample_files = [f for f in os.listdir(samples_dir) if os.path.isfile(os.path.join(samples_dir, f))]
    except FileNotFoundError:
        print(f"Error: The 'samples' directory does not exist at {samples_dir}.")
        return

    if not sample_files:
        print("No files found in the 'samples' folder.")
        return

    print("Available files in the 'samples' folder:")
    for idx, file_name in enumerate(sample_files, start=1):
        print(f"{idx}. {file_name}")

    # Ask the user to select a file
    try:
        choice = int(input("Enter the number of the file you want to process: "))
        if choice < 1 or choice > len(sample_files):
            raise ValueError("Invalid choice.")
    except ValueError:
        print("Invalid input. Please enter a valid number.")
        return

    # Get the selected file
    input_file = os.path.join(samples_dir, sample_files[choice - 1])
    input_base_name = os.path.splitext(os.path.basename(input_file))[0]

    # Define output file paths
    out_csv = os.path.join(out_dir, f"{input_base_name}_report_findings.csv")
    out_pdf = os.path.join(out_dir, f"{input_base_name}_report_findings.pdf")

    # Load rules and mappings
    try:
        with open(rules_file, "r", encoding="utf-8") as f:
            rules_cfg = yaml.safe_load(f) or {}
        with open(mappings_file, "r", encoding="utf-8") as f:
            vendor_mappings = yaml.safe_load(f) or {}
    except FileNotFoundError as e:
        print(f"Error: {e}")
        return

    # Pick vendor mapping
    vendor = "fortinet"
    if vendor not in vendor_mappings:
        print(f"Vendor '{vendor}' not found in mappings file.")
        return
    mapping = vendor_mappings[vendor]

    # Load and normalize rows
    print(f"Loading rows from {input_file}...")
    raw_rows = load_table(input_file)
    rules = []
    for row in raw_rows:
        normalized_row = map_row_fortinet(row, mapping)
        rules.append(Rule(**normalized_row))
    print(f"Normalized {len(rules)} rules.")

    # Run checks
    print("Running checks...")
    findings = run_checks(rules=rules, cfg=rules_cfg, vendor=vendor)  # Pass 'vendor' explicitly
    print(f"Findings: {len(findings)} total.")

    # Write findings to CSV
    write_findings_csv(out_csv, findings)
    print(f"Wrote CSV: {out_csv}")

    # Generate PDF report
    generate_pdf(out_pdf, findings)
    print(f"Wrote PDF: {out_pdf}")

if __name__ == "__main__":
    # Add the `src` directory to the Python module search path
    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "src")))
    main()