# FireFind Backend

This is the backend portion of the FireFind project, which processes firewall rules, analyzes them for risks, and generates reports in CSV and PDF format.

## Features
- Processes firewall rules from CSV or Excel files.
- Normalizes and analyzes rules for potential risks.
- Generates findings in both CSV and PDF formats.
- Allows users to select which file to process from the `samples` directory.

---

## Prerequisites
1. **Python**: Ensure Python 3.8 or later is installed.
   - Verify installation:
     ```bash
     python --version
     ```
2. **Dependencies**: Install required Python packages.
   - Navigate to the `backend` directory and run:
     ```bash
     pip install -r requirements.txt
     ```

---

## How to Use

### 1. **Prepare Input Files**
   - Place your firewall rule files (CSV or Excel format) in the `samples` directory located in the `backend` folder.

### 2. **Run the Program**
   - Use the `run_backend.py` script to process the files.
   - Navigate to the `backend` directory and run:
     ```bash
     python run_backend.py
     ```

### 3. **Select a File**
   - The program will list all files in the `samples` directory.
   - Example:
     ```
     Available files in the 'samples' folder:
     1. CLIENT1 Firewall Rules - Anonymised - Firewall Policy-EXTERNAL-FW-DC.xlsx
     2. CLIENT1 Firewall Rules - Anonymised - Firewall Policy-INSIDE-DaaS.xlsx
     3. fortinet_sample.csv
     Enter the number of the file you want to process:
     ```
   - Enter the number corresponding to the file you want to process.

### 4. **Output**
   - The program will generate two output files in the `out` directory:
     - A CSV file containing the findings.
     - A PDF report summarizing the findings.
   - The output files will have `_report_findings` appended to their names. For example:
     - Input file: `fortinet_sample.csv`
     - Output CSV: `fortinet_sample_report_findings.csv`
     - Output PDF: `fortinet_sample_report_findings.pdf`

---

## Example Workflow
1. Place the file `fortinet_sample.csv` in the `samples` directory.
2. Run the program:
   ```bash
   python run_backend.py
   ```
