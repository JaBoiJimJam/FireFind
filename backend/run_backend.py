import os
import sys
import subprocess
from datetime import datetime

def find_directory(start_path, dir_name):
    """Find a directory by searching in common locations"""
    # Check current directory and parent directories
    current = start_path
    for _ in range(3):  # Check up to 3 levels up
        test_path = os.path.join(current, dir_name)
        if os.path.exists(test_path):
            return test_path
        current = os.path.dirname(current)
    return None

def find_file(start_path, file_path):
    """Find a file by searching in common locations"""
    # Check current directory and parent directories
    current = start_path
    for _ in range(3):  # Check up to 3 levels up
        test_path = os.path.join(current, file_path)
        if os.path.exists(test_path):
            return test_path
        current = os.path.dirname(current)
    return None

def main():
    # Define paths relative to the current script's directory
    script_dir = os.path.dirname(os.path.abspath(__file__))
    backend_dir = script_dir
    src_dir = os.path.join(backend_dir, "src")
    project_root = os.path.dirname(script_dir)
    
    # Try to find all required directories and files
    samples_dir = find_directory(project_root, "samples")
    if not samples_dir:
        samples_dir = find_directory(backend_dir, "samples")
    
    out_dir = os.path.join(project_root, "out")
    
    # Search for rules files
    rules_file = find_file(project_root, os.path.join("rules", "rules.yaml"))
    if not rules_file:
        rules_file = find_file(backend_dir, os.path.join("rules", "rules.yaml"))
    
    mappings_file = find_file(project_root, os.path.join("rules", "vendor_mappings.yaml"))
    if not mappings_file:
        mappings_file = find_file(backend_dir, os.path.join("rules", "vendor_mappings.yaml"))

    # Ensure output directory exists
    os.makedirs(out_dir, exist_ok=True)

    # Check if required directories and files exist
    if not os.path.exists(src_dir):
        print(f"Error: The 'src' directory does not exist at {src_dir}.")
        return
    
    if not samples_dir or not os.path.exists(samples_dir):
        print(f"Error: Could not find 'samples' directory.")
        print(f"Searched from: {project_root}")
        print(f"Please ensure the samples directory exists.")
        return
    
    if not rules_file or not os.path.exists(rules_file):
        print(f"Error: Could not find 'rules/rules.yaml' file.")
        print(f"Searched from: {project_root}")
        print(f"Please ensure the rules file exists.")
        return
    
    if not mappings_file or not os.path.exists(mappings_file):
        print(f"Error: Could not find 'rules/vendor_mappings.yaml' file.")
        print(f"Searched from: {project_root}")
        print(f"Please ensure the vendor mappings file exists.")
        return

    # Generate timestamp for filenames (YYYY-MM-DD_HH-MM-SS format)
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    
    # Define output file paths with timestamp
    out_csv = os.path.join(out_dir, f"findings_all_{timestamp}.csv")
    out_pdf = os.path.join(out_dir, f"report_all_{timestamp}.pdf")

    print("Running FireFind backend...")
    print(f"Input directory: {samples_dir}")
    print(f"Rules file: {rules_file}")
    print(f"Mappings file: {mappings_file}")
    print(f"Output CSV: {out_csv}")
    print(f"Output PDF: {out_pdf}")

    # Sets up environment with Unicode support
    env = os.environ.copy()
    env["PYTHONPATH"] = src_dir
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONUTF8"] = "1"

    # Build the command
    cmd = [
        sys.executable, "-m", "firefind.cli",
        "--vendor", "fortinet",
        "--input", samples_dir,
        "--out-csv", out_csv,
        "--out-pdf", out_pdf,
        "--rules", rules_file,
        "--mappings", mappings_file
    ]

    try:
        # Run the command
        result = subprocess.run(
            cmd,
            cwd=backend_dir,
            env=env,
            capture_output=True,
            text=True,
            encoding='utf-8',
            errors='replace'
        )
        
        # Print output
        if result.stdout:
            print("Output:")
            print(result.stdout)
        
        if result.stderr:
            print("Errors:")
            print(result.stderr)
        
        if result.returncode == 0:
            print("\nFireFind backend completed successfully!")
        else:
            print(f"\nFireFind backend failed with return code: {result.returncode}")
            
    except Exception as e:
        print(f"Error running FireFind backend: {e}")

if __name__ == "__main__":
    main()