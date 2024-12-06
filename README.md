# Log Analysis Script

## Overview
This repository contains a Python script (`main.py`) for analyzing web server log files. The script extracts valuable insights such as request counts per IP, the most accessed endpoint, and detection of suspicious activities. The results are saved to a CSV file for further analysis.

---

## Features
1. **File Selection:**
   - Allows users to select a `.log` file via a GUI file dialog.
   - Defaults to `sample.log` in the script directory if no file is selected.

2. **Analysis Capabilities:**
   - **Requests per IP Address**: Counts the number of requests made by each IP address.
   - **Most Accessed Endpoint**: Identifies the endpoint with the highest access frequency.
   - **Suspicious Activity Detection**: Flags IPs with more than a specified threshold of failed login attempts (default: 10).

3. **Output**:
   - Saves results to `log_analysis_results.csv` in the following structure:
     - **Requests per IP**: List of IP addresses and their request counts.
     - **Most Accessed Endpoint**: The most accessed endpoint and its count.
     - **Suspicious Activity**: IP addresses with failed login attempts exceeding the threshold.

---

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/karwap22/VRV-Intern.git
   cd VRV-Intern

2. Install dependencies:
   ```bash
   pip install pandas

## Dependencies
Python 3.7+

Libraries:

    - pandas
    
    - tkinter (pre-installed with Python)

## Usage
1. Run the script:
   ```bash
   python main.py

2. A file dialog will prompt you to select a **.log** file. If no file is selected, the script will use **sample.log**.
3. The script will:
      -Display the selected file path.
      -Perform the analysis and print results to the console.
      -Save results in log_analysis_results.csv.

## File Structure
 - **main.py**: Main script for log file analysis.
 - **sample.log**: Default log file for testing.
 - **log_analysis_results.csv**: Output file with analysis results (created after execution).
