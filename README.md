# Cybersecurity Threat Detection System

## 1. Project Overview

The Cybersecurity Threat Detection System is a web-based application designed to analyze security logs and identify potentially suspicious activities.

The system uses rule-based detection to identify repeated failed login attempts and denied access events. It calculates risk scores, assigns severity levels, and displays detected alerts through a web dashboard.

The project is developed using Python and Flask, with SQLite for storing alert information.

## 2. Objectives

* Analyze security logs to identify suspicious activities.
* Detect repeated failed login attempts.
* Identify repeated denied access events.
* Calculate risk scores for suspicious activity.
* Classify alerts according to severity.
* Display security metrics and alerts through a web dashboard.
* Allow users to manage alert statuses.

## 3. Technologies Used

* **Programming Language:** Python
* **Backend Framework:** Flask
* **Frontend:** HTML, CSS, JavaScript
* **Database:** SQLite
* **Data Processing:** Pandas
* **Visualization:** Chart.js
* **Version Control:** Git and GitHub

## 4. Current Features

* Security log analysis using CSV files.
* Rule-based suspicious activity detection.
* Risk scoring and severity classification.
* Dashboard displaying security metrics.
* Alert storage using SQLite.
* Alert status management.
* CSV upload functionality, subject to testing in the current version.

## 5. Project Structure

```text
Cybersecurity-Threat-Detection/
│
├── app.py
├── detector.py
├── requirements.txt
├── README.md
├── .gitignore
├── alerts.csv
├── security_logs.csv
│
├── templates/
│   └── index.html
│
└── static/
    └── style.css
```

The project may contain additional local test files that are not shown in this simplified structure.

## 6. Prerequisites

Install the following before running the application:

* Python 3.13 or a compatible Python version.
* Git.
* A web browser.

## 7. Installation and Setup

### Step 1: Clone the Repository

Open a terminal and run:

```bash
git clone https://github.com/poojithajetti16/Cybersecurity-Threat-Detection-System.git
```

### Step 2: Open the Project Folder

```bash
cd Cybersecurity-Threat-Detection-System
```

### Step 3: Create a Virtual Environment

```bash
python -m venv venv
```

### Step 4: Activate the Virtual Environment

**Windows PowerShell:**

```powershell
.\venv\Scripts\Activate.ps1
```

**Windows Command Prompt:**

```cmd
venv\Scripts\activate.bat
```

### Step 5: Install Dependencies

```bash
python -m pip install -r requirements.txt
```

## 8. Running the Application

From the main project directory, with the virtual environment activated, run:

```bash
python app.py
```

Open the following address in your web browser:

http://127.0.0.1:5000

The dashboard runs locally on the computer where the application is started.

To stop the server, press `Ctrl + C` in the terminal.

## 9. Security Log Format

The security log CSV file is expected to contain the following columns:

| Column     | Description                          |
| ---------- | ------------------------------------ |
| timestamp  | Date and time of the event           |
| username   | User associated with the event       |
| ip_address | IP address associated with the event |
| event_type | Type of security event               |
| status     | Result of the event                  |
| resource   | Resource being accessed              |

Use the sample CSV files included with the project to test the application, after confirming that they contain only fictional or anonymized data.

## 10. Detection Approach

The current implementation uses predefined rules to assign risk scores to suspicious activity.

Examples include:

* Repeated failed login attempts.
* Multiple denied access events.
* Risk scores used to determine alert severity.

The detection results depend on the rules and thresholds implemented in the current version of `detector.py`.

This version should be treated as an educational prototype rather than a complete enterprise-grade security monitoring platform.

## 11. Testing

After starting the application:

1. Confirm that the dashboard opens.
2. Check whether security metrics and existing alerts appear.
3. Test the available alert status controls.
4. If CSV upload is available, upload a correctly formatted sample CSV.
5. Check whether the application handles invalid CSV files appropriately.

Report any errors encountered during testing.

## 12. Current Project Status

The current version includes the Flask application, rule-based detection, risk scoring, dashboard, and SQLite alert storage.

Additional enhancements, including further testing, machine-learning or external API integration, email notifications, authentication, and deployment, are planned for future development.

## 13. Future Enhancements

* Machine-learning-based anomaly detection.
* External IP reputation API integration.
* Email notifications for important alerts.
* Authentication and access control.
* Improved validation and error handling.
* Additional dashboard filtering and reporting.
* Deployment to a suitable hosting platform.

## 14. Disclaimer

This project is developed for educational purposes and cybersecurity learning.

Detection results are based on implemented rules and should not be considered a guarantee that an activity is malicious or safe.
