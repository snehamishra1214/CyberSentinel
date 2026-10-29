# CyberSentinel: Cybersecurity Log Analysis Using Machine Learning

## About the Project

CyberSentinel is a Python project that uses machine learning to analyse cybersecurity logs and identify potentially suspicious login activities.

The main idea is to help understand how machine learning can be used in cybersecurity. The project analyses log data, identifies unusual patterns, groups related alerts into possible incidents, and generates a report with findings and recommendations.

It also includes a Flask API that allows log data to be submitted for analysis.

## Features

- **Log Data Generation:** Creates sample cybersecurity logs for testing.
- **Machine Learning:** Trains a Decision Tree model to classify login activity as normal or suspicious.
- **Threat Detection:** Flags login patterns that may need further investigation.
- **Alert Correlation:** Groups suspicious events from the same source IP when they occur close together.
- **Compliance Mapping:** Connects findings to possible ISO 27001 and NIST CSF references.
- **HTML Report:** Generates a report containing detected events, possible incidents, and recommendations.
- **Flask API:** Provides an endpoint for submitting log data and receiving analysis results.

## Technologies Used

- Python
- Pandas
- Scikit-learn
- Flask
- Joblib
- HTML and CSS

## Requirements

- Python 3.10 or newer
- VS Code or another Python editor
- Required Python libraries listed in `requirements.txt`

## How to Set Up the Project

First, open the project folder in VS Code and open a terminal.

Create a virtual environment:

```bash
python -m venv .venv
```

Activate it on Windows:

```powershell
.\.venv\Scripts\Activate.ps1
```

Install the required libraries:

```bash
pip install -r requirements.txt
```

If activation does not work, you can run Python directly using `.\.venv\Scripts\python.exe`.

## How to Run the Project

Run these commands one by one from the main project folder.

**1. Generate the sample dataset**

```bash
python src/generate_dataset.py
```

**2. Train the machine-learning model**

```bash
python src/train_model.py
```

**3. Analyse the logs and generate the report**

```bash
python src/run_pipeline.py
```

After the pipeline finishes, open `reports/security_report.html` in your browser to view the report.

## Running the API

Start the Flask API after training the model:

```bash
python src/app.py
```

The API runs locally and provides these endpoints:

- `GET /` – Shows basic project information.
- `GET /health` – Checks whether the API is running.
- `POST /analyse` – Accepts log records for analysis.

The `/analyse` endpoint expects a non-empty JSON array. Each record must include a timestamp, source IP, username, affected asset, event type, failed login count, login hour, and number of unique IPs.

## Dataset and Data Source

This project uses a generated CSV dataset containing sample cybersecurity events.

The dataset is useful for testing the workflow, but it does not contain verified real-world attack records. Its labels are created using a simple rule, so the model's evaluation results should not be treated as proof of real-world accuracy.

The CSV reader is the project's initial data source. Connecting to a live security platform would require an approved external data source and additional configuration.

## How the Project Works

1. Generate sample cybersecurity logs.
2. Prepare the data for machine learning.
3. Train and evaluate the Decision Tree model.
4. Analyse log records and flag suspicious patterns.
5. Group related alerts into possible incidents.
6. Create compliance reference mappings and recommendations.
7. Save the results as CSV files and an HTML report.
8. Make log analysis available through the Flask API.

## Limitations

CyberSentinel is a learning project and has some limitations:

- It uses synthetic data rather than verified real-world security logs.
- The model's results may not represent how well it would perform on real attacks.
- Alert correlation uses simple rules and may miss connections between events.
- Compliance mappings are suggestions and must be checked against the applicable standards.
- All suspicious activity should be reviewed by a person before taking action.

## Future Improvements

Some improvements that could be added in the future include:

- Testing the model with a real, properly labelled cybersecurity dataset.
- Connecting the project to a security monitoring platform.
- Improving alert correlation to identify more complex incidents.
- Adding more tests and better error handling.
- Adding authentication and request limits to the API.
- Improving the report with more detailed evidence and visualisations.

## Conclusion

CyberSentinel is a beginner-friendly project that brings together Python, machine learning, and cybersecurity log analysis. It helped demonstrate how log data can be processed, suspicious activity can be identified, and findings can be presented in a report for further investigation.