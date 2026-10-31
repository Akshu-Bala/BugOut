# BugOut
An AI agent that detects, investigates and fixes software bugs
# BugOut — confidence-score prototype

## Run on Windows (PowerShell)

From this folder:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m streamlit run app.py
```

Open the local URL printed by Streamlit (usually http://localhost:8501).

## Demo

1. Upload `demo_vulnerable.py` to see a supported patch proposal and its confidence evidence breakdown.
2. Upload `demo_needs_review.py` to see an unsupported query-construction pattern routed to human review.

## Important limitations

- Uploaded code is analyzed as text and is never executed.
- Only one exact demo pattern receives a patch proposal.
- The score is an evidence score, not a probability or proof of security.
- Runtime, regression, and exploit tests are not run. Therefore, the current version always requires human review; it does not automatically apply patches to the uploaded original file.
- This is a student proof of concept, not a production security scanner.

