# Financial Report Excel Template

This is a sample Excel template structure for testing the encrypted file upload.

## Template Structure (for manual creation):

Create an Excel file with the following structure:

```
Cell A1: "Revenue"
Cell B2: 1000000  (example revenue value)

Cell A3: "Expenses"
Cell B3: 750000   (example expenses value)

Cell A4: "Net Profit"
Cell B4: 250000   (example profit value)
```

## Or use this Python script to create it:

```python
import openpyxl

# Create a new workbook
wb = openpyxl.Workbook()
sheet = wb.active
sheet.title = "Financial Report"

# Add headers and values
sheet['A1'] = "Item"
sheet['B1'] = "Amount"
sheet['A2'] = "Revenue"
sheet['B2'] = 1000000
sheet['A3'] = "Expenses"
sheet['B3'] = 750000
sheet['A4'] = "Net Profit"
sheet['B4'] = 250000

# Save the file
wb.save('financial_report_template.xlsx')
print("Template created: financial_report_template.xlsx")
```

Run this script to create a test file:
```bash
venv\Scripts\python create_template.py
```

Then upload the generated `financial_report_template.xlsx` through the web interface!
