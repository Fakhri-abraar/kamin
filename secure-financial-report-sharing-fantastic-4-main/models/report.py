from extensions import db
from datetime import datetime

class FinancialReport(db.Model):
    __tablename__ = 'financial_reports'
    
    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(db.Integer, db.ForeignKey('files.id'), nullable=False)
    report_date = db.Column(db.Date, nullable=True)
    
    # Encrypted fields (stored as TEXT)
    encrypted_revenue = db.Column(db.Text, nullable=True)
    encrypted_expenses = db.Column(db.Text, nullable=True)
    encrypted_profit = db.Column(db.Text, nullable=True)
    encrypted_assets = db.Column(db.Text, nullable=True)
    encrypted_liabilities = db.Column(db.Text, nullable=True)
    encrypted_equity = db.Column(db.Text, nullable=True)
    
    encryption_algorithm = db.Column(db.String(10), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    
    def __repr__(self):
        return f'<FinancialReport {self.id}>'