from fpdf import FPDF
import os
from typing import List
from datetime import datetime
from ..model import Finding

class PDFReport(FPDF):
    def __init__(self):
        super().__init__()
        self.set_auto_page_break(auto=True, margin=15)
        self.set_margins(15, 15, 15)  # More generous margins
        
    def header(self):
        # Logo placeholder (if logo file exists)
        logo_path = os.path.join(os.path.dirname(__file__), "assets", "logo.png")
        if os.path.exists(logo_path):
            self.image(logo_path, 10, 8, 33)
        
        # Title
        self.set_font('Arial', 'B', 16)
        self.cell(0, 10, 'FireFind - Firewall Risk Assessment Report', 0, 1, 'C')
        self.ln(10)
        
    def footer(self):
        self.set_y(-15)
        self.set_font('Arial', 'I', 8)
        self.cell(0, 10, f'Page {self.page_no()}', 0, 0, 'C')
        
    def safe_text(self, text, max_chars=60):
        """Ensure text fits within reasonable bounds and uses safe characters"""
        if isinstance(text, (int, float)):
            return str(text)
        elif text is None:
            return "N/A"
        
        text = str(text)
        # Replace problematic Unicode characters with ASCII equivalents
        text = text.replace('•', '-')  # Replace bullet with dash
        text = text.replace("'", "'")  # Replace smart quotes
        text = text.replace('"', '"')
        text = text.replace('"', '"')
        text = text.replace('–', '-')  # Replace en-dash
        text = text.replace('—', '-')  # Replace em-dash
        
        # Truncate if too long
        if len(text) > max_chars:
            return text[:max_chars-3] + "..."
            
        return text
        
    def add_title_page(self, client_name="Organization", report_date=None):
        self.add_page()
        
        if report_date is None:
            # Include both date and time
            report_date = datetime.now().strftime("%B %d, %Y at %I:%M %p")
            
        # Main title
        self.set_font('Arial', 'B', 24)
        self.ln(40)
        self.cell(0, 15, 'Firewall Risk Assessment', 0, 1, 'C')
        self.cell(0, 15, 'Security Analysis Report', 0, 1, 'C')
        
        self.ln(20)
        
        # Client and date info
        self.set_font('Arial', '', 14)
        self.cell(0, 10, f'Client: {client_name}', 0, 1, 'C')
        self.cell(0, 10, f'Report Date: {report_date}', 0, 1, 'C')
        
    def get_severity_color(self, severity):
        """Return RGB color based on severity level"""
        colors = {
            'Critical': (220, 50, 50),    # Red
            'High': (255, 165, 0),        # Orange  
            'Medium': (255, 215, 0),      # Yellow
            'Low': (144, 238, 144),       # Light Green
            'Info': (173, 216, 230)       # Light Blue
        }
        return colors.get(severity, (200, 200, 200))  # Default gray
        
    def add_risk_summary(self, findings: List[Finding]):
        self.add_page()
        self.set_font('Arial', 'B', 16)
        self.cell(0, 10, 'Risk Summary Dashboard', 0, 1, 'L')
        self.ln(5)
        
        # Count findings by severity
        severity_counts = {}
        for finding in findings:
            severity = finding.severity
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
        # Risk level boxes - stack vertically for better fit
        y_start = self.get_y()
        box_width = 40
        box_height = 20
        
        severities = ['Critical', 'High', 'Medium', 'Low', 'Info']
        
        for i, severity in enumerate(severities):
            count = severity_counts.get(severity, 0)
            color = self.get_severity_color(severity)
            
            y_pos = y_start + (i * 25)
            
            # Draw colored box
            self.set_fill_color(*color)
            self.rect(20, y_pos, box_width, box_height, 'F')
            
            # Add border
            self.rect(20, y_pos, box_width, box_height, 'D')
            
            # Add count and label
            self.set_xy(20, y_pos + 2)
            self.set_font('Arial', 'B', 10)
            self.cell(box_width, 8, str(count), 0, 0, 'C')
            
            self.set_xy(20, y_pos + 10)
            self.set_font('Arial', '', 8)
            self.cell(box_width, 6, severity, 0, 0, 'C')
            
            # Add description next to box
            self.set_xy(65, y_pos + 6)
            self.set_font('Arial', '', 10)
            self.cell(0, 8, f'{severity} Risk Issues: {count}', 0, 1, 'L')
            
        self.ln(140)  # Move past the boxes
        
        # Key metrics
        self.set_font('Arial', 'B', 12)
        self.cell(0, 8, 'Key Metrics:', 0, 1, 'L')
        self.set_font('Arial', '', 10)
        
        total_findings = len(findings)
        critical_high = severity_counts.get('Critical', 0) + severity_counts.get('High', 0)
        
        # Calculate total rules analyzed from findings
        total_rules = len(set([f.rule_id for f in findings if hasattr(f, 'rule_id') and f.rule_id]))
        if total_rules == 0:
            total_rules = len(findings)  # Fallback if no rule_id available
        
        metrics = [
            f"Total Rules Analyzed: {total_rules}",
            f"Total Findings: {total_findings}",
            f"Critical/High Risk: {critical_high}",
            f"Risk Coverage: {(total_findings/max(1, total_rules))*100:.1f}%"
        ]
        
        for metric in metrics:
            self.cell(0, 6, f"* {metric}", 0, 1, 'L')
        
    def generate_risk_id(self, finding: Finding, index: int):
        """Generate a unique risk ID for tracking"""
        severity_prefix = {
            'Critical': 'CR',
            'High': 'HI', 
            'Medium': 'ME',
            'Low': 'LO',
            'Info': 'IN'
        }
        
        finding_type = getattr(finding, 'finding_type', 'unknown')
        severity = getattr(finding, 'severity', 'Info')
        
        # Create a short code from finding type
        type_codes = {
            'broad_source_range': 'BSR',
            'broad_destination_range': 'BDR',
            'any_destination': 'ANY',
            'admin_port_exposure': 'APE',
            'permissive_rule': 'PER',
            'default': 'GEN'
        }
        
        type_code = type_codes.get(finding_type, type_codes['default'])
        sev_code = severity_prefix.get(severity, 'IN')
        
        return f"FR-{sev_code}{type_code}-{index:03d}"
        
    def get_user_friendly_description(self, finding: Finding):
        """Convert technical finding type to user-friendly description"""
        descriptions = {
            'broad_source_range': 'Overly Broad Source Network Range',
            'broad_destination_range': 'Overly Broad Destination Network Range', 
            'any_destination': 'Rule Allows Traffic to Any Destination',
            'admin_port_exposed': 'Administrative Port Exposed',
            'permissive_rule': 'Overly Permissive Rule Configuration',
        }
        
        finding_type = getattr(finding, 'finding_type', 'unknown')
        return descriptions.get(finding_type, f'Security Finding: {finding_type}')
        
    def format_technical_details(self, finding: Finding):
        """Format technical details for the PDF"""
        details = []
        
        # Rule information
        rule_id = getattr(finding, 'rule_id', 'N/A')
        details.append(f"Rule ID: {rule_id}")
        
        # Network details
        src = self.safe_text(getattr(finding, 'src', 'N/A'), 40)
        dst = self.safe_text(getattr(finding, 'dst', 'N/A'), 40)
        details.append(f"Source: {src}")
        details.append(f"Destination: {dst}")
        
        # Service details - removed protocol line
        port = getattr(finding, 'port', 'N/A')
        details.append(f"Port/Service: {port}")
        
        # Action
        action = getattr(finding, 'action', 'N/A')
        details.append(f"Action: {action}")
        
        return details
        
    def add_detailed_findings(self, findings: List[Finding]):
        if not findings:
            return
            
        self.add_page()
        self.set_font('Arial', 'B', 16)
        self.cell(0, 10, 'Detailed Security Findings', 0, 1, 'L')
        self.ln(5)
        
        for i, finding in enumerate(findings, 1):
            # Generate risk ID
            risk_id = self.generate_risk_id(finding, i)
            
            # Severity color
            severity = getattr(finding, 'severity', 'Info')
            color = self.get_severity_color(severity)
            
            # Risk ID and Severity header
            self.set_fill_color(*color)
            self.set_font('Arial', 'B', 12)
            self.cell(0, 8, f'{risk_id} - {severity} Risk', 1, 1, 'L', True)
            
            # Reset background
            self.set_fill_color(255, 255, 255)
            
            # User-friendly title
            self.set_font('Arial', 'B', 11)
            title = self.get_user_friendly_description(finding)
            self.cell(0, 6, title, 0, 1, 'L')
            
            # Technical details - using safe bullet alternative
            self.set_font('Arial', '', 9)
            technical_details = self.format_technical_details(finding)
            for detail in technical_details:
                safe_detail = self.safe_text(detail)
                self.cell(0, 5, f'  - {safe_detail}', 0, 1, 'L')  # Changed from • to -
            
            # Rationale if available
            rationale = getattr(finding, 'rationale', None)
            if rationale:
                self.set_font('Arial', 'I', 9)
                rationale_text = self.safe_text(rationale, 80)
                self.cell(0, 5, f'Analysis: {rationale_text}', 0, 1, 'L')
            
            self.ln(3)
            
            # Check if we need a new page
            if self.get_y() > 250:
                self.add_page()
                
    def get_summary_description(self, finding: Finding):
        """Get a brief summary for the recommendations section"""
        rule_id = getattr(finding, 'rule_id', 'N/A')
        finding_type = getattr(finding, 'finding_type', 'unknown')
        
        if finding_type == 'admin_port_exposed':
            port = getattr(finding, 'port', 'N/A')
            return f"Rule {rule_id}: Restrict administrative access on port {port}"
        elif finding_type == 'any_destination':
            return f"Rule {rule_id}: Narrow destination scope from 'any'"
        elif 'broad' in finding_type:
            return f"Rule {rule_id}: Reduce overly broad network ranges"
        else:
            return f"Rule {rule_id}: Review and tighten rule configuration"
            
    def add_recommendations_summary(self, findings: List[Finding]):
        if not findings:
            return
            
        self.add_page()
        self.set_font('Arial', 'B', 16)
        self.cell(0, 10, 'Prioritized Recommendations', 0, 1, 'L')
        self.ln(5)
        
        # Group by severity
        severity_groups = {}
        for finding in findings:
            severity = getattr(finding, 'severity', 'Info')
            if severity not in severity_groups:
                severity_groups[severity] = []
            severity_groups[severity].append(finding)
        
        # Display recommendations by priority
        priority_order = ['Critical', 'High', 'Medium', 'Low', 'Info']
        
        for severity in priority_order:
            if severity in severity_groups and severity_groups[severity]:
                color = self.get_severity_color(severity)
                
                # Section header
                self.set_fill_color(*color)
                self.set_font('Arial', 'B', 12)
                
                if severity in ['Critical', 'High']:
                    section_title = f'{severity} Priority - Immediate Action Required'
                elif severity == 'Medium':
                    section_title = f'{severity} Priority - Plan for Remediation'
                else:
                    section_title = f'{severity} Priority - Long-term Improvement'
                    
                self.cell(0, 8, section_title, 1, 1, 'L', True)
                self.set_fill_color(255, 255, 255)  # Reset
                
                # List recommendations - using safe bullet alternative
                self.set_font('Arial', '', 10)
                for finding in severity_groups[severity]:
                    summary = self.get_summary_description(finding)
                    safe_summary = self.safe_text(summary)
                    self.cell(0, 6, f'  - {safe_summary}', 0, 1, 'L')  # Changed from • to -
                
                self.ln(3)

def generate_pdf(output_path: str, findings: List[Finding], client_name="Triskele Labs"):
    """Generate a comprehensive PDF report"""
    pdf = PDFReport()
    
    # Title page with updated client name
    pdf.add_title_page(client_name)
    
    # Risk summary dashboard
    pdf.add_risk_summary(findings)
    
    # Detailed findings
    pdf.add_detailed_findings(findings)
    
    # Recommendations summary
    pdf.add_recommendations_summary(findings)
    
    # Save the PDF
    pdf.output(output_path)
    print(f"PDF report generated: {output_path}")
