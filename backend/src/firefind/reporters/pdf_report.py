from fpdf import FPDF
import os
import logging
from typing import List
from datetime import datetime
from ..model import Finding


_SEVERITY_CANONICAL = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "cautionary": "Cautionary",
    "low": "Low",
    "info": "Info",
    "informational": "Info",
}

_SEVERITY_RANK = {
    "Critical": 5,
    "High": 4,
    "Medium": 3,
    "Cautionary": 2,
    "Low": 1,
    "Info": 0,
}


logger = logging.getLogger(__name__)

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
        """Ensure text fits within reasonable bounds and uses safe characters."""
        if isinstance(text, (int, float)):
            return str(text)
        if text is None:
            return "N/A"

        text = str(text)

        translation_table = str.maketrans({
            "•": "-",  # bullet
            "·": "-",  # alternate bullet / middle dot
            "“": '"',
            "”": '"',
            "‘": "'",
            "’": "'",
            "—": "-",  # em dash
            "–": "-",  # en dash
            "…": "...",  # ellipsis
        })

        text = text.translate(translation_table)

        if len(text) > max_chars:
            text = text[: max_chars - 3] + "..."

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
            'Cautionary': (255, 239, 153),  # Light Amber
            'Low': (144, 238, 144),       # Light Green
            'Info': (173, 216, 230)       # Light Blue
        }
        return colors.get(severity, (200, 200, 200))  # Default gray
        
    def add_risk_bar_chart(
        self,
        severity_counts: dict,
        origin_x: float,
        origin_y: float,
        chart_width: float = 80,
        chart_height: float = 70,
    ) -> float:
        """Draw a simple bar chart summarising risk distribution."""

        severities = ['Critical', 'High', 'Medium', 'Cautionary', 'Low', 'Info']
        max_count = max([severity_counts.get(severity, 0) for severity in severities] + [0])
        if max_count == 0:
            max_count = 1  # Avoid divide-by-zero when there are no findings

        # Chart title
        self.set_font('Arial', 'B', 11)
        self.set_text_color(0, 0, 0)
        self.text(
            origin_x + chart_width / 2 - self.get_string_width('Risk Distribution') / 2,
            origin_y - chart_height - 4,
            'Risk Distribution',
        )

        # Draw axes
        self.set_draw_color(0, 0, 0)
        self.line(origin_x, origin_y, origin_x + chart_width, origin_y)  # X-axis
        self.line(origin_x, origin_y, origin_x, origin_y - chart_height)  # Y-axis

        # Axis labels
        self.set_font('Arial', '', 9)
        self.set_text_color(0, 0, 0)
        self.text(origin_x + chart_width / 2 - self.get_string_width('Risk Level') / 2, origin_y + 8, 'Risk Level')

        # Keep the Y-axis label within the page margins even if the chart is centered
        label_width = 30
        label_margin = 5
        label_x = max(self.l_margin, origin_x - label_width - label_margin)
        self.set_xy(label_x, origin_y - chart_height / 2 - 8)
        self.multi_cell(label_width, 4, 'Number of Rules\nFlagged', 0, 'C')

        bar_spacing = chart_width / len(severities)
        bar_width = bar_spacing * 0.6

        for index, severity in enumerate(severities):
            count = severity_counts.get(severity, 0)
            bar_height = (count / max_count) * chart_height
            bar_x = origin_x + (index * bar_spacing) + (bar_spacing - bar_width) / 2
            bar_y = origin_y - bar_height

            color = self.get_severity_color(severity)
            self.set_fill_color(*color)
            self.rect(bar_x, bar_y, bar_width, bar_height, 'F')
            self.rect(bar_x, bar_y, bar_width, bar_height, 'D')

            # Count label above the bar
            self.set_font('Arial', '', 8)
            self.set_text_color(0, 0, 0)
            self.text(bar_x + bar_width / 2 - self.get_string_width(str(count)) / 2, bar_y - 2, str(count))

            # Severity label on X-axis
            label_width = self.get_string_width(severity)
            self.text(bar_x + bar_width / 2 - label_width / 2, origin_y + 5, severity)

        # Reset drawing color to default black
        self.set_draw_color(0, 0, 0)

        # Return bottom Y position (including some space for labels)
        return origin_y + 12

    def add_risk_summary(self, findings: List[Finding]):
        self.add_page()
        self.set_font('Arial', 'B', 16)
        self.cell(0, 10, 'Risk Summary Dashboard', 0, 1, 'L')
        self.ln(5)

        # Count findings by severity, favouring the highest severity between
        # calculated findings and any vendor-supplied risk rating.
        severity_counts = {}
        for finding in findings:
            rating = getattr(finding, "risk_rating", "")
            chosen = self.pick_display_severity(rating, finding.severity)
            severity_counts[chosen] = severity_counts.get(chosen, 0) + 1
            
        # Risk level boxes - stack vertically for better fit
        y_start = self.get_y()
        box_width = 40
        box_height = 20
        
        severities = ['Critical', 'High', 'Medium', 'Cautionary', 'Low', 'Info']
        
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
            
        boxes_bottom = y_start + ((len(severities) - 1) * 25) + box_height

        # Position the bar chart below the summary boxes to avoid overlapping text
        chart_height = 70
        chart_spacing = 18
        chart_origin_y = boxes_bottom + chart_height + chart_spacing
        chart_origin_x = max(45, self.l_margin + 5)
        chart_width = self.w - chart_origin_x - self.r_margin

        chart_bottom = self.add_risk_bar_chart(
            severity_counts,
            origin_x=chart_origin_x,
            origin_y=chart_origin_y,
            chart_width=chart_width,
            chart_height=chart_height,
        )
        final_bottom = max(boxes_bottom, chart_bottom)
        self.set_y(final_bottom + 10)
        self.ln(5)
        
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
        
    @staticmethod
    def pick_display_severity(rating: str, severity: str) -> str:
        """Return the most severe label from ``rating`` and ``severity``."""

        def _canonical(value: str) -> str:
            key = (value or "").strip()
            if not key:
                return ""
            lowered = key.lower()
            for alias, label in _SEVERITY_CANONICAL.items():
                if lowered.startswith(alias):
                    return label
            return key

        rating_label = _canonical(rating)
        severity_label = _canonical(severity)

        if rating_label and severity_label:
            rating_rank = _SEVERITY_RANK.get(rating_label, -1)
            severity_rank = _SEVERITY_RANK.get(severity_label, -1)
            if severity_rank > rating_rank:
                return severity_label
            return rating_label

        if severity_label:
            return severity_label
        if rating_label:
            return rating_label
        return "Info"

    def generate_risk_id(self, finding: Finding, index: int):
        """Generate a unique risk ID for tracking"""
        severity_prefix = {
            'Critical': 'CR',
            'High': 'HI',
            'Medium': 'ME',
            'Cautionary': 'CA',
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

    def derive_client_identifier(self, source_file: str) -> str:
        """Extract a high-level client identifier from a source filename."""
        if not source_file:
            return ""

        basename = os.path.basename(source_file)
        stem, _ = os.path.splitext(basename)
        stem_normalized = stem.replace('_', ' ').strip()
        if not stem_normalized:
            return ""

        dash_tokens = [token.strip() for token in stem_normalized.split('-') if token.strip()]
        if dash_tokens:
            first_token = dash_tokens[0]
            first_word = first_token.split()[0].strip()
            if first_word:
                return first_word

        for word in stem_normalized.split():
            cleaned = word.strip()
            if cleaned:
                return cleaned

        return stem_normalized

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

        # Source file / client information
        source_file = getattr(finding, 'source_file', '')
        if source_file:
            safe_source = self.safe_text(source_file, max_chars=80)
            details.append(f"Source File: {safe_source}")
            client_identifier = self.derive_client_identifier(source_file)
            if client_identifier and client_identifier != source_file:
                safe_client = self.safe_text(client_identifier, max_chars=40)
                details.append(f"Client Identifier: {safe_client}")

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
        priority_order = ['Critical', 'High', 'Medium', 'Cautionary', 'Low', 'Info']
        
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
                elif severity == 'Cautionary':
                    section_title = f'{severity} Priority - Monitor and Schedule'
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
    logger.info("PDF report generated: %s", output_path)
