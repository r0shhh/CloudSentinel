from datetime import datetime
from rich.console import Console
from rich.text import Text
from rich.panel import Panel
from rich.table import Table



class ReportGenerator:
    def __init__(self):
        self.findings = []
        self.scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def add_finding(self, check_name, result, severity, cis_control='N/A'):
        if result['status'] == 'FAIL':
            self.findings.append({
                'check': check_name,
                'severity': severity,
                'cis_control': cis_control,
                'resource': result.get('bucket') or result.get('user') or result.get('group_id') or result.get('trail_name') or result.get('db_name'),
                'issues': result['issues']
            })    

    def get_summary(self):
        total = len(self.findings)
        breakdown = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW':0}

        for finding in self.findings:
            severity = finding['severity']
            if severity in breakdown:
                breakdown[severity] += 1

        return {
            'scan_time': self.scan_time,
            'total_findings': total,
            'breakdown': breakdown
        }               
    
    def print_report(self):
        console = Console()
        summary = self.get_summary()
        summary_text = Text()
        
        summary_text.append("Scan Time: ", style="bold cyan")
        summary_text.append(f"{summary['scan_time']}\n")
        summary_text.append("Total Findings: ", style="bold cyan")
        summary_text.append(f"{summary['total_findings']}\n")
        summary_text.append("Severity Breakdown\n", style="bold cyan underline")

        for severity, count in summary['breakdown'].items():
            summary_text.append(f"•{severity:<8}: ", style="bold")
            count_style = "bold red" if count > 0 else "white"
            summary_text.append(f"{count}\n", style=count_style)
        
        console.print(Panel(summary_text, title="[bold magenta underline]CloudSentinel Summary[/bold magenta underline]", expand=False))

        if self.findings:

            table = Table(title="\nDetailed Findings", title_style="bold magenta underline", show_header=True)

            table.add_column("Severity", justify="center")
            table.add_column("CIS")
            table.add_column("Rule Check Name")
            table.add_column("Resource Identifier")
            table.add_column("Issues")

            for finding in self.findings:
                issues_bullet = "\n".join([f"• {issue}" for issue in finding['issues']])

                table.add_row(
                    finding['severity'].upper(),
                    finding['cis_control'],
                    finding['check'],
                    finding['resource'],
                    issues_bullet
                )

            console.print(table)
        else:
            console.print("\n[bold green]No findings: All checks passed.[/bold green]\n") 


    def save_json_report(self, filepath):
        import json
        console = Console()
        summary = self.get_summary()
        output = {
            'summary': summary,
            'findings': self.findings
        }
        with open(filepath, 'w') as f:
            json.dump(output, f, indent=4)
        console.print(f"\n[bold green]✔[/bold green] [dim] Report saved to {filepath}[/dim]\n")
