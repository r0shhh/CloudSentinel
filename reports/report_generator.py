from datetime import datetime


class ReportGenerator:
    def __init__(self):
        self.findings = []
        self.scan_time = datetime.now().isoformat()

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
        summary = self.get_summary()
        
        print("\n" + "="*50)
        print("CLOUDSENTINEL SCAN REPORT")
        print("="*50)
        print(f"Scan Time : {summary['scan_time']}")
        print(f"Total Findings: {summary['total_findings']}")
        print()
        print("Severity Breakdown:")
        for severity, count in summary['breakdown'].items():
            print(f" {severity}: {count}")

        if self.findings:
            print()
            print("Findings:")
            print("-"*50)
            for finding in self.findings:
                print(f"[{finding['severity']}] {finding['check']} (CIS {finding['cis_control']})") 
                print(f"Resource : {finding['resource']}")
                for issue in finding['issues']:
                    print(f"!{issue}" )
                print()
        
        else: 
            print()
            print("No findings. All checks passed.")

        print("="*50)    

    def save_json_report(self, filepath):
        import json
        summary = self.get_summary()
        output = {
            'summary': summary,
            'findings': self.findings
        }
        with open(filepath, 'w') as f:
            json.dump(output, f, indent=4)
        print(f"\nReport saved to {filepath}")    
