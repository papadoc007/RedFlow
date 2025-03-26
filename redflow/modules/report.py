"""
Module for generating reports and result summaries for RedFlow
מודול לייצור דוחות ותקצירי תוצאות עבור RedFlow
"""

import os
import json
import time
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.markdown import Markdown

from redflow.utils.logger import get_module_logger


class ReportGenerator:
    """Class for generating reports and summaries
    מחלקה לייצור דוחות ותקצירים"""
    
    def __init__(self, config, logger, console):
        """
        Initialize the reports module
        אתחול מודול הדוחות
        
        Args:
            config: Configuration object
                   אובייקט תצורה
            logger: Logger instance
                   מופע הלוגר
            console: Console instance
                    מופע קונסולה
        """
        self.config = config
        self.console = console
        self.logger = get_module_logger("Report", logger)
        self.target = config.target
        self.output_dir = config.output_dir
        self.summaries_dir = config.summaries_dir
    
    def generate(self, results):
        """
        Create a summary report from scan results
        יצירת דוח מסכם מתוצאות הסריקה
        
        Args:
            results: Scan results from all stages
                    תוצאות הסריקה מכל השלבים
            
        Returns:
            Path to the summary report
            נתיב לדוח המסכם
        """
        self.logger.info(f"Generating summary report for {self.target}")
        
        # Create visual progress
        # יצירת התקדמות ויזואלית
        with Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]{task.description}"),
            BarColumn(),
            TimeElapsedColumn(),
            console=self.console
        ) as progress:
            generate_task = progress.add_task("[cyan]Generating summary report...", total=4)
            
            # Prepare paths and directories
            # הכנת נתיבים ותיקיות
            report_file = os.path.join(self.summaries_dir, f"summary_{self.target.replace('.', '_')}.md")
            json_report_file = os.path.join(self.summaries_dir, f"summary_{self.target.replace('.', '_')}.json")
            progress.update(generate_task, advance=1)
            
            # Create detailed report in Markdown
            # יצירת דוח מפורט ב-Markdown
            self._generate_markdown_report(results, report_file)
            progress.update(generate_task, advance=1)
            
            # Save summary report in JSON
            # שמירת דוח מסכם ב-JSON
            self._generate_json_report(results, json_report_file)
            progress.update(generate_task, advance=1)
            
            # If required and possible, display the report in the console
            # אם נדרש וניתן, הצגת הדוח במסוף
            self._display_report_summary(results)
            progress.update(generate_task, advance=1)
        
        self.logger.info(f"Summary report created at {report_file}")
        
        return report_file
    
    def _generate_markdown_report(self, results, report_file):
        """
        Create a Markdown report
        יצירת דוח Markdown
        
        Args:
            results: Scan results
                    תוצאות הסריקה
            report_file: Path to the report file
                        נתיב לקובץ הדוח
        """
        self.logger.debug(f"Creating Markdown report at {report_file}")
        
        # Scan time and date details
        # פרטי זמן ותאריך הסריקה
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        duration = int(results.get("duration", 0))
        minutes, seconds = divmod(duration, 60)
        
        # Start writing the report
        # תחילת כתיבת הדוח
        with open(report_file, "w", encoding="utf-8") as f:
            # Title and summary
            # כותרת וסיכום
            f.write(f"# Scan Report - {self.target}\n\n")
            f.write(f"**Scan Date:** {timestamp}\n")
            f.write(f"**Scan Duration:** {minutes} minutes and {seconds} seconds\n")
            f.write(f"**Target:** {self.target}\n")
            f.write(f"**Scan Mode:** {self.config.mode}\n\n")
            
            # Target information
            # מידע על המטרה
            target_info = results.get("target_info", {})
            f.write("## Target Information\n\n")
            if target_info:
                f.write(f"**Type:** {target_info.get('type', 'Unknown')}\n")
                if target_info.get("type") == "domain":
                    f.write(f"**Domain:** {target_info.get('domain', 'Unknown')}\n")
                    f.write(f"**IP Address:** {target_info.get('ip', 'Unknown')}\n")
                else:
                    f.write(f"**IP Address:** {target_info.get('ip', 'Unknown')}\n")
                    f.write(f"**Hostname:** {target_info.get('hostname', 'Unknown')}\n")
            else:
                f.write("No target information found.\n")
            f.write("\n")
            
            # Open ports
            # פורטים פתוחים
            open_ports = results.get("open_ports", [])
            f.write("\n## Open Ports / פורטים פתוחים\n\n")
            f.write("| Port | Service | Version |\n")
            f.write("|------|--------|------|\n")
            for port in open_ports:
                if isinstance(port, str):
                    # If port is a string, just display the port number
                    f.write(f"| {port} | Unknown | Unknown |\n")
                else:
                    # If port is a dictionary, extract data as before
                    port_num = port.get("port", "?")
                    service = port.get("service", "לא ידוע")
                    version = port.get("version", "")
                    f.write(f"| {port_num} | {service} | {version} |\n")
            f.write("\n")
            
            # Passive reconnaissance
            # איסוף מידע פסיבי
            passive_recon = results.get("passive_recon", {})
            f.write("## Passive Reconnaissance\n\n")
            if passive_recon:
                # WHOIS
                whois_info = passive_recon.get("whois", {})
                if whois_info:
                    f.write("### WHOIS Information\n\n")
                    f.write("| Field | Value |\n")
                    f.write("|------|------|\n")
                    for key, value in whois_info.items():
                        if isinstance(value, str):
                            f.write(f"| {key} | {value} |\n")
                    f.write("\n")
                
                # DNS Records
                dns_records = passive_recon.get("dns_records", [])
                if dns_records:
                    f.write("### DNS Records\n\n")
                    f.write("| Type | Value | TTL |\n")
                    f.write("|------|------|------|\n")
                    for record in dns_records:
                        record_type = record.get("type", "?")
                        record_value = record.get("value", "?")
                        ttl = record.get("ttl", "?")
                        f.write(f"| {record_type} | {record_value} | {ttl} |\n")
                    f.write("\n")
                
                # Subdomains
                subdomains = passive_recon.get("subdomains", [])
                if subdomains:
                    f.write("### Subdomains\n\n")
                    f.write("| Subdomain | IP Address |\n")
                    f.write("|------------|--------|\n")
                    for subdomain in subdomains:
                        if isinstance(subdomain, dict):
                            name = subdomain.get("name", "?")
                            ip = subdomain.get("ip", "לא ידוע")
                            f.write(f"| {name} | {ip} |\n")
                        else:
                            f.write(f"| {subdomain} | לא ידוע |\n")
                    f.write("\n")
                
                # Web Technologies
                web_techs = passive_recon.get("web_technologies", [])
                if web_techs:
                    f.write("### Web Technologies\n\n")
                    f.write("| Technology | Version |\n")
                    f.write("|------------|--------|\n")
                    for tech in web_techs:
                        if isinstance(tech, dict):
                            name = tech.get("name", "?")
                            version = tech.get("version", "לא ידוע")
                            f.write(f"| {name} | {version} |\n")
                        else:
                            f.write(f"| {tech} | לא ידוע |\n")
                    f.write("\n")
            else:
                f.write("No passive reconnaissance performed or no results found.\n\n")
            
            # Enumeration
            # תשאול שירותים
            enumeration = results.get("enumeration", {})
            f.write("## Enumeration\n\n")
            if enumeration:
                # FTP
                ftp_info = enumeration.get("ftp", {})
                if ftp_info:
                    f.write("### FTP\n\n")
                    f.write(f"**Port:** {ftp_info.get('port', '21')}\n")
                    f.write(f"**פורט:** {ftp_info.get('port', '21')}\n")
                    f.write(f"**גרסה:** {ftp_info.get('version', 'לא ידוע')}\n")
                    f.write(f"**גישה אנונימית:** {'כן' if ftp_info.get('anonymous_access', False) else 'לא'}\n")
                    
                    directories = ftp_info.get('directories', [])
                    if directories:
                        f.write("\n**תיקיות שנמצאו:**\n\n")
                        for directory in directories:
                            f.write(f"- {directory}\n")
                    f.write("\n")
                
                # SMB
                smb_info = enumeration.get("smb", {})
                if smb_info:
                    f.write("### SMB/Windows\n\n")
                    f.write(f"**פורט:** {smb_info.get('port', '445')}\n")
                    f.write(f"**גרסה:** {smb_info.get('version', 'לא ידוע')}\n")
                    f.write(f"**שם מחשב:** {smb_info.get('computer_name', 'לא ידוע')}\n")
                    f.write(f"**דומיין:** {smb_info.get('domain', 'לא ידוע')}\n")
                    f.write(f"**מערכת הפעלה:** {smb_info.get('os', 'לא ידוע')}\n")
                    
                    shares = smb_info.get('shares', [])
                    if shares:
                        f.write("\n**שיתופים שנמצאו:**\n\n")
                        for share in shares:
                            f.write(f"- {share}\n")
                    
                    users = smb_info.get('users', [])
                    if users:
                        f.write("\n**משתמשים שנמצאו:**\n\n")
                        for user in users:
                            f.write(f"- {user}\n")
                    f.write("\n")
                
                # Web
                web_info = enumeration.get("web", [])
                if web_info:
                    f.write("### שירותי Web\n\n")
                    if isinstance(web_info, list):
                        for web_service in web_info:
                            protocol = web_service.get('protocol', 'http')
                            port = web_service.get('port', '80')
                            f.write(f"**שירות {protocol} בפורט {port}:**\n\n")
                            
                            directories = web_service.get('directories', [])
                            if directories:
                                f.write("**תיקיות שנמצאו:**\n\n")
                                for directory in directories[:20]:  # מגביל ל-20 להדגמה
                                    f.write(f"- {directory}\n")
                                if len(directories) > 20:
                                    f.write(f"- ... ועוד {len(directories)-20} תיקיות\n")
                            
                            files = web_service.get('files', [])
                            if files:
                                f.write("\n**קבצים שנמצאו:**\n\n")
                                for file in files[:20]:  # מגביל ל-20 להדגמה
                                    f.write(f"- {file}\n")
                                if len(files) > 20:
                                    f.write(f"- ... ועוד {len(files)-20} קבצים\n")
                            f.write("\n")
                    else:
                        f.write("נמצאו שירותי web אך המבנה לא תקין להצגה.\n\n")
                
                # SSH
                ssh_info = enumeration.get("ssh", {})
                if ssh_info:
                    f.write("### SSH\n\n")
                    f.write(f"**פורט:** {ssh_info.get('port', '22')}\n")
                    f.write(f"**גרסה:** {ssh_info.get('version', 'לא ידוע')}\n")
                    
                    auth_methods = ssh_info.get('auth_methods', [])
                    if auth_methods:
                        f.write(f"**שיטות אימות:** {', '.join(auth_methods)}\n")
                    
                    f.write(f"**אלגוריתמים חלשים:** {'כן' if ssh_info.get('weak_algorithms', False) else 'לא'}\n\n")
                
                # מסדי נתונים
                db_info = enumeration.get("database", {})
                if db_info:
                    f.write("### מסדי נתונים\n\n")
                    for db_type, instances in db_info.items():
                        for db in instances:
                            f.write(f"**{db_type} בפורט {db.get('port', 'לא ידוע')}:**\n\n")
                            f.write(f"**גרסה:** {db.get('version', 'לא ידוע')}\n")
                            f.write(f"**נגיש:** {'כן' if db.get('accessible', False) else 'לא'}\n")
                            f.write(f"**אישורים ברירת מחדל:** {'כן' if db.get('default_credentials', False) else 'לא'}\n\n")
            else:
                f.write("לא בוצע תשאול שירותים או שלא נמצאו תוצאות.\n\n")
            
            # פגיעויות וניצול
            exploitation = results.get("exploitation", {})
            f.write("## פגיעויות וניצול\n\n")
            if exploitation:
                # פגיעויות
                vulnerabilities = exploitation.get("vulnerabilities", [])
                if vulnerabilities:
                    f.write("### פגיעויות שזוהו\n\n")
                    f.write("| שירות | פורט | פגיעות | חומרה | תיאור |\n")
                    f.write("|--------|------|---------|-------|--------|\n")
                    for vuln in vulnerabilities:
                        service = vuln.get("service", "לא ידוע")
                        port = vuln.get("port", "?")
                        name = vuln.get("name", "לא ידוע")
                        severity = vuln.get("severity", "לא ידוע")
                        description = vuln.get("description", "").replace("\n", " ")
                        f.write(f"| {service} | {port} | {name} | {severity} | {description} |\n")
                    f.write("\n")
                
                # אישורים
                credentials = exploitation.get("credentials", [])
                if credentials:
                    f.write("### אישורים שנחשפו\n\n")
                    f.write("| שירות | פורט | שם משתמש | סיסמה |\n")
                    f.write("|--------|------|------------|--------|\n")
                    for cred in credentials:
                        service = cred.get("service", "לא ידוע")
                        port = cred.get("port", "?")
                        username = cred.get("username", "לא ידוע")
                        password = cred.get("password", "לא ידוע")
                        f.write(f"| {service} | {port} | {username} | {password} |\n")
                    f.write("\n")
                
                # Exploits
                exploits = exploitation.get("exploits", [])
                if exploits:
                    f.write("### Exploit-ים פוטנציאליים\n\n")
                    f.write("| פגיעות | שם | מיקום |\n")
                    f.write("|---------|------|--------|\n")
                    for exploit in exploits:
                        vulnerability = exploit.get("vulnerability", "לא ידוע")
                        name = exploit.get("name", "לא ידוע")
                        path = exploit.get("path", "לא ידוע")
                        f.write(f"| {vulnerability} | {name} | {path} |\n")
                    f.write("\n")
            else:
                f.write("לא בוצע ניתוח פגיעויות או שלא נמצאו תוצאות.\n\n")
            
            # מסקנות והמלצות
            f.write("## מסקנות והמלצות\n\n")
            
            # נייצר המלצות בסיסיות על סמך הממצאים
            recommendations = self._generate_recommendations(results)
            for category, rec_list in recommendations.items():
                f.write(f"### {category}\n\n")
                for rec in rec_list:
                    f.write(f"- {rec}\n")
                f.write("\n")
            
            # סוף הדוח
            f.write("---\n\n")
            f.write(f"דוח זה נוצר אוטומטית על ידי RedFlow v{self.config._get_version()}\n")
            f.write(f"תאריך ייצור הדוח: {timestamp}\n")
    
    def _generate_json_report(self, results, json_report_file):
        """
        Create a JSON report
        יצירת דוח JSON
        
        Args:
            results: Scan results
                    תוצאות הסריקה
            json_report_file: Path to the report file
                             נתיב לקובץ הדוח
        """
        self.logger.debug(f"Creating JSON report at {json_report_file}")
        
        # Save all results in an organized JSON structure
        # שמירת כל התוצאות במבנה JSON מאורגן
        summary = {
            "timestamp": datetime.now().isoformat(),
            "target": self.target,
            "mode": self.config.mode,
            "duration": results.get("duration", 0),
            "target_info": results.get("target_info", {}),
            "open_ports": results.get("open_ports", []),
            "services": results.get("discovered_services", []),
            "passive_recon": results.get("passive_recon", {}),
            "enumeration": results.get("enumeration", {}),
            "vulnerabilities": results.get("exploitation", {}).get("vulnerabilities", []),
            "credentials": results.get("exploitation", {}).get("credentials", []),
            "exploits": results.get("exploitation", {}).get("exploits", [])
        }
        
        # Add recommendations
        # הוספת המלצות
        summary["recommendations"] = self._generate_recommendations(results)
        
        # Save to JSON file
        # שמירה לקובץ JSON
        with open(json_report_file, "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=4, ensure_ascii=False)
    
    def _display_report_summary(self, results):
        """
        Display a brief summary of the report in the console
        הצגת תקציר קצר של הדוח במסוף
        
        Args:
            results: Scan results
                    תוצאות הסריקה
        """
        self.logger.debug("Displaying report summary in console")
        
        self.console.print("\n[bold green]== Findings Summary ==[/bold green]")
        
        # Number of open ports
        # מספר פורטים פתוחים
        open_ports_count = len(results.get("open_ports", []))
        self.console.print(f"[cyan]Open Ports:[/cyan] {open_ports_count}")
        
        # Number of services
        # מספר שירותים
        services_count = len(results.get("discovered_services", []))
        self.console.print(f"[cyan]Identified Services:[/cyan] {services_count}")
        
        # Number of vulnerabilities
        # מספר פגיעויות
        if "exploitation" in results:
            vuln_count = len(results["exploitation"].get("vulnerabilities", []))
            self.console.print(f"[cyan]Identified Vulnerabilities:[/cyan] {vuln_count}")
            
            # Vulnerabilities by severity
            # פגיעויות לפי חומרה
            if vuln_count > 0:
                severity_count = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
                for vuln in results["exploitation"].get("vulnerabilities", []):
                    severity = vuln.get("severity", "MEDIUM").upper()
                    if severity in severity_count:
                        severity_count[severity] += 1
                
                self.console.print(f"  [red]Critical:[/red] {severity_count['CRITICAL']}")
                self.console.print(f"  [orange]High:[/orange] {severity_count['HIGH']}")
                self.console.print(f"  [yellow]Medium:[/yellow] {severity_count['MEDIUM']}")
                self.console.print(f"  [green]Low:[/green] {severity_count['LOW']}")
            
            # Exposed credentials
            # אישורים שנחשפו
            cred_count = len(results["exploitation"].get("credentials", []))
            if cred_count > 0:
                self.console.print(f"[cyan]Exposed Credentials:[/cyan] {cred_count}")
            
            # Potential exploits
            # Exploits פוטנציאליים
            exploit_count = len(results["exploitation"].get("exploits", []))
            if exploit_count > 0:
                self.console.print(f"[cyan]Potential Exploits:[/cyan] {exploit_count}")
        
        self.console.print("\n[bold blue]Full report saved in the output directory![/bold blue]")
    
    def _generate_recommendations(self, results):
        """
        Generate basic recommendations based on findings
        יצירת המלצות בסיסיות על סמך הממצאים
        
        Args:
            results: Scan results
                    תוצאות הסריקה
            
        Returns:
            Dictionary of recommendations divided into categories
            מילון המלצות מחולק לקטגוריות
        """
        recommendations = {
            "General Recommendations": [],
            "Network Security Recommendations": [],
            "Service Security Recommendations": [],
            "Urgent Recommendations": []
        }
        
        # General recommendations always appear
        # המלצות כלליות תמיד יופיעו
        recommendations["General Recommendations"].append("It is recommended to regularly follow security updates for all exposed services.")
        recommendations["General Recommendations"].append("Ensure that all services with external access are necessary for business operations.")
        
        # Network security recommendations
        # המלצות אבטחת רשת
        open_ports = results.get("open_ports", [])
        if open_ports:
            if len(open_ports) > 10:
                recommendations["Network Security Recommendations"].append(f"Found {len(open_ports)} open ports. It is recommended to close unnecessary ports.")
            
            # Check sensitive ports
            # בדיקת פורטים רגישים
            sensitive_ports = [21, 22, 23, 3389, 5900]
            exposed_sensitive = []
            for port in open_ports:
                port_num = port.get("port")
                if port_num in sensitive_ports:
                    exposed_sensitive.append(port_num)
            
            if exposed_sensitive:
                port_str = ", ".join([str(p) for p in exposed_sensitive])
                recommendations["Network Security Recommendations"].append(f"Sensitive ports exposed: {port_str}. It is recommended to restrict access using a firewall.")
        
        # Service security recommendations
        # המלצות אבטחת שירותים
        if "enumeration" in results:
            enumeration = results["enumeration"]
            
            # FTP
            if "ftp" in enumeration and enumeration["ftp"].get("anonymous_access", False):
                recommendations["Service Security Recommendations"].append("Anonymous access to FTP is enabled. It is recommended to disable anonymous access if not necessary.")
            
            # SMB
            if "smb" in enumeration and enumeration["smb"].get("shares"):
                recommendations["Service Security Recommendations"].append("SMB file shares are exposed. Ensure they are properly protected with appropriate access permissions.")
            
            # SSH
            if "ssh" in enumeration and enumeration["ssh"].get("weak_algorithms", False):
                recommendations["Service Security Recommendations"].append("SSH server uses weak algorithms. It is recommended to update the SSH configuration to support only strong algorithms.")
            
            # Web
            if "web" in enumeration:
                recommendations["Service Security Recommendations"].append("Web services are exposed. Ensure they are updated and properly configured.")
        
        # Urgent recommendations based on severe vulnerabilities
        # המלצות דחופות על סמך פגיעויות חמורות
        if "exploitation" in results:
            exploitation = results["exploitation"]
            vulnerabilities = exploitation.get("vulnerabilities", [])
            
            high_severity_vulns = [v for v in vulnerabilities if v.get("severity") in ["HIGH", "CRITICAL"]]
            if high_severity_vulns:
                for vuln in high_severity_vulns:
                    service = vuln.get("service", "Unknown")
                    port = vuln.get("port", "Unknown")
                    name = vuln.get("name", "Unknown")
                    recommendations["Urgent Recommendations"].append(f"Urgently address vulnerability {name} in service {service} (port {port}).")
            
            creds = exploitation.get("credentials", [])
            if creds:
                recommendations["Urgent Recommendations"].append("Weak credentials found. Change passwords immediately and enforce a strong password policy.")
        
        return recommendations
    
    def _get_version(self):
        """Returns the tool version
        מחזיר את גרסת הכלי"""
        try:
            return self.config._get_version()
        except:
            return "0.1.0" 