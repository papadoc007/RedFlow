# RedFlow - Advanced Automated Information Gathering and Attack Tool for Kali Linux
# RedFlow - כלי אוטומטי מתקדם לאיסוף מידע ותקיפה לסביבת Kali Linux

RedFlow is a CLI-based Python tool (with optional GUI capabilities) that automates the early stages of penetration testing.
RedFlow הוא כלי Python מבוסס-CLI (עם אפשרות להרחבות GUI) שמאפשר אוטומציה של השלבים המוקדמים בבדיקות חדירות.

## Key Features / תכונות עיקריות

- Target specification by IP address or domain
- Passive and active information gathering
- Open port and service identification
- Automatic recommendation or execution of appropriate attack tools (e.g., Gobuster, Enum4linux, Hydra)
- **Vulnerability detection and interactive exploitation**
- **Enhanced searchsploit integration with custom search options**
- **Port-focused scanning and exploitation**
- **File discovery and downloading from web and FTP services**
- **Recursive directory scanning**
- **Integration with searchsploit for finding vulnerabilities and exploits**
- **GPT-powered Exploit Advisor for intelligent vulnerability assessment**
- Wordlist and attack method selection via simple CLI or GUI
- Analysis of each tool's output
- Context-aware help for understanding outputs and common error messages
- Default path detection for wordlists/tools/scripts in Kali Linux

---

- קבלת כתובת IP או דומיין כמטרה
- ביצוע איסוף מידע פסיבי ואקטיבי
- זיהוי פורטים פתוחים ושירותים
- המלצה או הפעלה אוטומטית של כלי תקיפה המתאימים (למשל Gobuster, Enum4linux, Hydra)
- **זיהוי פגיעויות וניצול אינטראקטיבי שלהן**
- **אינטגרציה משופרת עם searchsploit ואפשרויות חיפוש מותאמות אישית**
- **סריקה וניצול ממוקדים בפורט ספציפי**
- **גילוי והורדת קבצים משירותי אינטרנט ו-FTP**
- **סריקת תיקיות באופן רקורסיבי**
- **אינטגרציה עם searchsploit למציאת פגיעויות ומנגנוני ניצול**
- **יועץ ניצול מבוסס GPT להערכה חכמה של פגיעויות**
- אפשרות לבחירת רשימות מילים ושיטות תקיפה באמצעות ממשק CLI פשוט או GUI
- ניתוח פלט של כל כלי
- עזרה מבוססת-הקשר להבנת פלטים והודעות שגיאה נפוצות
- זיהוי ושימוש בנתיבי ברירת מחדל של רשימות מילים/כלים/סקריפטים מסביבת Kali Linux

## Architecture & Workflow / ארכיטקטורה וזרימת עבודה

RedFlow uses a modular architecture with the following main components:

1. **Core Scanner**: Manages the overall scanning flow and orchestrates other modules
2. **Enumeration Module**: Performs detailed enumeration of discovered services
3. **Exploitation Module**: Handles exploitation of identified vulnerabilities
4. **GPT Advisor Module**: Provides AI-powered analysis and recommendations
5. **File Operations Module**: Manages file discovery and downloading
6. **Utilities**: Configuration, logging, and helper functions

The typical workflow is:

1. **Target Identification**: Specify target IP/domain and scan parameters
2. **Reconnaissance**: Perform passive (whois, DNS) and active (port scanning) reconnaissance
3. **Service Enumeration**: Detailed analysis of discovered services
4. **Vulnerability Identification**: Identify potential vulnerabilities in discovered services
5. **Exploitation**: Interactive exploitation of vulnerabilities
6. **GPT Analysis**: AI-powered analysis and recommendations for complex vulnerabilities
7. **Reporting**: Summary of findings and recommendations

---

RedFlow משתמש בארכיטקטורה מודולרית עם הרכיבים העיקריים הבאים:

1. **סורק ליבה**: מנהל את זרימת הסריקה הכוללת ומתזמר מודולים אחרים
2. **מודול תשאול**: מבצע תשאול מפורט של שירותים שהתגלו
3. **מודול ניצול**: מטפל בניצול של פגיעויות שזוהו
4. **מודול יועץ GPT**: מספק ניתוח והמלצות מבוססי בינה מלאכותית
5. **מודול פעולות קבצים**: מנהל גילוי והורדת קבצים
6. **כלי עזר**: תצורה, רישום יומן ופונקציות עזר

זרימת העבודה הטיפוסית היא:

1. **זיהוי מטרה**: הגדרת IP/דומיין של מטרה ופרמטרים לסריקה
2. **סיור מקדים**: ביצוע סיור פסיבי (whois, DNS) ואקטיבי (סריקת פורטים)
3. **תשאול שירות**: ניתוח מפורט של שירותים שהתגלו
4. **זיהוי פגיעויות**: זיהוי פגיעויות פוטנציאליות בשירותים שהתגלו
5. **ניצול**: ניצול אינטראקטיבי של פגיעויות
6. **ניתוח GPT**: ניתוח והמלצות מבוססי בינה מלאכותית לפגיעויות מורכבות
7. **דיווח**: סיכום ממצאים והמלצות

## Installation / התקנה

```bash
# Clone the repository / קלון המאגר
git clone https://github.com/papadoc007/RedFlow.git

# Navigate to the project directory / כניסה לתיקיית הפרויקט
cd RedFlow

# Install dependencies / התקנת התלויות
pip install -r requirements.txt

# Install additional dependencies / התקנת תלויות נוספות
pip install ftputil   # For FTP file handling
```

## CLI Usage / שימוש בממשק CLI

Basic execution / הפעלה בסיסית:

```bash
python redflow.py --target example.com --mode full
```

### All Possible CLI Parameters / כל הפרמטרים האפשריים ב-CLI

```bash
usage: redflow.py [-h] --target TARGET [--mode {passive,active,full}] [--port PORT] [--output OUTPUT] [--interactive] [--gpt] [--verbose] [--version]
                 [--list-files] [--interactive-download] [--port PORT] [--protocol {http,https,ftp}] [--download DOWNLOAD_URL]
                 [--view VIEW_URL] [--results-dir RESULTS_DIR] [--exploit-menu] [--search-exploits SEARCH_EXPLOITS]
                 [--port-to-exploit PORT_TO_EXPLOIT] [--service-to-exploit SERVICE_TO_EXPLOIT] [--gpt-advisor] [--gpt-model GPT_MODEL]
```

| Parameter | Shortcut | Description | Default | Example |
|-----------|----------|-------------|---------|---------|
| `--target` | `-t` | IP address or domain of the target | (Required) | `--target example.com` |
| `--mode` | `-m` | Scan mode (`passive` / `active` / `full`) | `full` | `--mode passive` |
| `--port` | `-p` | Focus on a specific port for scanning and exploitation | | `--port 21` |
| `--output` | `-o` | Path to output directory | `./scans/` | `--output ./my_scans/` |
| `--interactive` | `-i` | Request confirmation before proceeding to next step | `False` | `--interactive` |
| `--gpt` | | Use GPT for general analysis and recommendations | `False` | `--gpt` |
| `--gpt-advisor` | | Use GPT Exploit Advisor for vulnerability assessment | `False` | `--gpt-advisor` |
| `--gpt-model` | | Specify the GPT model to use | `gpt-4o-mini` | `--gpt-model gpt-4` |
| `--verbose` | `-v` | Display detailed information in logs | `False` | `--verbose` |
| `--version` | | Display software version | | `--version` |
| `--help` | `-h` | Display help | | `--help` |

#### File Operations / פעולות על קבצים

| Parameter | Description | Default | Example |
|-----------|-------------|---------|---------|
| `--list-files` | List discovered files from a previous scan | | `--list-files` |
| `--interactive-download` | Interactively select and download discovered files | | `--interactive-download` |
| `--port` | Port to use for file operations | `80` | `--port 8080` |
| `--protocol` | Protocol to use for file operations | `http` | `--protocol https` |
| `--download` | URL or path of file to download | | `--download http://target/file.txt` |
| `--view` | URL or path of file to view | | `--view http://target/robots.txt` |
| `--results-dir` | Directory of previous scan results to use for file operations | | `--results-dir ./scans/RedFlow_192.168.1.1` |

#### Vulnerability Exploitation / ניצול פגיעויות

| Parameter | Description | Default | Example |
|-----------|-------------|---------|---------|
| `--exploit-menu` | Show interactive exploit menu for discovered services | | `--exploit-menu` |
| `--search-exploits` | Search for exploits for a specific service | | `--search-exploits vsftpd:2.3.4` |
| `--port-to-exploit` | Port of the service to exploit | | `--port-to-exploit 21` |
| `--service-to-exploit` | Name of the service to exploit | | `--service-to-exploit vsftpd` |
| `--gpt-advisor` | Use GPT-powered Exploit Advisor for vulnerability analysis | | `--gpt-advisor` |

---

| פרמטר | קיצור | תיאור | ערך ברירת מחדל | דוגמה |
|-------|-------|-------|----------------|-------|
| `--target` | `-t` | כתובת IP או דומיין של המטרה | (חובה) | `--target example.com` |
| `--mode` | `-m` | מצב סריקה (`passive` / `active` / `full`) | `full` | `--mode passive` |
| `--port` | `-p` | התמקדות בפורט ספציפי לסריקה ולניצול | | `--port 21` |
| `--output` | `-o` | נתיב לתיקיית הפלט | `./scans/` | `--output ./my_scans/` |
| `--interactive` | `-i` | בקשת אישור לפני המשך לשלב הבא | `False` | `--interactive` |
| `--gpt` | | שימוש ב-GPT לניתוח כללי והמלצות | `False` | `--gpt` |
| `--gpt-advisor` | | שימוש ביועץ ניצול GPT להערכת פגיעויות | `False` | `--gpt-advisor` |
| `--gpt-model` | | הגדרת מודל ה-GPT לשימוש | `gpt-4o-mini` | `--gpt-model gpt-4` |
| `--verbose` | `-v` | הצגת מידע מפורט בלוגים | `False` | `--verbose` |
| `--version` | | הצגת גרסת התוכנה | | `--version` |
| `--help` | `-h` | הצגת עזרה | | `--help` |

#### פעולות על קבצים

| פרמטר | תיאור | ערך ברירת מחדל | דוגמה |
|-------|-------|----------------|-------|
| `--list-files` | הצגת קבצים שהתגלו בסריקה קודמת | | `--list-files` |
| `--interactive-download` | בחירה והורדה אינטראקטיבית של קבצים שהתגלו | | `--interactive-download` |
| `--port` | פורט לשימוש בפעולות על קבצים | `80` | `--port 8080` |
| `--protocol` | פרוטוקול לשימוש בפעולות על קבצים | `http` | `--protocol https` |
| `--download` | נתיב או URL של קובץ להורדה | | `--download http://target/file.txt` |
| `--view` | נתיב או URL של קובץ לצפייה | | `--view http://target/robots.txt` |
| `--results-dir` | תיקיית תוצאות סריקה קודמת לשימוש בפעולות על קבצים | | `--results-dir ./scans/RedFlow_192.168.1.1` |

#### ניצול פגיעויות

| פרמטר | תיאור | ערך ברירת מחדל | דוגמה |
|-------|-------|----------------|-------|
| `--exploit-menu` | הצגת תפריט אינטראקטיבי לניצול פגיעויות בשירותים שהתגלו | | `--exploit-menu` |
| `--search-exploits` | חיפוש מנגנוני ניצול לשירות ספציפי | | `--search-exploits vsftpd:2.3.4` |
| `--port-to-exploit` | הפורט של השירות לניצול | | `--port-to-exploit 21` |
| `--service-to-exploit` | שם השירות לניצול | | `--service-to-exploit vsftpd` |
| `--gpt-advisor` | שימוש ביועץ ניצול מבוסס GPT לניתוח פגיעויות | | `--gpt-advisor` |

### Usage Examples / דוגמאות לשימוש ב-CLI

1. **Perform passive scan only** (no port scanning or active attacks):
   ```bash
   python redflow.py --target example.com --mode passive
   ```

2. **Perform full scan in interactive mode**:
   ```bash
   python redflow.py --target 192.168.1.10 --mode full --interactive
   ```

3. **Perform active scan with GPT and save results to custom directory**:
   ```bash
   python redflow.py --target example.com --mode active --output ./custom_dir/ --gpt
   ```

4. **List discovered files on port 80**:
   ```bash
   python redflow.py --target 192.168.1.10 --list-files --port 80
   ```

5. **Interactive download of discovered files**:
   ```bash
   python redflow.py --target 192.168.1.10 --interactive-download --port 80
   ```

6. **View a specific file**:
   ```bash
   python redflow.py --view http://192.168.1.10/robots.txt
   ```

7. **Launch exploit menu for discovered services**:
   ```bash
   python redflow.py --exploit-menu
   ```

8. **Search for exploits for a specific service**:
   ```bash
   python redflow.py --search-exploits apache:2.4.7
   ```

9. **Exploit a specific service**:
   ```bash
   python redflow.py --service-to-exploit vsftpd --port-to-exploit 21
   ```

10. **Scan and exploit a specific port**:
   ```bash
   python redflow.py --target 10.0.2.4 --port 21
   ```
   
11. **Use GPT Exploit Advisor for vulnerability analysis**:
   ```bash
   python redflow.py --gpt-advisor
   ```

12. **Full scan with GPT Exploit Advisor enabled**:
   ```bash
   python redflow.py --target 192.168.1.10 --mode full --gpt-advisor
   ```

13. **Scan specific port and use GPT Exploit Advisor**:
   ```bash
   python redflow.py --target 192.168.1.10 --port 21 --gpt-advisor
   ```

---

1. **ביצוע סריקה פסיבית בלבד** (ללא סריקת פורטים או תקיפה אקטיבית):
   ```bash
   python redflow.py --target example.com --mode passive
   ```

2. **ביצוע סריקה מלאה במצב אינטראקטיבי**:
   ```bash
   python redflow.py --target 192.168.1.10 --mode full --interactive
   ```

3. **ביצוע סריקה אקטיבית עם שימוש ב-GPT ושמירת התוצאות בתיקייה מותאמת אישית**:
   ```bash
   python redflow.py --target example.com --mode active --output ./custom_dir/ --gpt
   ```

4. **הצגת קבצים שהתגלו בפורט 80**:
   ```bash
   python redflow.py --target 192.168.1.10 --list-files --port 80
   ```

5. **הורדה אינטראקטיבית של קבצים שהתגלו**:
   ```bash
   python redflow.py --target 192.168.1.10 --interactive-download --port 80
   ```

6. **צפייה בקובץ ספציפי**:
   ```bash
   python redflow.py --view http://192.168.1.10/robots.txt
   ```

7. **הצגת תפריט ניצול פגיעויות לשירותים שהתגלו**:
   ```bash
   python redflow.py --exploit-menu
   ```

8. **חיפוש מנגנוני ניצול לשירות ספציפי**:
   ```bash
   python redflow.py --search-exploits apache:2.4.7
   ```

9. **ניצול שירות ספציפי**:
   ```bash
   python redflow.py --service-to-exploit vsftpd --port-to-exploit 21
   ```

10. **סריקה וניצול של פורט ספציפי**:
   ```bash
   python redflow.py --target 10.0.2.4 --port 21
   ```

11. **שימוש ביועץ ניצול GPT לניתוח פגיעויות**:
   ```bash
   python redflow.py --gpt-advisor
   ```

12. **סריקה מלאה עם יועץ ניצול GPT מופעל**:
   ```bash
   python redflow.py --target 192.168.1.10 --mode full --gpt-advisor
   ```

13. **סריקת פורט ספציפי ושימוש ביועץ ניצול GPT**:
   ```bash
   python redflow.py --target 192.168.1.10 --port 21 --gpt-advisor
   ```

## New Features / תכונות חדשות

### File Discovery and Download / גילוי והורדת קבצים

The tool now provides comprehensive features for discovering and downloading files from web and FTP services:
הכלי כעת מספק יכולות מקיפות לגילוי והורדת קבצים משירותי אינטרנט ו-FTP:

- **Automatic file discovery**: During enumeration, the tool discovers files such as `robots.txt`, `sitemap.xml`, and other common files.
- **Recursive directory scanning**: Ability to recursively scan discovered directories for deeper enumeration.
- **Interactive file download**: Choose which discovered files to download through an interactive menu.
- **File viewing**: View file contents directly from the CLI without downloading.

***

- **גילוי קבצים אוטומטי**: במהלך האיתור, הכלי מגלה קבצים כמו `robots.txt`, `sitemap.xml`, וקבצים נפוצים אחרים.
- **סריקת תיקיות באופן רקורסיבי**: יכולת לסרוק תיקיות שהתגלו באופן רקורסיבי לאיתור עמוק יותר.
- **הורדת קבצים אינטראקטיבית**: בחירה אילו קבצים שהתגלו להוריד באמצעות תפריט אינטראקטיבי.
- **צפייה בקבצים**: צפייה בתוכן הקבצים ישירות מה-CLI ללא הורדה.

#### Instructions / הוראות שימוש:

To use these features after a scan:
לשימוש בתכונות אלה לאחר סריקה:

```bash
# List discovered files / הצגת קבצים שהתגלו
python redflow.py --target 192.168.1.10 --list-files

# Interactive download / הורדה אינטראקטיבית
python redflow.py --target 192.168.1.10 --interactive-download

# Recursive directory scanning / סריקת תיקיות רקורסיבית
# (Available within the interactive download menu, type "scan X" where X is the directory number)
# (זמין בתוך תפריט ההורדה האינטראקטיבי, הקלד "scan X" כאשר X הוא מספר התיקייה)
```

### Vulnerability Exploitation / ניצול פגיעויות

The tool now integrates with searchsploit to find and exploit vulnerabilities:
הכלי כעת משתלב עם searchsploit למציאת וניצול פגיעויות:

- **Vulnerability detection**: Automatically detects vulnerabilities in discovered services.
- **Exploit search**: Searches for exploits using searchsploit based on service version information.
- **Interactive exploit menu**: Provides an interactive menu to select and exploit vulnerabilities.
- **Custom search options**: Allows users to enter custom search terms when looking for exploits.
- **Exploit selection**: Displays a numbered list of available exploits for easy selection.
- **Exploit preparation**: Automatically prepares exploits for execution by copying and configuring them.
- **GPT Exploit Advisor**: AI-powered analysis of vulnerabilities and detailed exploitation guides.

***

- **זיהוי פגיעויות**: מזהה באופן אוטומטי פגיעויות בשירותים שהתגלו.
- **חיפוש מנגנוני ניצול**: מחפש מנגנוני ניצול באמצעות searchsploit בהתבסס על מידע גרסת השירות.
- **תפריט ניצול אינטראקטיבי**: מספק תפריט אינטראקטיבי לבחירה וניצול פגיעויות.
- **אפשרויות חיפוש מותאמות אישית**: מאפשר למשתמשים להזין מונחי חיפוש מותאמים אישית בעת חיפוש אחר exploits.
- **בחירת exploit**: מציג רשימה ממוספרת של exploits זמינים לבחירה קלה.
- **הכנת מנגנוני ניצול**: מכין באופן אוטומטי מנגנוני ניצול להרצה על ידי העתקה והגדרה שלהם.
- **יועץ ניצול GPT**: ניתוח מבוסס בינה מלאכותית של פגיעויות ומדריכי ניצול מפורטים.

#### Instructions / הוראות שימוש:

To use these features after a scan:
לשימוש בתכונות אלה לאחר סריקה:

```bash
# Launch exploit menu / הצגת תפריט ניצול
python redflow.py --exploit-menu

# Search for exploits for a specific service / חיפוש מנגנוני ניצול לשירות ספציפי
python redflow.py --search-exploits apache:2.4.7

# Exploit a specific service / ניצול שירות ספציפי
python redflow.py --service-to-exploit vsftpd --port-to-exploit 21

# Scan and focus exploitation on a specific port / סריקה ומיקוד ניצול על פורט ספציפי
python redflow.py --target 10.0.2.4 --port 21

# Use GPT Exploit Advisor / שימוש ביועץ ניצול GPT
python redflow.py --gpt-advisor
```

### GPT Exploit Advisor / יועץ ניצול GPT

The GPT Exploit Advisor is a powerful feature that uses OpenAI's GPT models to provide detailed analysis and exploitation guidance:

- **Vulnerability assessment**: Thorough analysis of discovered vulnerabilities and their applicability to the target
- **Exploitation instructions**: Step-by-step instructions for exploiting vulnerabilities, including command examples
- **Post-exploitation guidance**: Suggestions for actions to take after successful exploitation
- **Metasploit integration**: Special handling for Metasploit modules with custom resource script generation
- **Customizable parameters**: Control GPT behavior through parameters like temperature, token limits and more

***

יועץ ניצול ה-GPT הוא תכונה חזקה המשתמשת במודלים של OpenAI GPT כדי לספק ניתוח מפורט והנחיות ניצול:

- **הערכת פגיעות**: ניתוח מעמיק של פגיעויות שהתגלו והתאמתן למטרה
- **הוראות ניצול**: הוראות שלב-אחר-שלב לניצול פגיעויות, כולל דוגמאות פקודה
- **הנחיות לאחר הניצול**: הצעות לפעולות שיש לבצע לאחר ניצול מוצלח
- **אינטגרציה עם Metasploit**: טיפול מיוחד במודולים של Metasploit עם יצירת סקריפט משאבים מותאם אישית
- **פרמטרים מותאמים אישית**: שליטה בהתנהגות GPT באמצעות פרמטרים כמו טמפרטורה, מגבלות תווים ועוד

#### Sample Usage / דוגמת שימוש:

```bash
# Basic usage with default settings / שימוש בסיסי עם הגדרות ברירת מחדל
python redflow.py --target example.com --gpt-advisor

# Specify GPT model / הגדרת מודל GPT
python redflow.py --gpt-advisor --gpt-model gpt-4o-mini

# Full scan with GPT advisor / סריקה מלאה עם יועץ GPT
python redflow.py --target 192.168.1.10 --mode full --gpt-advisor
```

You can customize GPT behavior in the config.yaml file:
תוכל להתאים אישית את התנהגות ה-GPT בקובץ config.yaml:

```yaml
gpt:
  api_key: "YOUR_API_KEY_HERE"
  model: "gpt-4o-mini"  # or other available models
  temperature: 0.3      # 0.0-1.0 (lower = more focused)
  max_tokens: 500       # Maximum response length
  top_p: 1.0            # Controls token selection
  frequency_penalty: 0.0
  presence_penalty: 0.0
```

#### Sample Output / דוגמת פלט:

```
[bold blue]======== RedFlow + GPT Exploit Advisor ========[/bold blue]
[bold cyan]Found services:[/bold cyan]
1. [bold]vsftpd 2.3.4[/bold] on port 21

[bold green]Found 3 potential exploits:[/bold green]
[1] vsftpd 2.3.4 - Backdoor Command Execution

[bold green]GPT Analysis:[/bold green]
───────────────────────────────────────────────────
│ # Vulnerability Assessment                       │
│                                                   │
│ ## Target                                         │
│ - **Service**: vsftpd 2.3.4                       │
│ - **Exploit**: vsftpd 2.3.4 - Backdoor Command Execution │
│                                                   │
│ ## Analysis                                       │
│ This vulnerability exists due to a backdoor in vsftpd 2.3.4. │
│ When a username containing the string `:)` is provided, │
│ a backdoor is triggered that opens shell on port 6200. │
│                                                   │
│ ## Execution Instructions                         │
│                                                   │
│ 1. Check if the backdoor is active:              │
│    ```                                            │
│    nc -v <TARGET_IP> 21                           │
│    ```                                            │
│                                                   │
│ 2. Run the exploit:                               │
│    ```                                            │
│    msfconsole -q                                  │
│    use exploit/unix/ftp/vsftpd_234_backdoor      │
│    set RHOSTS <TARGET_IP>                         │
│    run                                            │
│    ```                                            │
│                                                   │
│ ## Expected Outcome                               │
│ Root access to the system.                        │
│                                                   │
│ ## Post-Exploitation Steps                        │
│ 1. Check permissions: `id` and `whoami`           │
│ 2. Look for sensitive files in `/etc/passwd`, `/etc/shadow` │
│ 3. Check for lateral movement opportunities       │
───────────────────────────────────────────────────
```

### Port-Focused Scanning and Exploitation / סריקה וניצול ממוקדי-פורט

RedFlow now supports port-focused scanning and exploitation, allowing you to:
RedFlow כעת תומך בסריקה וניצול ממוקדי-פורט, המאפשרים לך:

- **Target specific ports**: Focus on a particular port for faster and more efficient scanning
- **Automatic exploitation flow**: Automatically move to the exploitation phase after discovering a specific port is open
- **Interactive exploit selection**: Choose from available exploits for the identified service on the specified port
- **Service-specific enumeration**: Run only the enumeration modules relevant to the service on the specified port

***

- **מיקוד בפורטים ספציפיים**: התמקדות בפורט מסוים לסריקה מהירה ויעילה יותר
- **זרימת ניצול אוטומטית**: מעבר אוטומטי לשלב הניצול לאחר גילוי שפורט ספציפי פתוח
- **בחירת exploit אינטראקטיבית**: בחירה מתוך exploits זמינים עבור השירות שזוהה בפורט שצוין
- **תשאול ספציפי לשירות**: הפעלת רק מודולי התשאול הרלוונטיים לשירות בפורט שצוין

#### Examples / דוגמאות

```bash
# Scan and focus on FTP service (port 21)
# סריקה והתמקדות בשירות FTP (פורט 21)
python redflow.py --target 10.0.2.4 --port 21

# Scan and focus on HTTP service (port 80)
# סריקה והתמקדות בשירות HTTP (פורט 80)
python redflow.py --target 10.0.2.4 --port 80 --interactive

# Scan and focus on SSH service (port 22)
# סריקה והתמקדות בשירות SSH (פורט 22)
python redflow.py --target 10.0.2.4 --port 22
```

## GUI Interface / ממשק GUI

RedFlow also includes a graphical user interface (GUI) that allows for easier tool usage.

RedFlow כולל גם ממשק משתמש גרפי (GUI) המאפשר שימוש נוח יותר בכלי.

### Starting the GUI / הפעלת ה-GUI

```bash
python redflow_gui.py
```

### GUI Features / תכונות ה-GUI

- **User-friendly Interface**: Simple and easy-to-understand interface presenting all options visually.
- **Parameter Configuration**: Easy setup of all scan parameters using text boxes and checkboxes.
- **Real-time Results Display**: View scan progress and results in real-time.
- **Multiple Scan Management**: Ability to manage multiple scans concurrently.
- **Result Exports**: Export scan results to various formats (JSON, PDF, HTML).
- **Configuration Saving**: Save common settings for reuse.

---

- **ממשק ידידותי למשתמש**: ממשק פשוט וקל להבנה המציג את כל האפשרויות בצורה ויזואלית.
- **הגדרת פרמטרים**: הגדרה קלה של כל פרמטרי הסריקה באמצעות תיבות טקסט ותיבות סימון.
- **הצגת תוצאות בזמן אמת**: צפייה בהתקדמות הסריקה ובתוצאות בזמן אמת.
- **ניהול סריקות מרובות**: אפשרות לנהל מספר סריקות במקביל.
- **ייצוא תוצאות**: ייצוא תוצאות הסריקה לפורמטים שונים (JSON, PDF, HTML).
- **שמירת תצורות**: שמירת הגדרות נפוצות לשימוש חוזר.

![GUI Example Screen](docs/images/gui_example.png)

## Configuration File / קובץ תצורה

RedFlow also supports using a configuration file for advanced parameter settings. You can create a `config.yaml` file in the project's root directory:

RedFlow תומך גם בשימוש בקובץ תצורה להגדרת פרמטרים מתקדמים. ניתן ליצור קובץ `config.yaml` בתיקיית הבסיס של הפרויקט:

```yaml
# Configuration file example / דוגמה לקובץ תצורה
tools:
  nmap: /usr/bin/nmap
  gobuster: /usr/bin/gobuster
  searchsploit: /usr/bin/searchsploit

scripts:
  custom_scan: /path/to/custom_script.py

gpt:
  api_key: "YOUR_API_KEY_HERE"
  model: "gpt-4"
  temperature: 0.7
  custom_prompt: "Examine scan results and find vulnerabilities"
  
file_operations:
  extensions_to_download: [".txt", ".php", ".html", ".xml", ".conf", ".bak", ".old", ".sql", ".db"]
  max_file_size: 10485760  # 10MB
  recursive_depth: 3
```

## System Requirements / דרישות מערכת

This project requires the following tools to be installed:
פרויקט זה מחייב את הכלים הבאים להיות מותקנים:

- nmap
- enum4linux
- hydra
- gobuster
- whois
- dig/nslookup
- theHarvester
- Sublist3r
- whatweb
- wafw00f
- searchsploit
- ftputil (Python package: `pip install ftputil`)

## Support / קבלת תמיכה

If you encounter issues or have questions, please create a [new Issue](https://github.com/papadoc007/RedFlow/issues) in the GitHub repository.

אם אתה נתקל בבעיות או יש לך שאלות, אנא צור [Issue חדש](https://github.com/papadoc007/RedFlow/issues) במאגר ה-GitHub.

## Contributing / תרומה לפרויקט

We welcome contributions to the project! Please follow these steps:
אנחנו מעודדים תרומות לפרויקט! אנא עקוב אחר השלבים הבאים:

1. Fork the repository / Fork את המאגר
2. Create a branch for the new feature / צור ענף (branch) עבור התכונה החדשה
3. Make your changes / בצע את השינויים שלך
4. Submit a Pull Request / שלח Pull Request

## License / רישיון

MIT 

## Recent Updates / עדכונים אחרונים

In the latest release, the following improvements have been made / בגרסה האחרונה בוצעו השיפורים הבאים:

1. **Added GPT Exploit Advisor** - New AI-powered feature for detailed vulnerability analysis and exploitation guidance
   / **נוסף יועץ ניצול GPT** - תכונה חדשה מבוססת בינה מלאכותית לניתוח מפורט של פגיעויות והדרכת ניצול

2. **Fixed exploit execution issues** - Exploits are now attempted twice automatically if they fail the first time
   / **תוקנו בעיות בהרצת אקספלויטים** - אקספלויטים כעת מנסים לרוץ פעמיים אוטומטית אם נכשלים בפעם הראשונה

3. **Improved recursive directory scanning** - The recursive directory scanner now uses optimized scanning depths and improved performance
   / **שיפור בסריקת תיקיות רקורסיבית** - הסורק הרקורסיבי כעת משתמש בעומקי סריקה מותאמים וביצועים משופרים

4. **Enhanced Metasploit integration** - Better feedback and retry mechanisms for Metasploit exploits
   / **שיפור אינטגרציה עם Metasploit** - משוב טוב יותר ומנגנוני ניסיון נוסף למודולים של Metasploit

5. **Improved GUI results display** - Results are now displayed with better formatting and color-coding in the GUI
   / **שיפור תצוגת תוצאות בממשק הגרפי** - התוצאות כעת מוצגות עם עיצוב טוב יותר וקידוד צבעים בממשק הגרפי

6. **New interactive menu interface** - Added a step-by-step guided menu interface for easier tool usage
   / **ממשק תפריט אינטראקטיבי חדש** - נוסף ממשק תפריט מונחה שלב-אחר-שלב לשימוש קל יותר בכלי

7. **Special handling for problematic exploits** - Added custom handlers for known problematic exploits like vsftpd 2.3.4
   / **טיפול מיוחד לאקספלויטים בעייתיים** - נוספו מטפלים מותאמים לאקספלויטים בעייתיים ידועים כמו vsftpd 2.3.4

8. **Added support for custom GPT prompts** - Users can now define custom GPT system prompts in the configuration file
   / **נוספה תמיכה בפרומפטים מותאמים אישית ל-GPT** - משתמשים יכולים כעת להגדיר פרומפטים מותאמים אישית לGPT בקובץ התצורה

9. **Advanced GPT parameter control** - Fine-tune GPT model behavior with parameters like temperature, token limits, and more
   / **בקרת פרמטרים מתקדמת ל-GPT** - כוונון עדין של התנהגות מודל GPT עם פרמטרים כמו טמפרטורה, מגבלות תווים ועוד

### Using the new menu interface / שימוש בממשק התפריט החדש

To use the new interactive menu interface, simply run:
כדי להשתמש בממשק התפריט האינטראקטיבי החדש, פשוט הרץ:

```bash
python redflow.py --menu
```

This will guide you through a step-by-step process to:
זה ינחה אותך בתהליך שלב-אחר-שלב:

1. Select target type (IP address or domain)
2. Choose specific port or scan all ports
3. Select scan mode (passive, active, full, or quick)
4. Configure additional options (including enabling GPT Exploit Advisor)

The menu provides a more user-friendly way to use RedFlow, especially for new users.
התפריט מספק דרך ידידותית יותר להשתמש ב-RedFlow, במיוחד למשתמשים חדשים.

### Using the GPT Exploit Advisor / שימוש ביועץ ניצול GPT

The GPT Exploit Advisor can be used in several ways:

1. **After completing a scan**:
   ```bash
   python redflow.py --gpt-advisor
   ```

2. **During initial scan**:
   ```bash
   python redflow.py --target example.com --gpt-advisor
   ```

3. **From the interactive menu** - Select the GPT Exploit Advisor option when prompted.

This powerful feature provides detailed, AI-generated guidance on exploiting discovered vulnerabilities, with step-by-step instructions tailored to your specific target.

---

ניתן להשתמש ביועץ ניצול GPT במספר דרכים:

1. **לאחר השלמת סריקה**:
   ```bash
   python redflow.py --gpt-advisor
   ```

2. **במהלך סריקה ראשונית**:
   ```bash
   python redflow.py --target example.com --gpt-advisor
   ```

3. **מהתפריט האינטראקטיבי** - בחר באפשרות "יועץ ניצול GPT" כאשר תתבקש.

תכונה חזקה זו מספקת הדרכה מפורטת, מבוססת בינה מלאכותית, לניצול פגיעויות שהתגלו, עם הוראות שלב-אחר-שלב המותאמות למטרה הספציפית שלך. 