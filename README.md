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
- Wordlist and attack method selection via simple CLI or GUI
- Analysis of each tool's output
- Context-aware help for understanding outputs and common error messages
- Default path detection for wordlists/tools/scripts in Kali Linux
- GPT integration for advanced analysis and recommendations

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
- אפשרות לבחירת רשימות מילים ושיטות תקיפה באמצעות ממשק CLI פשוט או GUI
- ניתוח פלט של כל כלי
- עזרה מבוססת-הקשר להבנת פלטים והודעות שגיאה נפוצות
- זיהוי ושימוש בנתיבי ברירת מחדל של רשימות מילים/כלים/סקריפטים מסביבת Kali Linux
- תמיכה ב-GPT לניתוח ממצאים והמלצות מתקדמות

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
                 [--port-to-exploit PORT_TO_EXPLOIT] [--service-to-exploit SERVICE_TO_EXPLOIT]
```

| Parameter | Shortcut | Description | Default | Example |
|-----------|----------|-------------|---------|---------|
| `--target` | `-t` | IP address or domain of the target | (Required) | `--target example.com` |
| `--mode` | `-m` | Scan mode (`passive` / `active` / `full`) | `full` | `--mode passive` |
| `--port` | `-p` | Focus on a specific port for scanning and exploitation | | `--port 21` |
| `--output` | `-o` | Path to output directory | `./scans/` | `--output ./my_scans/` |
| `--interactive` | `-i` | Request confirmation before proceeding to next step | `False` | `--interactive` |
| `--gpt` | | Use GPT-4 for recommendations (requires API key) | `False` | `--gpt` |
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

---

| פרמטר | קיצור | תיאור | ערך ברירת מחדל | דוגמה |
|-------|-------|-------|----------------|-------|
| `--target` | `-t` | כתובת IP או דומיין של המטרה | (חובה) | `--target example.com` |
| `--mode` | `-m` | מצב סריקה (`passive` / `active` / `full`) | `full` | `--mode passive` |
| `--port` | `-p` | התמקדות בפורט ספציפי לסריקה ולניצול | | `--port 21` |
| `--output` | `-o` | נתיב לתיקיית הפלט | `./scans/` | `--output ./my_scans/` |
| `--interactive` | `-i` | בקשת אישור לפני המשך לשלב הבא | `False` | `--interactive` |
| `--gpt` | | שימוש ב-GPT-4 לקבלת המלצות (דורש מפתח API) | `False` | `--gpt` |
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

***

- **זיהוי פגיעויות**: מזהה באופן אוטומטי פגיעויות בשירותים שהתגלו.
- **חיפוש מנגנוני ניצול**: מחפש מנגנוני ניצול באמצעות searchsploit בהתבסס על מידע גרסת השירות.
- **תפריט ניצול אינטראקטיבי**: מספק תפריט אינטראקטיבי לבחירה וניצול פגיעויות.
- **אפשרויות חיפוש מותאמות אישית**: מאפשר למשתמשים להזין מונחי חיפוש מותאמים אישית בעת חיפוש אחר exploits.
- **בחירת exploit**: מציג רשימה ממוספרת של exploits זמינים לבחירה קלה.
- **הכנת מנגנוני ניצול**: מכין באופן אוטומטי מנגנוני ניצול להרצה על ידי העתקה והגדרה שלהם.

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