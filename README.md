# RedFlow - Advanced Automated Information Gathering and Attack Tool for Kali Linux
# RedFlow - כלי אוטומטי מתקדם לאיסוף מידע ותקיפה לסביבת Kali Linux

RedFlow is a CLI-based Python tool (with optional GUI capabilities) that automates the early stages of penetration testing.
RedFlow הוא כלי Python מבוסס-CLI (עם אפשרות להרחבות GUI) שמאפשר אוטומציה של השלבים המוקדמים בבדיקות חדירות.

## Key Features / תכונות עיקריות

- Target specification by IP address or domain
- Passive and active information gathering
- Open port and service identification
- Automatic recommendation or execution of appropriate attack tools (e.g., Gobuster, Enum4linux, Hydra)
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
```

## CLI Usage / שימוש בממשק CLI

Basic execution / הפעלה בסיסית:

```bash
python redflow.py --target example.com --mode full
```

### All Possible CLI Parameters / כל הפרמטרים האפשריים ב-CLI

```bash
usage: redflow.py [-h] --target TARGET [--mode {passive,active,full}] [--output OUTPUT] [--interactive] [--gpt] [--verbose] [--version]
```

| Parameter | Shortcut | Description | Default | Example |
|-----------|----------|-------------|---------|---------|
| `--target` | `-t` | IP address or domain of the target | (Required) | `--target example.com` |
| `--mode` | `-m` | Scan mode (`passive` / `active` / `full`) | `full` | `--mode passive` |
| `--output` | `-o` | Path to output directory | `./scans/` | `--output ./my_scans/` |
| `--interactive` | `-i` | Request confirmation before proceeding to next step | `False` | `--interactive` |
| `--gpt` | | Use GPT-4 for recommendations (requires API key) | `False` | `--gpt` |
| `--verbose` | `-v` | Display detailed information in logs | `False` | `--verbose` |
| `--version` | | Display software version | | `--version` |
| `--help` | `-h` | Display help | | `--help` |

---

| פרמטר | קיצור | תיאור | ערך ברירת מחדל | דוגמה |
|-------|-------|-------|----------------|-------|
| `--target` | `-t` | כתובת IP או דומיין של המטרה | (חובה) | `--target example.com` |
| `--mode` | `-m` | מצב סריקה (`passive` / `active` / `full`) | `full` | `--mode passive` |
| `--output` | `-o` | נתיב לתיקיית הפלט | `./scans/` | `--output ./my_scans/` |
| `--interactive` | `-i` | בקשת אישור לפני המשך לשלב הבא | `False` | `--interactive` |
| `--gpt` | | שימוש ב-GPT-4 לקבלת המלצות (דורש מפתח API) | `False` | `--gpt` |
| `--verbose` | `-v` | הצגת מידע מפורט בלוגים | `False` | `--verbose` |
| `--version` | | הצגת גרסת התוכנה | | `--version` |
| `--help` | `-h` | הצגת עזרה | | `--help` |

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

4. **Scan with more verbose logging**:
   ```bash
   python redflow.py --target example.com --verbose
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

4. **סריקה עם יותר מידע בלוגים**:
   ```bash
   python redflow.py --target example.com --verbose
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

scripts:
  custom_scan: /path/to/custom_script.py

gpt:
  api_key: "YOUR_API_KEY_HERE"
  model: "gpt-4"
  temperature: 0.7
  custom_prompt: "Examine scan results and find vulnerabilities"
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