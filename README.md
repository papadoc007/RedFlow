# RedFlow - כלי אוטומטי לסריקת וניצול פגיעויות

RedFlow הוא כלי פייתון מבוסס ממשק פקודות המאפשר אוטומציה של השלבים הראשונים בבדיקות חדירה וסריקת אבטחה.

## תכונות עיקריות

- סריקת מטרה לפי כתובת IP או דומיין
- זיהוי פורטים פתוחים ושירותים
- בדיקות אוטומטיות לשירותים נפוצים (FTP, SSH, HTTP, SMB)
- זיהוי פגיעויות וניצול אינטראקטיבי
- אינטגרציה עם searchsploit למציאת מנגנוני ניצול
- יועץ ניצול מבוסס GPT להערכה חכמה של פגיעויות
- אפשרות להתמקד בפורט ספציפי לסריקה וניצול
- גילוי והורדת קבצים משירותי רשת

## התקנה

```bash
# קלון המאגר
git clone https://github.com/papadoc007/RedFlow.git

# כניסה לתיקיית הפרויקט
cd RedFlow

# התקנת התלויות
pip install -r requirements.txt

# התקנת תלויות נוספות (אופציונלי)
pip install ftputil   # לטיפול בקבצי FTP
```

## שימוש בסיסי

```bash
# סריקה בסיסית של מטרה
python redflow.py --target example.com

# סריקה עם התמקדות בפורט ספציפי
python redflow.py --target 192.168.1.10 --port 21

# חיפוש פגיעויות בשירות ספציפי
python redflow.py --search-exploits vsftpd:2.3.4

# הפעלת יועץ ה-GPT לניתוח פגיעויות
python redflow.py --target 10.0.2.4 --gpt-advisor
```

## דוגמאות שימוש נפוצות

1. **סריקה פסיבית בלבד**:
   ```bash
   python redflow.py --target example.com --mode passive
   ```

2. **סריקה מלאה עם אינטראקציה**:
   ```bash
   python redflow.py --target 192.168.1.10 --interactive
   ```

3. **הצגת תפריט ניצול עבור שירותים שהתגלו**:
   ```bash
   python redflow.py --exploit-menu
   ```

4. **ניצול שירות ספציפי**:
   ```bash
   python redflow.py --service-to-exploit vsftpd --port-to-exploit 21
   ```

## פרמטרים עיקריים

| פרמטר | תיאור | דוגמה |
|-------|-------|-------|
| `--target`, `-t` | כתובת IP או דומיין של המטרה | `--target example.com` |
| `--mode`, `-m` | מצב סריקה (passive/active/full) | `--mode passive` |
| `--port`, `-p` | התמקדות בפורט ספציפי | `--port 21` |
| `--output`, `-o` | נתיב לתיקיית הפלט | `--output ./my_scans/` |
| `--interactive`, `-i` | הפעלה אינטראקטיבית | `--interactive` |
| `--exploit-menu` | תפריט ניצול לשירותים שהתגלו | `--exploit-menu` |
| `--gpt-advisor` | יועץ ניצול מבוסס GPT | `--gpt-advisor` |

לקבלת מידע על כל האפשרויות, הרץ:
```bash
python redflow.py --help
```

**הערה**: כלי זה נועד למטרות חוקיות בלבד, כגון בדיקות אבטחה ובדיקות חדירה מורשות. 