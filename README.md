# RedFlow - כלי אוטומטי מתקדם לאיסוף מידע ותקיפה לסביבת Kali Linux

RedFlow הוא כלי Python מבוסס-CLI (עם אפשרות להרחבות GUI) שמאפשר אוטומציה של השלבים המוקדמים בבדיקות חדירות.

## תכונות עיקריות

- קבלת כתובת IP או דומיין כמטרה
- ביצוע איסוף מידע פסיבי ואקטיבי
- זיהוי פורטים פתוחים ושירותים
- המלצה או הפעלה אוטומטית של כלי תקיפה המתאימים (למשל Gobuster, Enum4linux, Hydra)
- אפשרות לבחירת רשימות מילים ושיטות תקיפה באמצעות ממשק CLI פשוט או GUI
- ניתוח פלט של כל כלי
- עזרה מבוססת-הקשר להבנת פלטים והודעות שגיאה נפוצות
- זיהוי ושימוש בנתיבי ברירת מחדל של רשימות מילים/כלים/סקריפטים מסביבת Kali Linux

## התקנה

```bash
pip install -r requirements.txt
```

## שימוש

```bash
python redflow.py --target example.com --mode full --output ./scans/ --interactive
```

### פרמטרים

- `--target`: כתובת IP או דומיין של מטרה
- `--mode`: סוג הסריקה (passive / active / full)
- `--output`: נתיב לתיקיית הפלט (ברירת מחדל: ./scans/)
- `--interactive`: בקשת אישור לפני המשך לשלב הבא
- `--gpt`: שימוש ב-GPT-4 לקבלת המלצות (אופציונלי, דורש מפתח API)

## דרישות מערכת

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

## רישיון

MIT 