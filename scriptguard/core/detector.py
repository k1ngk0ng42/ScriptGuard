import chardet

def detect_script(data: bytes):
    """
    Определяет язык скрипта (VBA, PowerShell, JavaScript или Unknown)
    и возвращает текст и confidence score (0–1).
    """
    # Декодируем байты
    try:
        enc = chardet.detect(data)["encoding"] or "utf-8"
        text = data.decode(enc, errors="ignore")
    except Exception:
        text = data.decode("utf-8", errors="ignore")

    # Словари ключевых слов для каждого языка
    vba_keywords = ["Sub AutoOpen", "Sub Document_Open", "CreateObject", "Dim ", "ActiveDocument", "ThisWorkbook"]
    ps_keywords = ["powershell", "-enc", "Invoke-Expression", "New-Object", "Get-Content", "Set-Content"]
    js_keywords = ["function", "eval(", "var ", "let ", "const ", "document.", "window.", "console.log"]

    # Функция для подсчёта совпадений и confidence
    def calc_confidence(keywords, text):
        matches = sum(1 for k in keywords if k.lower() in text.lower())
        return min(1.0, matches / len(keywords))  # confidence от 0 до 1

    # Проверяем VBA
    vba_conf = calc_confidence(vba_keywords, text)
    if vba_conf > 0.3:
        return "VBA", text, vba_conf

    # Проверяем PowerShell
    ps_conf = calc_confidence(ps_keywords, text)
    if ps_conf > 0.3:
        return "PowerShell", text, ps_conf

    # Проверяем JavaScript
    js_conf = calc_confidence(js_keywords, text)
    if js_conf > 0.3:
        return "JavaScript", text, js_conf

    # Если ничего не подошло
    return "Unknown", text, 0.0
