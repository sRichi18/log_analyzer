Herramienta educativa desarrollada en **Python** para el análisis de archivos de logs del sistema (Windows o Linux).  
Detecta **eventos sospechosos** como intentos fallidos de acceso, errores, denegaciones o autenticaciones no autorizadas, y genera un **reporte estructurado en JSON y PDF**.

> ⚠️ Este proyecto está destinado a fines educativos y pruebas controladas en entornos propios o autorizados.


## 🎯 **Objetivos del proyecto**

- Practicar el análisis de logs en sistemas reales.  
- Identificar eventos críticos y patrones sospechosos mediante **expresiones regulares (RegEx)**.  
- Automatizar reportes técnicos en formatos **JSON y PDF**.  
- Aplicar buenas prácticas de programación, documentación y ética profesional.

---

## ⚙️ **Requisitos**

- Python **3.8 o superior**  
- Librerías necesarias (instalar con `pip install -r requirements.txt`)

---

- Uso básico

1️⃣ Ejecución interactiva

> python log_analyzer.py

El programa solicitará:

> Introduce la ruta del archivo de log: logs/test.log

> Analizando eventos sospechosos...

> ✅ Se encontraron 12 eventos críticos.

> 💾 Resultados guardados en log_analysis_20251104_183012.json

> 📄 Reporte PDF generado: log_analysis_20251104_183012.pdf 

---

2️⃣ Ejecución directa (CLI)

> python log_analyzer.py --file logs/test.log --pdf

o bien

> python log_analyzer.py --file logs/test.log --out resultados.json --pdf

---

🧩 Conocimientos aplicados

- Python intermedio (lectura de archivos, regex, CLI, JSON).
- Librerías: reportlab, colorama, argparse, re.
- Fundamentos de ciberseguridad: detección de eventos, auditoría de logs, ética profesional.
- Documentación y control de versiones con Git y GitHub.
