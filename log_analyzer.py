import os
import re
import sys
import json
import argparse
from datetime import datetime
from colorama import Fore, Style, init

#--------------------------------------
#Librerias para generar un reporte PDF.
#--------------------------------------
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from reportlab.lib import colors
from reportlab.lib.units import inch
#--------------------------------------

#--------------------------------------
#Log analyzer
#--------------------------------------
init(autoreset=True)

"""Valida si la ruta del archivo de logs existe"""
def validate_file_path(path: str) -> bool:
    return os.path.isfile(path)

"""Leer el archivo de logs linea a linea"""
def read_log_file(path: str) -> list[str]:
    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            return f.readlines()
    except Exception as e:
        print(Fore.RED + f"[ERROR] No se pudo leer el archivo {e}")
        sys.exit(1)

"""Analiza las lineas buscando patrones maliciosos"""
def analyze_log(lines: list[str]) -> dict:
    suspicious_patterns = {
        "failed_login": re.compile(r"failed", re.IGNORECASE),
        "unauthorized": re.compile(r"unauthorized", re.IGNORECASE),
        "denied": re.compile(r"denied", re.IGNORECASE),
        "error": re.compile(r"error", re.IGNORECASE),
    }

    results = {key: [] for key in suspicious_patterns.keys()}

    for i, line in enumerate(lines, start=1):
        for label, pattern in suspicious_patterns.items():
            if pattern.search(line):
                results[label].append({"line": i, "content": line.strip()})
    
    return results

"""Guarda los resultados en un JSON"""
def save_to_json(result: dict, output_file: str):
    try:
        with open(output_file, "w", encoding='utf-8') as f:
            json.dump(result, f, indent=4, ensure_ascii=False)
        print(Fore.GREEN + f"Resultados guardados en {output_file}")
    except Exception as e:
        print(Fore.RED + f"[ERROR] No se pudo guardar el archivo: {e}")
        
#-----------------------------------------
#Generar reporte PDF.
#-----------------------------------------

def generate_pdf_report(results: dict, source_file: str, output_pdf: str):
    c = canvas.Canvas(output_pdf, pagesize=A4)
    widht, height = A4
    y = height - 100
    
    #Encabezado
    c.setFont("Helvetica-Bold", 16)
    c.setFillColor(colors.darkblue)
    c.drawString(50, y, "Log Security Analyzer Report")
    c.setFillColor(colors.black)
    y -= 25
    c.setFont("Helvetica", 11)
    c.drawString(50, y, f"Archivo analizado: {source_file}")
    y -= 15
    c.drawString(50, y, f"Fecha de generacion: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    y -= 25
    
    #Eventos sospechosos totales
    total = sum(len(v) for v in results.values())
    c.setFont("Helvetica-Bold", 12)
    c.drawString(50, y, f"Eventos sospechosos totales: {total}")
    y -= 25
    
    #Conteo por categoria
    c.setFont("Helvetica-Bold", 11)
    for category, matches in results.items():
        c.drawString(70, y, f"* {category.replace('_', ' ').capitalize()}: {len(matches)}")
        y -= 15
    y -= 20
    
    #Detalles
    c.setFont("Helvetica-Bold", 12)
    c.drawString(50, y, "Detalles de eventos:")
    y -= 20
    c.setFont("Helvetica", 10)
    
    for category, matches in results.items():
        if not matches:
            continue
        c.setFont("Helvetica", 9)
        for event in matches:
            text = f"Linea {event['line']}: {event['content'][:100]}"
            c.drawString(80, y, text)
            y -= 11
            if y < 100:  #Salto de pagina
                c.showPage()
                y = height - 80
                c.setFont("Helvetica", 9)
    
    c.save
    print(Fore.GREEN + f"Reporte PDF generado: {output_pdf}")

def main():
    parser = argparse.ArgumentParser(
        description="🔍 Log Security Analyzer - Analiza archivos de logs en busca de eventos sospechosos."
    )
    parser.add_argument("--file", "-f", help="Ruta del archivo de log a analizar.")
    parser.add_argument("--out", "-o", help="Nombre del archivo JSON de salida (opcional).")
    parser.add_argument("--pdf", action="store_true", help="Genera un reporte PDF a demas de JSON.")
    args = parser.parse_args()

    print(Fore.CYAN + "\n=== Log Security Analyzer ===\n")

    if not args.file:
        log_path = input("Introduce la ruta del archivo de log: ").strip()
    else:
        log_path = args.file

    if not validate_file_path(log_path):
        print(Fore.RED + f"[ERROR] No se encontró el archivo: {log_path}")
        sys.exit(1)

    lines = read_log_file(log_path)
    print(Fore.YELLOW + f"Analizando {len(lines)} líneas...")

    results = analyze_log(lines)
    total_events = sum(len(v) for v in results.values())

    print(Fore.GREEN + f"✅ Se encontraron {total_events} eventos sospechosos.\n")

    out_file = args.out or f"log_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    save_to_json(results, out_file)
    
    if args.pdf:
        pdf_name = os.path.splitext(out_file)[0] + ".pdf"
        generate_pdf_report(results, log_path, pdf_name)
        
if __name__ == "__main__":
    main()