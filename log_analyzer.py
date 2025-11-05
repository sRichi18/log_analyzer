import os
import re
import sys
import json
import argparse
from datetime import datetime
from colorama import Fore, Style, init

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
        

def main():
    parser = argparse.ArgumentParser(
        description="🔍 Log Security Analyzer - Analiza archivos de logs en busca de eventos sospechosos."
    )
    parser.add_argument("--file", "-f", help="Ruta del archivo de log a analizar.")
    parser.add_argument("--out", "-o", help="Nombre del archivo JSON de salida (opcional).")
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
    

if __name__ == "__main__":
    main()