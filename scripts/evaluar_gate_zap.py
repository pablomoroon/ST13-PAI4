
import json
import os
import sys
from pathlib import Path
from collections import Counter

# Informe generado por OWASP ZAP
ruta = Path("zap-reports/zap-report.json")

# 3 = High, 2 = Medium, 1 = Low
umbral = int(os.getenv("ZAP_GATE_MIN_RISK", "3"))

niveles = {
    0: "Informational",
    1: "Low",
    2: "Medium",
    3: "High",
}

if umbral not in (1, 2, 3):
    sys.exit("ERROR: Umbral no valido")

if not ruta.is_file():
    sys.exit("ERROR: No existe el informe de ZAP")

try:
    datos = json.loads(ruta.read_text(encoding="utf-8"))

    sitios = datos["site"]
    if not isinstance(sitios, list):
        raise ValueError("Formato de sitios no valido")

    hallazgos = []

    for sitio in sitios:
        for alerta in sitio.get("alerts", []):
            riesgo = int(alerta["riskcode"])

            if riesgo not in niveles:
                raise ValueError("Nivel de riesgo desconocido")

            hallazgos.append({
                "nombre": alerta.get("name", "Sin nombre"),
                "riesgo": riesgo,
                "id": alerta.get("pluginid", ""),
            })

except (ValueError, KeyError, TypeError, json.JSONDecodeError) as error:
    sys.exit(f"ERROR: Informe ZAP no valido: {error}")

conteo = Counter(h["riesgo"] for h in hallazgos)

bloqueantes = [
    h for h in hallazgos
    if h["riesgo"] >= umbral
]

lineas = [
    "RESULTADO DEL QUALITY GATE DAST",
    "================================",
    f"High: {conteo[3]}",
    f"Medium: {conteo[2]}",
    f"Low: {conteo[1]}",
    f"Informational: {conteo[0]}",
    f"Umbral configurado: {niveles[umbral]}",
    f"Hallazgos bloqueantes: {len(bloqueantes)}",
    "",
]

for h in bloqueantes:
    lineas.append(
        f"[{niveles[h['riesgo']]}] "
        f"{h['nombre']} (ID: {h['id']})"
    )

if bloqueantes:
    lineas.append("\nRESULTADO: BLOQUEADO")
else:
    lineas.append("\nRESULTADO: APROBADO")

resultado = "\n".join(lineas)

print(resultado)

Path("zap-reports/gate-resultado.txt").write_text(
    resultado, encoding="utf-8"
)

if bloqueantes:
    print("::error::Quality gate DAST bloqueado")
    sys.exit(1)

sys.exit(0)
