# SecureGuard Antivirus

SecureGuard Antivirus es un proyecto realista de prototipo en Python para detección por firmas, cuarentena y generación de informes.

## Archivos incluidos

- `index.html`: Página principal con diseño profesional de antivirus.
- `styles.css`: Estilos modernos y responsivos.
- `README.md`: Documentación del proyecto.
- `antivirus_demo.py`: entrypoint del escáner de SecureGuard.
- `signatures.txt`: base de firmas de detección.
- `secureguard/`: paquete Python con lógica de escaneo, heurística y cuarentena.
- `pyproject.toml`: configuración de paquete Python.

## Cómo usarlo

### Requisitos

- Python 3.8 o superior

### Instalación opcional

Desde la carpeta del proyecto:

```bash
python -m pip install -e .
```

### Ejecución directa

```bash
python antivirus_demo.py scan .
```

### Ejecución como paquete

```bash
python -m secureguard.cli scan .
```

### Comandos disponibles

- `python antivirus_demo.py scan <directorio>`: escanea la carpeta indicada.
- `python antivirus_demo.py scan . --verbose`: muestra detalles de detección.
- `python antivirus_demo.py signatures`: lista las firmas cargadas.
- `python antivirus_demo.py version`: muestra la versión del proyecto.

## Proyecto real

Este proyecto incluye:

- detección basada en firmas con carga desde `signatures.txt`
- heurísticas de archivos sospechosos por extensión y tamaño
- cuarentena automática de archivos detectados
- informe de resultados en `scan-report.txt`
- estructura de paquete Python para desarrollo y publicación

## Cómo añadir firmas

Edita `signatures.txt` y agrega una firma por línea.

## Notas importantes

- Este proyecto es un prototipo de seguridad, no un antivirus certificado.
- La detección se basa en patrones de firma y heurísticas básicas.
- Para convertirlo en un producto comercial se necesitan pruebas de seguridad, firma de código y motor especializado.
