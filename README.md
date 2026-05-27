# SecureGuard Antivirus

Este proyecto contiene la landing page de un antivirus profesional para usuarios y empresas.

## Archivos incluidos

- `index.html`: Página principal con diseño profesional de antivirus.
- `styles.css`: Estilos modernos y responsivos.
- `README.md`: Información del proyecto.
- `SecureGuard-Demo.txt`: archivo de descarga demo para el instalador ficticio.

## Cómo usarlo

1. Extrae el archivo `ciberseguridad.zip` si lo estás descargando desde otro equipo.
2. Abre `index.html` en tu navegador para ver el sitio.
3. Para editarlo, usa un editor como Visual Studio Code o cualquier editor HTML/CSS.
4. Abre `index.html`, haz clic en “Iniciar escaneo” para ver la demo de antivirus y usa “Descargar demo” para obtener el archivo de demostración.
5. Para probar el prototipo de escaneo, instala Python 3 y ejecuta:
   ```bash
   python antivirus_demo.py scan .
   ```
6. Para publicar en GitHub Pages, sube los archivos a un repositorio GitHub y habilita Pages desde `Settings > Pages`.

## Prototipo de escáner

- `antivirus_demo.py`: escáner básico que busca firmas en los archivos de una carpeta.
- `signatures.txt`: patrones de prueba utilizados por el prototipo.
- `quarantine/`: carpeta donde se copia un archivo detectado durante el escaneo.

> Este prototipo es educativo y demuestra cómo funciona un escáner de firmas. No es un antivirus real.

## Recomendación de software profesional

- Visual Studio Code: https://code.visualstudio.com/
- GitHub Desktop: https://desktop.github.com/
- Google Chrome o Microsoft Edge para vista previa.

## Nota

Esta es una página web profesional para un producto antivirus. No es un software antivirus ejecutable.
