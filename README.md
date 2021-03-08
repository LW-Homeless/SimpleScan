# SimpleScam
SimpleScan herramienta para realizar escaneo de puertos tcp. La herramienta realiza escneos de tipo Stealth scan, Connect scan y Acknowledgement scan (ACK scan).

# Requisitos
- Python 3.7.x o superior.
- setuptools.
- Npcap ( se puede descarga desde: https://nmap.org/npcap/ )

# Dependencias
- colorama==0.4.4
- et-xmlfile==1.0.1
- jdcal==1.4.1
- openpyxl==3.0.5
- scapy==2.4.4
- tabulate==0.8.7

# Instruciones de uso

- Descarga o clone el repositorio.
- Instale las dependencia con el siguiente comando.

```
pip install -r requirements.txt
```
- Descargue y instale Npcap (ver requisitos)
- Luego, ejecute el archivo Simplescan.py con el siguiente comando.

```
python SimpleScan.py -t 127.0.0.1
```
# Opciones de SimpleScan
SimpleScan realiza por defecto un escaneo de tipo Stealth scan a los primeros 1.000 puertos.

Para realizar un escaneo por defecto se debe ejecutar el siguiente comando:
```
python SimpleScan.py -t 127.0.0.1
```
Donde, la IP 127.0.0.1 debe ser reemplazada por la IP que se desea escanear.

# Otras opciones de escaneo
-sC : Realiza un escaner de tipo Connect scan.  
-sA : Realiza un escaneo de tipo ACK scan.  
-sS : Realiza un escaneo de tipo Stealth scan.

# Especificación de puertos:
-p [puerto]:  Escanea un puerto específico.  
-p [puerto, puerto, puerto]:  Escanea un conjunto de puertos especificos separados por coma.  
-p [puerto-puerto]:  Escanea un intervalo de puertos.

# Especificación objeto a escanear
-t  [IP] :  Direccion IP del objetivo a escanear.

# Ejemplos:
Escaneo por defecto:
```
python SimpleScan.py -t 127.0.0.1
```
Escaneo a un puerto específico.
```
python SimpleScan.py -sS -p 80 -t 127.0.0.1
```
Escaneo a un intervalo de puertos.
```
python SimpleScan.py -sS -p 0-500 -t 127.0.0.1
```
Escaneo a puertos especificos e intervalos de puertos.
```
python SimpleScan.py -sS -p 21,22,53,445,455-500 -t 127.0.0.1
```
# Video demostración 
![alt text](https://github.com/LW-Homeless/Whois/blob/master/simplescan.gif)
