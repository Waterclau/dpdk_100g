# MIRA - Configuración Completa de Nodos CloudLab

## Información de Nodos

| Nodo | Hostname | IP (ens1f0) | MAC (ens1f0) | IP (ens1f1) | MAC (ens1f1) | Rol |
|------|----------|-------------|--------------|-------------|--------------|-----|
| **Monitor** | node-monitor | 10.10.1.2 | 0c:42:a1:dd:57:90 | 10.10.1.3 | 0c:42:a1:dd:57:91 | Detector DDoS |
| **Controller** | node-controller | 10.10.1.5 | 0c:42:a1:dd:57:b8 | - | 0c:42:a1:dd:57:b9 | Tráfico benigno |
| **TG** | node-tg | 10.10.1.1 | 0c:42:a1:dd:5a:48 | - | 0c:42:a1:dd:5a:49 | Tráfico de ataque |

**Directorio de trabajo:** `/local/dpdk_100g`

**Configuración de red:**
- Todos los nodos usan `ens1f0` para transmisión/recepción de tráfico DPDK
- El **node-monitor** recibe tráfico en `ens1f0` (MAC: `0c:42:a1:dd:57:90`)
- Esta MAC debe usarse como `dst-mac` en todos los PCAPs generados

**Esquema de direccionamiento IP:**
- **Nodos físicos:** `10.10.1.x`
  - node-monitor (detector): `10.10.1.2`
  - node-controller (sender benigno): `10.10.1.5`
  - node-tg (sender ataque): `10.10.1.1`
- **Clientes benignos simulados:** `10.10.2.0/24` (500 IPs)
- **Atacantes simulados:** `10.10.3.0/24` (200 IPs, red interna CloudLab)

---

## 🔧 Configuración Inicial (TODOS LOS NODOS)

### 1. Configurar Hugepages

Ejecutar en **node-monitor**, **node-controller** y **node-tg**:

```bash
# Limpiar configuración anterior
sudo rm -rf /var/run/dpdk/*
sudo rm -rf /dev/hugepages/*
sudo umount /mnt/huge 2>/dev/null

# Crear directorio y montar
sudo mkdir -p /mnt/huge
sudo mount -t hugetlbfs nodev /mnt/huge

# Asignar 2GB de hugepages (2048 páginas de 2MB)
echo 2048 | sudo tee /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages

# Verificar
grep Huge /proc/meminfo
```

**Salida esperada:**
```
HugePages_Total:    2048
HugePages_Free:     2048
Hugepagesize:       2048 kB
```

### 2. Verificar Interfaces de Red

```bash
# Listar todas las interfaces
ip addr

# Verificar estado de la interfaz DPDK
ip link show ens1f0

# Si está DOWN, levantarla
sudo ip link set ens1f0 up
```

### 3. Verificar MACs de Interfaces

```bash
# Ver MAC de ens1f0
ip link show ens1f0 | grep link/ether

# Verificar que coincida con la tabla de arriba:
# node-monitor: 0c:42:a1:dd:57:90
# node-controller: 0c:42:a1:dd:57:b8
# node-tg: 0c:42:a1:dd:5a:48
```

---

## 📦 node-monitor (Detector)

### Paso 1: Instalar Dependencias

```bash
cd /local/dpdk_100g/mira/detector_system

# Actualizar repositorios
sudo apt-get update

# Instalar DPDK y dependencias
sudo apt-get install -y dpdk dpdk-dev libdpdk-dev pkg-config build-essential
```

### Paso 2: Compilar Detector

```bash
cd /local/dpdk_100g/mira/detector_system

# Limpiar compilación anterior
make clean

# Compilar
make

# Verificar binario
ls -lh mira_ddos_detector
```

**Salida esperada:**
```
-rwxr-xr-x 1 cesteban cesteban 123K Jan 07 10:00 mira_ddos_detector
```

### Paso 3: Crear Directorio de Resultados

```bash
mkdir -p /local/dpdk_100g/mira/results
```

### Paso 4: Verificar Configuración DPDK

```bash
# Ver dispositivos DPDK
dpdk-devbind.py --status

# Verificar librería MLX5 (para Mellanox ConnectX-5)
ldconfig -p | grep mlx5
ldconfig -p | grep ibverbs

# Si faltan librerías:
sudo apt-get install -y libibverbs-dev libmlx5-1 rdma-core
```

### Paso 5: Obtener PCI Address de la NIC

```bash
# Listar dispositivos PCI Mellanox
lspci | grep -i mellanox

# Ejemplo de salida:
# 41:00.0 Ethernet controller: Mellanox Technologies MT27800 Family [ConnectX-5]
# 41:00.1 Ethernet controller: Mellanox Technologies MT27800 Family [ConnectX-5]
```

**Usar:** `0000:41:00.0` (ens1f0)

---

## 📤 node-controller (Tráfico Benigno)

### Paso 1: Instalar Dependencias Python

```bash
cd /local/dpdk_100g/mira/benign_generator

# Actualizar repositorios
sudo apt-get update

# Instalar Python y pip
sudo apt-get install -y python3 python3-pip

# Instalar Scapy
pip3 install scapy
```

### Paso 2: Generar PCAP de Tráfico Benigno

```bash
cd /local/dpdk_100g/mira/benign_generator

# Generar 10M paquetes de tráfico benigno (paralelo con todos los cores)
# Basado en patrones benignos de CICDDoS2019 dataset:
# - 50% HTTP (GET requests con responses)
# - 20% DNS (queries y responses)
# - 15% SSH (sesiones encriptadas)
# - 10% ICMP (ping)
# - 5% UDP background (NTP, SNMP)
# --cores 0 = usa todos los cores disponibles (8-16× más rápido)
# IMPORTANTE: Usar 10.10.2.0/24 para clientes (red interna CloudLab)
sudo python3 generate_benign_traffic_v2_parallel.py \
    --output ../benign_25M.pcap \
    --packets 25000000 \
    --cores 16 \
    --src-mac 00:00:00:00:00:01 \
    --dst-mac 0c:42:a1:dd:57:90 \
    --client-range 10.10.2.0/24 \
    --server-ip 10.10.1.2 \
    --clients 500

# OPCIONAL: Generar PCAP pequeño de prueba (100K paquetes, 4 cores)
sudo python3 generate_benign_traffic_v2_parallel.py \
    --output ../benign_test.pcap \
    --packets 100000 \
    --cores 4 \
    --src-mac 00:00:00:00:00:01 \
    --dst-mac 0c:42:a1:dd:57:90 \
    --client-range 10.10.2.0/24 \
    --server-ip 10.10.1.2 \
    --clients 500

# Verificar PCAP generado
ls -lh ../benign_10M.pcap
tcpdump -r ../benign_10M.pcap -c 10
ls -lh ../benign_test.pcap
tcpdump -r ../benign_test.pcap -c 10
```

**Notas importantes:**
- **Rango de IPs clientes:** `10.10.2.0/24` (red interna CloudLab para simular tráfico benigno)
- **IP servidor:** `10.10.1.2` (node-monitor)
- **MAC destino:** `0c:42:a1:dd:57:90` (ens1f0 del node-monitor)
- El parámetro `--cores 0` usa todos los cores disponibles para generación paralela (8-16× más rápido)
- Sin `--cores`, el script usa 1 core por defecto (muy lento para 10M paquetes)
- Tiempo estimado con 8 cores: ~2-3 minutos para 10M paquetes

### Paso 3: Instalar Dependencias DPDK

```bash
cd /local/dpdk_100g/mira/benign_sender

# Instalar libpcap
sudo apt-get install -y libpcap-dev pkg-config dpdk dpdk-dev
```

### Paso 4: Compilar DPDK Sender

```bash
cd /local/dpdk_100g/mira/benign_sender

# Limpiar y compilar
make clean
make

# Verificar binario
ls -lh build/dpdk_pcap_sender
```

**Salida esperada:**
```
-rwxr-xr-x 1 cesteban cesteban 89K Jan 07 10:05 build/dpdk_pcap_sender
```

### Paso 5: Verificar PCI Address

```bash
lspci | grep -i mellanox
# Usar: 0000:41:00.0 (ens1f0)
```

---

## 💥 node-tg (Tráfico de Ataque)

**IMPORTANTE:** Hay dos opciones para obtener tráfico de ataque:
- **Opción A (RECOMENDADA):** Usar dataset CICDDoS2019 real (PCAPs descargados)
- **Opción B:** Generar sintéticamente con scripts Python

---

### Opción A: Usar Dataset CICDDoS2019 Real

**NOTA:** El directorio `/proj/softmeasure-PG0` es **almacenamiento persistente** del proyecto CloudLab. Si ya trabajaste antes con el dataset, **probablemente ya esté descargado**.

#### Paso 0: Verificar si el Dataset ya Existe

```bash
cd /proj/softmeasure-PG0

# Verificar si existe el directorio CICD
ls -lh CICD/

# Verificar si hay PCAPs descargados
ls CICD/pcaps/*.pcap | wc -l

# Verificar si ya hay PCAPs remapeados
ls CICD/remapped/*.pcap 2>/dev/null | wc -l
```

**Si ves PCAPs en `CICD/pcaps/` o `CICD/remapped/`:**
- ✅ Ya tienes el dataset descargado
- ⏭️ **Salta al Paso 6** (Remapeo) o al **Paso 8** (Copiar) si ya están remapeados

**Si no existe o está vacío:**
- ⬇️ Continúa con el Paso 1 (crear directorios y descargar)

---

#### Paso 1: Preparar Directorios (solo si no existen)

```bash
# Crear estructura de carpetas en /proj (almacenamiento compartido CloudLab)
cd /proj/softmeasure-PG0
mkdir -p CICD/pcaps CICD/remapped

cd /proj/softmeasure-PG0/CICD
```

#### Paso 2: Descargar Dataset CICDDoS2019 (solo si no está descargado)

**Dataset oficial:** https://www.unb.ca/cic/datasets/ddos-2019.html

Descargar los ZIP files (desde navegador o wget):
- `PCAP-01-12_0-0249.zip`
- `PCAP-01-12_0250-0499.zip`
- `PCAP-01-12_0500-0749.zip`
- `PCAP-01-12_0750-0818.zip`

```bash
cd /proj/softmeasure-PG0/CICD

# Verificar que los ZIP están descargados
ls *.zip
```

#### Paso 3: Descomprimir PCAPs

```bash
cd /proj/softmeasure-PG0/CICD

# Descomprimir todos los ZIP hacia pcaps/
unzip -o PCAP-01-12_0-0249.zip -d pcaps
unzip -o PCAP-01-12_0250-0499.zip -d pcaps
unzip -o PCAP-01-12_0500-0749.zip -d pcaps
unzip -o PCAP-01-12_0750-0818.zip -d pcaps

# Si quedan subcarpetas, aplanar:
cd /proj/softmeasure-PG0/CICD/pcaps
find . -type f -maxdepth 2 -print
```

#### Paso 4: Arreglar Ficheros sin Extensión .pcap

```bash
cd /proj/softmeasure-PG0/CICD/pcaps

# Añadir .pcap a ficheros sin extensión
find . -maxdepth 1 -type f ! -name "*.pcap" -exec bash -lc 'mv "$1" "$1.pcap"' _ {} \;

# Comprobar
ls *.pcap | wc -l
ls | head -20
```

#### Paso 5: Instalar Herramientas de Remapeo

```bash
# Instalar tcprewrite y tshark
sudo apt-get update
sudo apt-get install -y tcpreplay tshark parallel pv
```

#### Paso 6: Remapear IPs y MACs (CRÍTICO)

**Parámetros de remapeo:**
- **IPs origen (atacantes):** `0.0.0.0/0` → `10.10.3.0/24` (red interna CloudLab)
- **IP destino (víctima):** `0.0.0.0/0` → `10.10.1.2` (node-monitor)
- **MAC origen:** `00:00:00:00:00:02` (genérica para ataques)
- **MAC destino:** `0c:42:a1:dd:57:90` (ens1f0 del node-monitor)

```bash
cd /proj/softmeasure-PG0/CICD/pcaps

# Remapear bloque de ficheros (ejemplo: 05xx a 08xx) en paralelo
# Usa 16 cores para acelerar el proceso
ls SAT-01-12-2018_05*.pcap SAT-01-12-2018_06*.pcap SAT-01-12-2018_07*.pcap SAT-01-12-2018_08*.pcap \
| pv -l \
| parallel -j16 '
  sudo tcprewrite \
    --infile {} \
    --outfile ../remapped/{} \
    --srcipmap=0.0.0.0/0:10.10.3.0/24 \
    --dstipmap=0.0.0.0/0:10.10.1.2 \
    --enet-smac=00:00:00:00:00:02 \
    --enet-dmac=0c:42:a1:dd:57:90 \
    --fixcsum \
    --dlt=enet
'
```

**IMPORTANTE:** Si encuentras errores de "Disk quota exceeded":
```bash
# Procesar por bloques pequeños y luego borrar
cd /proj/softmeasure-PG0/CICD
sudo rm -rf remapped
mkdir remapped

# Remapear solo un rango (p.ej. 0500-0599)
cd pcaps
ls SAT-01-12-2018_05*.pcap | pv -l | parallel -j16 'sudo tcprewrite ...'

# Copiar a /local/dpdk_100g/mira/
sudo cp ../remapped/*.pcap /local/dpdk_100g/mira/attack_pcaps/

# Borrar remapped y repetir con siguiente rango
cd /proj/softmeasure-PG0/CICD
sudo rm -rf remapped
mkdir remapped
```

#### Paso 7: Verificar Remapeo

```bash
cd /proj/softmeasure-PG0/CICD/remapped

# Si tshark no está instalado:
sudo apt-get update && sudo apt-get install -y tshark

# Verificar IPs
sudo tshark -r SAT-01-12-2018_0500.pcap -T fields -e ip.src -e ip.dst | head -20

# Verificar MACs + IPs
sudo tshark -r SAT-01-12-2018_0500.pcap -T fields -e eth.src -e eth.dst -e ip.src -e ip.dst | head -20

# Alternativa si tshark no funciona: usar tcpdump
sudo tcpdump -r SAT-01-12-2018_0500.pcap -e -n -c 20
```

**Salida esperada:**
```
00:00:00:00:00:02    0c:42:a1:dd:57:90    10.10.3.x    10.10.1.2
00:00:00:00:00:02    0c:42:a1:dd:57:90    10.10.3.y    10.10.1.2
```

**IMPORTANTE:** Si ya tienes PCAPs remapeados de sesiones anteriores, verifica que:
- **Src IP:** `10.10.3.x` (rango de atacantes)
- **Dst IP:** `10.10.1.2` (IP del node-monitor)
- **Dst MAC:** `0c:42:a1:dd:57:90` (debe coincidir con tu node-monitor actual)

**Si las IPs o MACs no coinciden:**
```bash
# Necesitarás volver a remapear con los parámetros correctos
cd /proj/softmeasure-PG0/CICD
sudo rm -rf remapped
mkdir remapped
# Ejecutar de nuevo el Paso 6 con:
#   --srcipmap=0.0.0.0/0:10.10.3.0/24
#   --enet-dmac=0c:42:a1:dd:57:90
```

#### Paso 8: Verificar PCAPs Remapeados

```bash
cd /proj/softmeasure-PG0/CICD/remapped

# Contar cuántos PCAPs se remapearon
ls *.pcap | wc -l

# Verificar tamaño total
du -sh .

# Verificar uno de los PCAPs
sudo tshark -r $(ls *.pcap | head -1) -T fields -e eth.dst -e ip.src -e ip.dst | head -5
```

**Salida esperada:**
```
0c:42:a1:dd:57:90    10.10.3.x    10.10.1.2  ✅
```

**NOTA:** NO necesitas copiar los PCAPs a `/local/`. El sender de ataque los usará **directamente desde `/proj/softmeasure-PG0/CICD/remapped/`** para ahorrar espacio en disco.

---

### Opción B: Generar Tráfico de Ataque Sintético

#### Paso 1: Instalar Dependencias Python

```bash
cd /local/dpdk_100g/mira/attack_generator

# Actualizar repositorios
sudo apt-get update

# Instalar Python y pip
sudo apt-get install -y python3 python3-pip

# Instalar Scapy
pip3 install scapy
```

#### Paso 2: Generar PCAP de Ataque Sintético

```bash
cd /local/dpdk_100g/mira/attack_generator

# Generar 10M paquetes de ataque mixto (UDP, SYN, ICMP)
# Basado en patrones de CICDDoS2019 dataset (UNB)
# - UDP Flood: 516-byte payloads (característico de Mirai en CICDDoS2019)
# - SYN Flood: TCP SYN a puertos 80/443/22
# - ICMP Flood: ping packets estándar
# NOTA: Este generador NO es paralelo (sin --cores), tardará más tiempo
# IP atacantes: 10.10.3.0/24 (red interna CloudLab)
# MAC destino: 0c:42:a1:dd:57:90 (ens1f0 del monitor)
sudo python3 generate_mirai_attacks_v2.py \
    --output ../attack_mixed_10M.pcap \
    --packets 10000000 \
    --attack-type mixed \
    --dst-mac 0c:42:a1:dd:57:90 \
    --attacker-range 10.10.3.0/24 \
    --target-ip 10.10.1.2 \
    --attackers 200

# Verificar PCAP generado
ls -lh ../attack_mixed_10M.pcap
tcpdump -r ../attack_mixed_10M.pcap -c 10
```

**Notas importantes:**
- **Rango de IPs atacantes:** `10.10.3.0/24` (red interna CloudLab)
- **IP objetivo:** `10.10.1.2` (node-monitor)
- **MAC destino:** `0c:42:a1:dd:57:90` (ens1f0 del node-monitor)
- **Patrones:** Basados en CICDDoS2019 dataset - UDP flood con 516-byte payloads (característico de Mirai)
- Este generador NO soporta paralelización (sin `--cores`)
- Tiempo estimado: ~10-15 minutos para 10M paquetes (single-core)

### Paso 3: Instalar Dependencias DPDK

```bash
cd /local/dpdk_100g/mira/attack_sender

# Instalar libpcap
sudo apt-get install -y libpcap-dev pkg-config dpdk dpdk-dev
```

**NOTA IMPORTANTE:** El directorio `attack_sender` contiene dos Makefiles:
- `Makefile`: Versión legacy (genera `build/dpdk_pcap_sender`)
- `Makefile_v2`: **Versión actual** (genera `dpdk_pcap_sender` y `dpdk_pcap_sender_v2`)

**Debes usar `Makefile_v2`** en el siguiente paso.

### Paso 4: Compilar DPDK Sender

```bash
cd /local/dpdk_100g/mira/attack_sender

# IMPORTANTE: Usar Makefile_v2 que compila ambas versiones
# Limpiar compilación anterior
make -f Makefile_v2 clean

# Compilar ambas versiones (v1: original, v2: temporal replay)
make -f Makefile_v2

# Verificar binarios generados
ls -lh dpdk_pcap_sender dpdk_pcap_sender_v2
```

**Salida esperada:**
```
-rwxr-xr-x 1 cesteban cesteban 89K Jan 07 10:10 dpdk_pcap_sender
-rwxr-xr-x 1 cesteban cesteban 92K Jan 07 10:10 dpdk_pcap_sender_v2
```

**Nota:**
- `dpdk_pcap_sender` (v1): Sender original (máxima velocidad)
- `dpdk_pcap_sender_v2` (v2): Sender con soporte temporal replay (--pcap-timed, --jitter, etc.)

**IMPORTANTE:** Si solo se compiló `dpdk_pcap_sender_v2`, úsalo directamente. Ambas versiones funcionan igual para envíos básicos.

### Paso 5: Verificar PCI Address

```bash
lspci | grep -i mellanox
# Usar: 0000:41:00.0 (ens1f0)
```

---

## ✅ Verificación Final

### En todos los nodos:

```bash
# 1. Verificar hugepages
grep HugePages_Free /proc/meminfo
# Debe mostrar: HugePages_Free: 2048

# 2. Verificar interfaz de red
ip link show ens1f0
# Debe mostrar: state UP

# 3. Verificar MAC address (debe coincidir con la tabla)
ip link show ens1f0 | grep link/ether
# node-monitor: 0c:42:a1:dd:57:90
# node-controller: 0c:42:a1:dd:57:b8
# node-tg: 0c:42:a1:dd:5a:48

# 4. Verificar binarios compilados
# node-monitor:
ls -lh /local/dpdk_100g/mira/detector_system/mira_ddos_detector

# node-controller:
ls -lh /local/dpdk_100g/mira/benign_sender/build/dpdk_pcap_sender

# node-tg (verificar que al menos uno de estos existe):
ls -lh /local/dpdk_100g/mira/attack_sender/dpdk_pcap_sender_v2
# O si se compilaron ambos:
ls -lh /local/dpdk_100g/mira/attack_sender/dpdk_pcap_sender

# 5. Verificar PCAPs
# node-controller:
ls -lh /local/dpdk_100g/mira/benign_10M.pcap

# node-tg:
ls -lh /local/dpdk_100g/mira/attack_mixed_10M.pcap

# 6. Verificar que los PCAPs tienen la MAC destino correcta
# node-controller:
tcpdump -r /local/dpdk_100g/mira/benign_10M.pcap -e -c 5 | grep "0c:42:a1:dd:57:90"

# node-tg:
tcpdump -r /local/dpdk_100g/mira/attack_mixed_10M.pcap -e -c 5 | grep "0c:42:a1:dd:57:90"
```

---

## 🚀 Comandos para Ejecutar Experimento

### 1. node-monitor (Detector) - Iniciar PRIMERO

```bash
cd /local/dpdk_100g/mira/detector_system

# Ejecutar detector con 16 cores (14 workers + 1 coordinator + 1 main)
# IMPORTANTE: Necesita 16 cores totales (lcores 0-15)
sudo ./mira_ddos_detector -l 0-15 -n 4 -w 0000:41:00.0 -- -p 0 2>&1 | tee ../results/results_mira.log
```

**Esperar mensajes:**
- `Worker thread 0 processing queue 0 on lcore 1`
- `Worker thread 1 processing queue 1 on lcore 2`
- ...
- `Worker thread 13 processing queue 13 on lcore 14`
- `Coordinator thread on lcore 15` ← **Importante: debe aparecer**

Si ves `Warning: No lcore available for coordinator thread!` significa que usaste menos de 16 cores.

### 2. node-controller (Benigno) - Esperar 5 segundos después del detector

```bash
cd /local/dpdk_100g/mira/benign_sender

# Esperar 5 segundos desde que arrancó el detector
sleep 5

# Ejecutar sender de tráfico benigno (17 Gbps target → ~7 Gbps real)
sudo ./build/dpdk_pcap_sender -l 0-7 -n 4 -w 0000:41:00.0 -- ../benign_10M.pcap
```

### 3. node-tg (Ataque) - Esperar 125 segundos después del tráfico benigno

```bash
cd /local/dpdk_100g/mira/attack_sender

# Esperar 125 segundos desde que arrancó el tráfico benigno
sleep 125

# Enviar UN PCAP de prueba (ejemplo)
sudo ./dpdk_pcap_sender_v2 -l 0-7 -n 4 -w 0000:41:00.0 -- /proj/softmeasure-PG0/CICD/remapped/SAT-01-12-2018_0500.pcap
sudo ./dpdk_pcap_sender -l 0-7 -n 4 -w 0000:41:00.0 -- /proj/softmeasure-PG0/CICD/remapped/SAT-01-12-2018_0500.pcap

# O enviar VARIOS PCAPs en secuencia (opcional)
sudo ./dpdk_pcap_sender_v2 -l 0-7 -n 4 -w 0000:41:00.0 -- /proj/softmeasure-PG0/CICD/remapped/SAT-01-12-2018_0500.pcap
sudo ./dpdk_pcap_sender_v2 -l 0-7 -n 4 -w 0000:41:00.0 -- /proj/softmeasure-PG0/CICD/remapped/SAT-01-12-2018_0501.pcap
sudo ./dpdk_pcap_sender_v2 -l 0-7 -n 4 -w 0000:41:00.0 -- /proj/softmeasure-PG0/CICD/remapped/SAT-01-12-2018_0502.pcap

# O usar un loop simple si quieres automatizarlo (copia y pega todo el bloque):
for pcap in /proj/softmeasure-PG0/CICD/remapped/*.pcap; do
  sudo ./dpdk_pcap_sender_v2 -l 0-7 -n 4 -w 0000:41:00.0 -- "$pcap"
done
```

**Comando básico:**
```bash
sudo ./dpdk_pcap_sender_v2 -l 0-7 -n 4 -w 0000:41:00.0 -- /ruta/al/pcap.pcap
```

**Parámetros:**
- `-l 0-7`: Usa 8 cores
- `-n 4`: 4 canales de memoria
- `-w 0000:41:00.0`: PCI address de tu NIC (ajustar si es diferente)
- `-- /ruta/pcap`: Archivo PCAP a enviar

---

## 🛑 Detener Experimento

### Orden de parada (t=450s):

1. **node-controller**: `Ctrl+C` (detener tráfico benigno)
2. **node-tg**: `Ctrl+C` (detener tráfico de ataque)
3. **node-monitor**: Esperar 10 segundos → `Ctrl+C` (detener detector)

---

## 📊 Analizar Resultados

```bash
# En node-monitor
cd /local/dpdk_100g/mira/results

# Ver log completo
cat results_mira.log

# Buscar métricas clave
grep "First Detection Latency" results_mira.log
grep "Total throughput" results_mira.log | tail -20
grep "ALERT STATUS" results_mira.log | head -5
```

---

## 🔍 Solución de Problemas

### Detector no recibe paquetes (0 pkts)

```bash
# Verificar interfaces conectadas
ip link show ens1f0

# Verificar que la interfaz está UP
sudo ip link set ens1f0 up

# Verificar bindings DPDK
dpdk-devbind.py --status
```

### Error al compilar (libdpdk no encontrado)

```bash
# Instalar DPDK completo
sudo apt-get install -y dpdk dpdk-dev libdpdk-dev pkg-config

# Recompilar
make clean && make
```

### Error de hugepages (Cannot allocate memory)

```bash
# Liberar hugepages existentes
sudo rm -rf /dev/hugepages/*
sudo umount /mnt/huge
sudo mkdir -p /mnt/huge
sudo mount -t hugetlbfs nodev /mnt/huge

# Reasignar
echo 2048 | sudo tee /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages
```

### Soft lockup al presionar Ctrl+C

**Solución:** Ya corregido en la versión actual. Si persiste, actualizar código.

---

## 📝 Notas Importantes

1. **Orden de ejecución:** Siempre iniciar detector PRIMERO, luego tráfico benigno (5s después), luego ataque (125s después).

2. **MACs y rangos de IPs verificados:**
   - **node-monitor** (ens1f0): `0c:42:a1:dd:57:90` ← **DESTINO de todo el tráfico**
   - **node-controller** (ens1f0): `0c:42:a1:dd:57:b8`
   - **node-tg** (ens1f0): `0c:42:a1:dd:5a:48`

   **Rangos de IP simulados:**
   - **Tráfico benigno:** `10.10.2.0/24` → `10.10.1.2`
   - **Tráfico de ataque:** `10.10.3.0/24` → `10.10.1.2`

   **IMPORTANTE:** La MAC `0c:42:a1:dd:57:90` del monitor debe usarse como `--dst-mac` en TODOS los PCAPs generados.

3. **PCI Address:** Ajustar `-w 0000:41:00.0` si tu NIC tiene dirección diferente:
   ```bash
   lspci | grep -i mellanox
   ```

4. **Throughput esperado:**
   - Tráfico benigno: ~7 Gbps en el detector
   - Tráfico de ataque: ~10 Gbps en el detector
   - Total durante ataque: ~17 Gbps

5. **Detección esperada:** < 50 ms (vs MULTI-LF: 866 ms → **17× más rápido**)

---

## 🎯 Checklist de Setup Completo

### Todos los nodos:
- [ ] Hugepages configuradas (2048 páginas)
- [ ] Interfaz `ens1f0` UP
- [ ] MAC addresses verificadas (monitor: 0c:42:a1:dd:57:90, controller: 0c:42:a1:dd:57:b8, tg: 0c:42:a1:dd:5a:48)
- [ ] PCI address verificada (`0000:41:00.0`)

### node-monitor (detector):
- [ ] Detector compilado (`mira_ddos_detector`)
- [ ] Directorio `/local/dpdk_100g/mira/results` creado
- [ ] Herramientas instaladas: `dpdk`, `dpdk-dev`, `libdpdk-dev`

### node-controller (tráfico benigno):
- [ ] PCAP benigno generado (`benign_10M.pcap` o `benign_25M.pcap`)
  - Con `--client-range 10.10.2.0/24`
  - Con `--dst-mac 0c:42:a1:dd:57:90`
- [ ] DPDK sender compilado (`benign_sender/build/dpdk_pcap_sender`)

### node-tg (tráfico de ataque):
- [ ] **Opción A:** PCAPs del dataset CICDDoS2019 descargados y remapeados
  - Dataset descargado en `/proj/softmeasure-PG0/CICD/pcaps`
  - PCAPs remapeados en `/proj/softmeasure-PG0/CICD/remapped/` ✅
  - IPs remapeadas: `10.10.3.0/24` → `10.10.1.2`
  - MACs remapeadas: dst-mac `0c:42:a1:dd:57:90`
  - Verificado con: `tshark -r <pcap> -T fields -e eth.dst -e ip.src -e ip.dst`
- [ ] **Opción B:** PCAP sintético generado (`attack_mixed_10M.pcap`)
  - Con `--attacker-range 10.10.3.0/24`
  - Con `--dst-mac 0c:42:a1:dd:57:90`
- [ ] DPDK sender compilado (`attack_sender/dpdk_pcap_sender_v2` - el binario principal a usar)
- [ ] Herramientas instaladas: `tcpreplay`, `tshark`, `parallel`, `pv`

---

**Estado:** ✅ Listo para ejecutar experimento MIRA

**Referencia:** Consultar `EXPERIMENT_COMMANDS.md` para comandos detallados del experimento.

---

## 📚 Referencias y Datasets

### CICDDoS2019 Dataset (UNB)

**Dataset oficial:** https://www.unb.ca/cic/datasets/ddos-2019.html

Este experimento usa **PCAPs reales** del dataset CICDDoS2019 (Opción A recomendada) o puede generar tráfico sintético basado en los patrones observados en el dataset (Opción B).

#### Opción A: PCAPs Reales (RECOMENDADA)

**Archivos del dataset:**
- `PCAP-01-12_0-0249.zip` (250 PCAPs)
- `PCAP-01-12_0250-0499.zip` (250 PCAPs)
- `PCAP-01-12_0500-0749.zip` (250 PCAPs)
- `PCAP-01-12_0750-0818.zip` (69 PCAPs)

**Procesamiento aplicado:**
1. Descarga y descompresión de PCAPs
2. Remapeo de IPs: `0.0.0.0/0` → `10.10.3.0/24` (atacantes), `10.10.1.2` (víctima)
3. Remapeo de MACs: dst-mac → `0c:42:a1:dd:57:90` (node-monitor)
4. Fix checksums y Ethernet DLT

**Ejemplo de PCAP remapeado:**
- Original: `SAT-01-12-2018_0500.pcap` (IPs/MACs originales del dataset)
- Remapeado: `SAT-01-12-2018_0500.pcap` (IPs: 10.10.3.x → 10.10.1.2, MAC: 0c:42:a1:dd:57:90)

#### Opción B: Tráfico Sintético

**Tráfico benigno (10.10.2.0/24 → 10.10.1.2):**
- 50% HTTP (GET requests + responses)
- 20% DNS (queries + responses)
- 15% SSH (sesiones encriptadas)
- 10% ICMP (echo request/reply)
- 5% UDP background (NTP, SNMP, etc.)

**Tráfico de ataque Mirai (10.10.3.0/24 → 10.10.1.2):**
- 50% SYN Flood (TCP SYN a puertos 80/443/22)
- 40% UDP Flood (516-byte payloads, característico de Mirai en CICDDoS2019)
- 10% ICMP Flood (ping packets)

### Paper de Comparación

**MULTI-LF (2025):**
- Título: "MULTI-LF: A Unified Continuous Learning Framework for Real-Time DDoS Detection in Multi-Environment Networks"
- Autores: Rustam et al.
- arXiv: 2504.11575
- Métrica clave: Prediction latency de **866 ms**

**Objetivo del experimento MIRA:**
Demostrar que DPDK + OctoSketch detecta ataques **17-170× más rápido** (<50 ms) que enfoques basados en ML como MULTI-LF.

---

## ⚡ Recomendación: ¿Qué Opción Usar?

### Para Experimentos de Investigación → **Opción A (Dataset Real)**

**Ventajas:**
- ✅ Tráfico **real** capturado de ataques Mirai reales
- ✅ Patrones de tráfico auténticos (timings, tamaños, variabilidad)
- ✅ Validación más robusta y publicable
- ✅ Comparación directa con otros papers que usan CICDDoS2019

**Desventajas:**
- ⚠️ Requiere descarga (~100GB total)
- ⚠️ Procesamiento de remapeo toma tiempo (~30-60 min)
- ⚠️ Necesita espacio en `/proj/` (cuota limitada)

### Para Pruebas Rápidas → **Opción B (Sintético)**

**Ventajas:**
- ✅ Rápido de generar (2-15 minutos)
- ✅ No requiere descarga externa
- ✅ Control total sobre parámetros de ataque

**Desventajas:**
- ⚠️ Tráfico sintético (menos realista)
- ⚠️ Patrones perfectos (no representa variabilidad real)

**Recomendación final:** Usa **Opción A** para resultados de tesis/publicación, **Opción B** para debugging y pruebas iniciales.
