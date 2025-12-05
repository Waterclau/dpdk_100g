# 🚨 URGENTE - CloudLab Control Network Fix

## ⚠️ PROBLEMA
CloudLab está a punto de cerrar tu experimento porque estás enviando tráfico por la **red de control pública** (192.168.x.x) en lugar de la **red interna** (10.x.x.x).

## ✅ SOLUCIÓN APLICADA

He cambiado todos los rangos de IP a la red interna de CloudLab (10.10.x.x):

### 1. Generador Benign v2
- ✅ `--client-range` cambiado de `192.168.1.0/24` → `10.10.1.0/24`
- ✅ `--server-ip` cambiado de `10.0.0.1` → `10.10.1.2`

### 2. Detector MIRA
- ✅ `BASELINE_NETWORK` cambiado de `0xC0A80100` (192.168.1.x) → `0x0A0A0100` (10.10.1.x)
- ✅ `ATTACK_NETWORK` cambiado de `0xC0A80200` (192.168.2.x) → `0x0A0A0200` (10.10.2.x)
- ✅ `SERVER_IP` cambiado de `0x0A000001` (10.0.0.1) → `0x0A0A0102` (10.10.1.2)

## 🔥 PASOS INMEDIATOS

### 1. Detén TODO el tráfico actual
```bash
# En todos los nodos donde haya tráfico corriendo
sudo pkill dpdk_pcap_sender
sudo pkill mira_ddos_detector
```

### 2. Responde a CloudLab inmediatamente
```
Asunto: Re: High volume traffic on control network

Hi,

I apologize for the traffic on the control network. I was mistakenly using
192.168.x.x IPs instead of the CloudLab internal 10.x.x.x range.

I have:
1. Stopped all current traffic
2. Reconfigured all software to use 10.10.1.x (benign) and 10.10.2.x (attack)
3. Will regenerate all PCAPs with correct IPs before resuming

The experiment is for DDoS detection research and all traffic will now be
confined to the internal experimental network.

Thank you for your patience.
```

### 3. Recompila el detector
```bash
cd /local/dpdk_100g/mira/detector_system
make clean
make
```

### 4. Regenera los PCAPs con IPs correctas

**BENIGN (10.10.1.x):**
```bash
cd /local/dpdk_100g/mira/benign_generator

# Genera tráfico benign con IPs internas
python3 generate_benign_traffic_v2.py \
    --output ../benign_10M_cloudlab.pcap \
    --packets 10000000 \
    --client-range 10.10.1.0/24 \
    --server-ip 10.10.1.2 \
    --clients 500
```

**ATTACK (10.10.2.x) - Si tienes generador de ataques:**
Cambia las IPs a `10.10.2.x` en tu generador de ataques.

### 5. Verifica las IPs antes de enviar
```bash
# Verifica que el PCAP tenga IPs correctas (10.10.x.x, NO 192.168.x.x)
tcpdump -r benign_10M_cloudlab.pcap -n | head -20

# Busca 10.10.1.x y 10.10.1.2, NO debe aparecer 192.168.x.x
```

### 6. Comprueba las MACs de tus interfaces
```bash
# En cada nodo, verifica las interfaces experimentales
ifconfig | grep -A 5 "10\."

# Usa las MACs correctas en --src-mac y --dst-mac
```

## 📋 Checklist antes de reiniciar

- [ ] Respondí a CloudLab explicando el error
- [ ] Detector recompilado con IPs 10.10.x.x
- [ ] PCAPs regenerados con `--client-range 10.10.1.0/24`
- [ ] Verificado con tcpdump que NO hay 192.168.x.x
- [ ] MACs actualizadas según interfaces reales
- [ ] Interfaces experimentales identificadas (NO usar eth0 que es control)

## ⚠️ REGLA DE ORO

**NUNCA uses:**
- 192.168.x.x
- 172.16.x.x
- Direcciones públicas

**SIEMPRE usa:**
- 10.10.1.x para tráfico benign
- 10.10.2.x para tráfico de ataque
- Verifica en `/etc/hosts` las IPs internas de tus nodos

## 🔍 Cómo identificar la red correcta

```bash
# En cada nodo
cat /etc/hosts | grep -v "^#"

# Busca líneas como:
# 10.10.1.1    node1
# 10.10.1.2    node2
# etc.

# Usa estas IPs en tu experimento
```

## 📞 Si CloudLab cierra el experimento

1. Crea una nueva reserva
2. Usa los archivos ya corregidos
3. Genera PCAPs con IPs correctas desde el inicio
4. Verifica SIEMPRE antes de enviar tráfico

---

**Archivos modificados:**
- ✅ `benign_generator/generate_benign_traffic_v2.py` (líneas 612-615)
- ✅ `detector_system/mira_ddos_detector.c` (líneas 77-81, 350, 608-609, 624-625)
- ✅ `stepsML.md` (líneas 209-210, 221-222)
