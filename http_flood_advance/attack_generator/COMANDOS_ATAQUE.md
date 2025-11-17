# Comandos para Ataque HTTP Flood
## Atacante → Monitor

---

## 📦 1. Generar PCAPs de Ataque

**En nodo Atacante:**

### Ataque GET Flood (100K paquetes)
```bash
cd /local/dpdk_100g/http_flood_advance/attack_generator

python3 generate_http_flood.py \
    -t get_flood \
    -n 100000 \
    -o attack_get_100k.pcap \
    -d 10.0.0.1 \
    --dst-mac 0c:42:a1:8c:dd:0c \
    -b 50 \
    -v
```

### Ataque Mixed (1M paquetes - Recomendado)
```bash
python3 generate_http_flood.py \
    -t mixed \
    -n 1000000 \
    -o attack_mixed_1M.pcap \
    -d 10.0.0.1 \
    --dst-mac 0c:42:a1:8c:dd:0c \
    -b 100 \
    -v
```

### Ataque Intenso (5M paquetes)
```bash
python3 generate_http_flood.py \
    -t mixed \
    -n 5000000 \
    -o attack_mixed_5M.pcap \
    -d 10.0.0.1 \
    --dst-mac 0c:42:a1:8c:dd:0c \
    -b 200 \
    -v
```

---

## 🚀 2. Lanzar Ataque

**En nodo Atacante:**

### Ataque Básico (1 Gbps)
```bash
sudo ./replay_attack.sh -i ens1f0 -f attack_mixed_1M.pcap -r 1000 -q
```

### Ataque Medio (5 Gbps)
```bash
sudo ./replay_attack.sh -i ens1f0 -f attack_mixed_1M.pcap -r 5000 -q
```

### Ataque Intenso (10 Gbps)
```bash
sudo ./replay_attack.sh -i ens1f0 -f attack_mixed_5M.pcap -r 10000 -q
```

### Ataque Máximo (Topspeed)
```bash
sudo ./replay_attack.sh -i ens1f0 -f attack_mixed_5M.pcap -t -q -p
```

---

## 🎯 3. Escenario Completo: Baseline + Ataque

### Terminal 1 - Monitor (Captura)
```bash
sudo tcpdump -i ens1f0 -n tcp port 80 -w capture_attack.pcap
```

### Terminal 2 - Controlador (Baseline)
```bash
cd /local/dpdk_100g/http_flood_advance/benign_generator
sudo ./replay_baseline.sh -i ens1f0 -f baseline_5M.pcap -r 10000 -q
```

### Terminal 3 - Atacante (Ataque)
```bash
cd /local/dpdk_100g/http_flood_advance/attack_generator

# Esperar 30 segundos para establecer baseline
sleep 30

# Lanzar ataque
sudo ./replay_attack.sh -i ens1f0 -f attack_mixed_1M.pcap -r 5000 -q
```

---

## 📊 4. Monitoreo en Monitor

### Ver tráfico en tiempo real
```bash
# Terminal 1
sudo tcpdump -i ens1f0 -n tcp port 80 -c 50 -v

# Terminal 2 - Estadísticas
watch -n 1 'ethtool -S ens1f0 | grep rx_packets'
```

### Distinguir baseline vs ataque
```bash
# Ver IPs origen (baseline: 192.168.x.x, ataque: 203.0.113.x)
sudo tcpdump -i ens1f0 -n tcp port 80 -c 100 | \
    awk '{print $3}' | cut -d'.' -f1-3 | sort | uniq -c
```

---

## 🔧 Tipos de Ataque Disponibles

| Tipo | Descripción | Comando |
|------|-------------|---------|
| `get_flood` | GET repetitivos a "/" | `-t get_flood` |
| `post_flood` | POST a /login | `-t post_flood` |
| `random_get` | GET a URLs aleatorias | `-t random_get` |
| `slowloris` | Conexiones lentas | `-t slowloris` |
| `mixed` | GET + POST mixtos | `-t mixed` |

---

## 🎬 Secuencia Recomendada

```bash
# 1. Generar PCAPs (una vez)
python3 generate_http_flood.py -t mixed -n 1000000 -o attack.pcap --dst-mac 0c:42:a1:8c:dd:0c -v

# 2. Iniciar captura en Monitor
sudo tcpdump -i ens1f0 -w test_attack.pcap

# 3. Enviar baseline desde Controlador (60 seg)
timeout 60 sudo ./replay_baseline.sh -i ens1f0 -f baseline_5M.pcap -r 10000 -q

# 4. Esperar 10 seg
sleep 10

# 5. Lanzar ataque desde Atacante (30 seg)
timeout 30 sudo ./replay_attack.sh -i ens1f0 -f attack.pcap -r 5000 -q

# 6. Analizar captura en Monitor
tcpdump -r test_attack.pcap -n tcp port 80 | head -100
```

---

## 🔍 Verificación

### Características del tráfico de ataque:

**IPs origen:**
- Baseline: 192.168.1.X
- Ataque: 203.0.113.X

**Patrones HTTP:**
- Baseline: URLs variadas, User-Agents normales
- Ataque: URLs repetitivas/maliciosas, User-Agents de bots

**Verificar en Monitor:**
```bash
# Ver IPs atacantes
sudo tcpdump -i ens1f0 -n src net 203.0.113.0/24 -c 20

# Ver peticiones maliciosas
sudo tcpdump -i ens1f0 -n tcp port 80 -A | grep -E "wp-admin|phpmyadmin|.env"
```

---

## 📝 Configuración

- **Atacante Interface:** ens1f0
- **Monitor IP:** 10.0.0.1
- **Monitor MAC:** 0c:42:a1:8c:dd:0c
- **IPs Atacante:** 203.0.113.0/24 (botnet)
- **Botnet size:** 50-200 IPs
