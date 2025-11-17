# Comandos para Prueba de Tráfico Baseline
## Controlador → Monitor

---

## 📦 1. Generar PCAP (5M paquetes)

**En Controlador:**

```bash
cd /local/dpdk_100g/http_flood_advance/benign_generator

python3 generate_baseline_pcap.py \
    -n 5000000 \
    -o baseline_5M.pcap \
    -s 192.168.1.0 \
    -d 10.0.0.1 \
    --dst-mac 0c:42:a1:8c:dd:0c \
    -v
```

*Tiempo: ~5-10 minutos*

---

## 🎧 2. Escuchar en Monitor

**En Monitor:**

```bash
sudo tcpdump -i ens1f0 -n tcp port 80 -c 100 -A
```

---

## 🚀 3. Enviar Tráfico desde Controlador

**En Controlador:**

```bash
sudo ./replay_baseline.sh -i ens1f0 -f baseline_5M.pcap -r 10000 -q
```

*Presionar Ctrl+C para detener*

---

## 📊 Estadísticas en Tiempo Real (opcional)

**En Monitor (Terminal 2):**

```bash
watch -n 1 'ethtool -S ens1f0 | grep rx_packets'
```

---

## ✅ Verificación Rápida

**En Monitor - Ver peticiones HTTP:**

```bash
sudo tcpdump -i ens1f0 -n tcp port 80 -c 10 -A | grep "GET\|POST"
```

---

## 🎯 Tasas de Envío

**1 Gbps (testing):**
```bash
sudo ./replay_baseline.sh -i ens1f0 -f baseline_5M.pcap -r 1000 -q
```

**10 Gbps (baseline normal):**
```bash
sudo ./replay_baseline.sh -i ens1f0 -f baseline_5M.pcap -r 10000 -q
```

**40 Gbps (alto rendimiento):**
```bash
sudo ./replay_baseline.sh -i ens1f0 -f baseline_5M.pcap -r 40000 -q -p
```

**100 Gbps (máximo):**
```bash
sudo ./replay_baseline.sh -i ens1f0 -f baseline_5M.pcap -t -q -p
```

---

## 🔧 Configuración

- **Controlador Interface:** ens1f0 (MAC: 0c:42:a1:8b:2f:c8)
- **Monitor Interface:** ens1f0 (MAC: 0c:42:a1:8c:dd:0c)
- **IPs origen:** 192.168.1.X (randomizado)
- **IP destino:** 10.0.0.1
