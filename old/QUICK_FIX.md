# Fix Rápido - Mezcla Simplificada

## 🔴 Problema

La función `mix_with_benign()` del generador se queda colgada o no funciona correctamente.

## ✅ Solución

Usar mezcla manual **fuera del generador**:

1. Generar ataques PUROS (sin flag `--mix-benign`)
2. Mezclar manualmente cada PCAP con Python/mergecap

## 📋 Archivos Nuevos (Versión Simplificada)

| Archivo | Descripción |
|---------|-------------|
| `test_mix.sh` | Test con mezcla manual (actualizado) |
| `regenerate_simple_mixed.sh` | Genera 9 ataques y mezcla manualmente |

## 🚀 PASOS EN CLOUDLAB

### Paso 1: Copiar archivos actualizados

```bash
# Desde Windows
scp test_mix.sh usuario@nodo.cloudlab.us:/local/dpdk_100g/
scp regenerate_simple_mixed.sh usuario@nodo.cloudlab.us:/local/dpdk_100g/

# En CloudLab
cd /local/dpdk_100g
chmod +x test_mix.sh regenerate_simple_mixed.sh
```

### Paso 2: Test rápido (1 solo ataque)

```bash
cd /local/dpdk_100g

# Test con mezcla manual
sudo ./test_mix.sh
```

**Resultado esperado:**
```
[*] Generando SYN flood con mezcla...
[+] Completado en Xs

[*] Mezclando PCAPs manualmente con mergecap...
  Ataque: 5000 paquetes
  Benigno: XXXX paquetes
  Total mezclado: XXXX paquetes
  ✓ Archivo mezclado guardado

✓ Archivo puro creado: syn_flood.pcap
✓ Archivo mezclado creado: syn_flood_mixed.pcap
✓✓✓ LA MEZCLA FUNCIONA! ✓✓✓
```

### Paso 3: Si el test funciona, generar todos

```bash
cd /local/dpdk_100g

# Generar 9 ataques + mezclar
sudo ./regenerate_simple_mixed.sh 10.10.1.2 /local/pcaps
```

Esto hará:
1. Generar 9 ataques puros (syn_flood.pcap, udp_flood.pcap, etc.)
2. Mezclar cada uno con benign_traffic.pcap
3. Crear 9 archivos *_mixed.pcap

**Duración:** ~5-7 minutos

### Paso 4: Verificar

```bash
# Ver mezclados
ls -lh /local/pcaps/*_mixed.pcap

# Contar (debe ser 9)
ls /local/pcaps/*_mixed.pcap | wc -l
```

### Paso 5: Ejecutar experimento

```bash
cd /local/dpdk_100g

# Reproducir los 9 mezclados
sudo ./run_mixed_experiment.sh ens1f0 /local/pcaps 2000
```

---

## 🔍 Qué Cambia

### ANTES (con bug):
```
Generador → mix_with_benign() → PCAP mezclado
                  ↑
            (Se queda pillado aquí)
```

### AHORA (simplificado):
```
Generador → PCAP puro
    ↓
Python/mergecap → PCAP mezclado
    ↓
    ✓ Funciona
```

---

## 📊 Ventajas del Método Simplificado

✅ **No usa la función bugueada** del generador
✅ **Más control** sobre la mezcla
✅ **Más rápido** (sin cálculos de ratio complejos)
✅ **100% de ambos tráficos** (todo el ataque + todo el benigno)
✅ **Más realista** para datasets

---

## 🛠️ Cómo Funciona la Mezcla Manual

```python
# Cargar ambos PCAPs
attack = rdpcap("syn_flood.pcap")      # 5,000 paquetes
benign = rdpcap("benign_traffic.pcap")  # 50,000 paquetes

# Combinar TODO (sin sampling)
mixed = attack + benign                 # 55,000 paquetes

# Ordenar por timestamp
mixed.sort(key=lambda p: p.time)

# Guardar
wrpcap("syn_flood_mixed.pcap", mixed)
```

**Resultado:**
- No se pierde ningún paquete
- Mezcla natural por timestamp
- Ratio real depende de los tamaños originales

---

## 🎯 Comandos Resumidos

```bash
# Test (30 segundos)
sudo ./test_mix.sh

# Generar todos (5-7 minutos)
sudo ./regenerate_simple_mixed.sh

# Verificar
ls /local/pcaps/*_mixed.pcap | wc -l

# Ejecutar experimento
sudo ./run_mixed_experiment.sh ens1f0
```

---

## ⚠️ Si Sigue Sin Funcionar

### Debug del test:

```bash
# Ver output completo
sudo ./test_mix.sh 2>&1 | tee test_output.log

# Ver si los PCAPs se crean
ls -lh /local/pcaps/syn_flood*.pcap

# Ver contenido del ataque puro
tcpdump -r /local/pcaps/syn_flood.pcap -c 5

# Ver contenido del benigno
tcpdump -r /local/pcaps/benign_traffic.pcap -c 5
```

### Verificar que Scapy funciona:

```bash
python3 << 'TEST'
from scapy.all import rdpcap, wrpcap
print("✓ Scapy importado correctamente")

# Test de lectura
pkts = rdpcap("/local/pcaps/benign_traffic.pcap")
print(f"✓ Leído benign_traffic.pcap: {len(pkts)} paquetes")
TEST
```

---

## 📝 Diferencias con Método Original

| Aspecto | Original (bug) | Simplificado (nuevo) |
|---------|----------------|----------------------|
| Generación | Con --mix-benign | Sin --mix-benign |
| Mezcla | Dentro del generador | Script Python separado |
| Ratio | Calculado (0.25) | Natural (ambos completos) |
| Sampling | Sí (selecciona paquetes) | No (usa todos) |
| Velocidad | Más lento | Más rápido |
| Confiabilidad | ❌ Se cuelga | ✅ Funciona |

---

**Siguiente paso:** Ejecuta `sudo ./test_mix.sh` en CloudLab y dime qué sale. 🚀
