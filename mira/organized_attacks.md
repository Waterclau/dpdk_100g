# Organized Attacks - Multi-clase por tipo

Guia paso a paso para entrenar el modelo por tipo de ataque (no solo 3 clases).

Objetivo:
- Separar PCAPs por tipo.
- Ejecutar runs dedicados por tipo.
- Extraer features con etiquetas especificas.
- Entrenar un modelo multi-clase real.

---

## 1) Generar PCAPs por tipo con el attack generator

En el nodo TG (o donde tengas el generador):

```bash
cd /local/dpdk_100g/mira/attack_generator

# Ejemplo NTP (ajusta -n segun el volumen que quieras)
sudo python3 generate_cicdos2019_attacks.py \
  -t ntp \
  -n 20000000 \
  -w 16 \
  -i 3.0 \
  -s 1 \
  -o /proj/softmeasure-PG0/CICD/organized/ntp/attack_ntp.pcap
```

Repite para cada tipo, cambiando `-t` y el nombre del archivo:
```
ntp, dns, snmp, ssdp, portmap, netbios, ldap, mssql, udp, udp-lag, syn, webddos, tftp
```

Ejemplo DNS:

```bash
sudo python3 generate_cicdos2019_attacks.py \
  -t dns \
  -n 20000000 \
  -w 16 \
  -i 3.0 \
  -s 1 \
  -o /proj/softmeasure-PG0/CICD/organized/dns/attack_dns.pcap
```

Si no necesitas el generador (porque ya tienes PCAPs remapeados), salta a la seccion 2.

---

## 2) Crear estructura de carpetas por tipo

En el nodo TG (o donde estan los PCAPs remapeados):

```bash
mkdir -p /proj/softmeasure-PG0/CICD/organized/{ntp,dns,snmp,ssdp,portmap,netbios,ldap,mssql,udp,syn,webddos,tftp}
```

Si ya tienes los PCAPs en `/proj/softmeasure-PG0/CICD/remapped/`, copia o mueve cada uno a su carpeta.
Ejemplo manual (ajusta nombres reales):

```bash
cp /proj/softmeasure-PG0/CICD/remapped/*NTP*.pcap   /proj/softmeasure-PG0/CICD/organized/ntp/
cp /proj/softmeasure-PG0/CICD/remapped/*DNS*.pcap   /proj/softmeasure-PG0/CICD/organized/dns/
cp /proj/softmeasure-PG0/CICD/remapped/*SNMP*.pcap  /proj/softmeasure-PG0/CICD/organized/snmp/
cp /proj/softmeasure-PG0/CICD/remapped/*SSDP*.pcap  /proj/softmeasure-PG0/CICD/organized/ssdp/
cp /proj/softmeasure-PG0/CICD/remapped/*PORTMAP*.pcap /proj/softmeasure-PG0/CICD/organized/portmap/
cp /proj/softmeasure-PG0/CICD/remapped/*NETBIOS*.pcap /proj/softmeasure-PG0/CICD/organized/netbios/
cp /proj/softmeasure-PG0/CICD/remapped/*LDAP*.pcap  /proj/softmeasure-PG0/CICD/organized/ldap/
cp /proj/softmeasure-PG0/CICD/remapped/*MSSQL*.pcap /proj/softmeasure-PG0/CICD/organized/mssql/
cp /proj/softmeasure-PG0/CICD/remapped/*UDP*.pcap   /proj/softmeasure-PG0/CICD/organized/udp/
cp /proj/softmeasure-PG0/CICD/remapped/*SYN*.pcap   /proj/softmeasure-PG0/CICD/organized/syn/
cp /proj/softmeasure-PG0/CICD/remapped/*WEB*.pcap   /proj/softmeasure-PG0/CICD/organized/webddos/
cp /proj/softmeasure-PG0/CICD/remapped/*TFTP*.pcap  /proj/softmeasure-PG0/CICD/organized/tftp/
```

Verifica que cada carpeta tenga PCAPs:

```bash
for d in /proj/softmeasure-PG0/CICD/organized/*; do
  echo "$d: $(ls "$d" | wc -l) files"
done
```

---

## 3) Correr runs dedicados por tipo

Formato recomendado (15 min por run):
- Monitor: detector sin ML.
- TG: attack sender con solo ese tipo.

### 3.1 Monitor (detector)

```bash
cd /local/dpdk_100g/mira/detector_system
sudo timeout 900 ./mira_ddos_detector -l 0-15 -n 4 -w 0000:41:00.0 -- -p 0 \
  2>&1 | sudo tee ../ml_system/datasets/raw_logs/attack_ntp_run1.log
```

### 3.2 TG (attack sender)

```bash
cd /local/dpdk_100g/mira/attack_sender
sudo timeout 895 ./dpdk_pcap_sender_v2 -l 0-7 -n 4 -w 0000:41:00.0 -- \
  --pcap-dir /proj/softmeasure-PG0/CICD/organized/ntp --rate-gbps 12
```

Repite el mismo esquema para cada tipo, cambiando:
- La carpeta del tipo.
- El nombre del log (por ejemplo: `attack_dns_run1.log`).

Ejemplo para DNS:

```bash
cd /local/dpdk_100g/mira/detector_system
sudo timeout 900 ./mira_ddos_detector -l 0-15 -n 4 -w 0000:41:00.0 -- -p 0 \
  2>&1 | sudo tee ../ml_system/datasets/raw_logs/attack_dns_run1.log
```

```bash
cd /local/dpdk_100g/mira/attack_sender
sudo timeout 895 ./dpdk_pcap_sender_v2 -l 0-7 -n 4 -w 0000:41:00.0 -- \
  --pcap-dir /proj/softmeasure-PG0/CICD/organized/dns --rate-gbps 12
```

Recomendacion: 2 o 3 runs por tipo (run1, run2, run3).

---

## 4) Extraer features con etiqueta especifica


Desde el nodo monitor:

```bash
cd /local/dpdk_100g/mira/ml_system/01_data_collection

python3 feature_extractor.py \
  --input ../datasets/raw_logs/attack_ntp_run1.log \
  --output ../datasets/processed/attack_ntp_run1.csv \
  --label ntp

python3 feature_extractor.py \
  --input ../datasets/raw_logs/attack_dns_run1.log \
  --output ../datasets/processed/attack_dns_run1.csv \
  --label dns
```

Repite para todos los tipos.

---

## 5) Preparar dataset y entrenar

Cuando tengas todos los CSVs:

```bash
cd /local/dpdk_100g/mira/ml_system/02_training
sudo python3 prepare_dataset.py \
  --input ../datasets/processed/*.csv \
  --output ../datasets/splits/ \
  --train-ratio 0.7 \
  --val-ratio 0.15 \
  --test-ratio 0.15
```

Entrena el modelo igual que antes:

```bash
sudo python3 train_with_normalization.py \
  --train ../datasets/splits/train.csv \
  --val ../datasets/splits/val.csv \
  --output ../../detector_system_ml/lightgbm_model.txt
```

---

## 6) Nota sobre overfitting

Para evitar leakage:
- Ideal: separar los runs por tipo entre train/val/test.
- Mejor: reservar un run completo nuevo para test (por tipo).

---

## Etiquetas sugeridas

Usa exactamente estas etiquetas para consistencia:
```
ntp, dns, snmp, ssdp, portmap, netbios, ldap, mssql, udp, syn, webddos, tftp, benign, mixed
```

Si solo haces multi-clase de ataques, deja fuera `benign/mixed`.
