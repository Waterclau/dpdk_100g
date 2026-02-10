# Propuesta: Sketches por Protocolo para Deteccion Multi-Clase de DDoS

## Contexto y Motivacion

El sistema MIRA utiliza actualmente un OctoSketch (Count-Min Sketch de 8x4096) que cuenta paquetes por IP de origen de forma **protocol-agnostic**. Las 14 features extraidas de este sketch (PPS, varianza, heavy hitters, entropia, etc.) consiguen un **37.74% de accuracy** en clasificacion multi-clase con LightGBM.

El problema es claro: todos los ataques de amplificacion/reflexion UDP (DNS, NTP, SNMP, SSDP, PortMap, NetBIOS, LDAP, MSSQL, TFTP) generan patrones volumetricos identicos desde el punto de vista del sketch. La unica diferencia entre ellos es el **protocolo/puerto** que utilizan, informacion que el sketch actual ignora.

El modelo con DPI (42 features de inspeccion profunda de paquetes) alcanza un **99.14%**, pero requiere parsear el payload de cada paquete, lo cual es costoso y fragil.

### Resultados actuales: sketch-only vs DPI

| Modelo | Features | Accuracy | Macro F1 |
|--------|:--------:|:--------:|:--------:|
| LightGBM (DPI) | 42 | 99.14% | 0.991 |
| LightGBM (DPI+Sketch) | 56 | 99.20% | 0.992 |
| LightGBM (Sketch-only) | 14 | 37.74% | 0.321 |

### Confusion del sketch actual

Los 8 ataques UDP de amplificacion son indistinguibles entre si:

| Ataque | F1 sketch | Confusion principal |
|--------|:---------:|---------------------|
| ldap | 0.000 | 86 muestras clasificadas como dns |
| ntp | 0.000 | 79 como dns, 37 como udp |
| snmp | 0.000 | 117 como dns |
| ssdp | 0.000 | 117 como netbios |
| netbios | 0.000 | 64 como mssql, 45 como snmp |
| portmap | 0.027 | 121 como snmp |
| mssql | 0.085 | 117 como dns |
| tftp | 0.008 | 99 como portmap |

---

## Propuesta: Sketches por Protocolo

### Idea central

En lugar de un unico OctoSketch global, mantener **12 instancias del mismo Count-Min Sketch**, cada una alimentada exclusivamente con paquetes de un protocolo/puerto concreto. El puerto de destino se lee de la cabecera TCP/UDP (capa 4), **no del payload**, por lo que no es inspeccion profunda.

### Sketches propuestos

| Sketch | Filtro de entrada | Puerto(s) |
|--------|-------------------|:---------:|
| `sketch_dns` | UDP dst_port 53 | 53 |
| `sketch_ntp` | UDP dst_port 123 | 123 |
| `sketch_snmp` | UDP dst_port 161 | 161 |
| `sketch_ssdp` | UDP dst_port 1900 | 1900 |
| `sketch_portmap` | UDP dst_port 111 | 111 |
| `sketch_netbios` | UDP dst_port 137 o 138 | 137/138 |
| `sketch_ldap` | UDP/TCP dst_port 389 | 389 |
| `sketch_mssql` | UDP/TCP dst_port 1434 | 1434 |
| `sketch_tftp` | UDP dst_port 69 | 69 |
| `sketch_syn` | TCP con flag SYN | — |
| `sketch_http` | TCP dst_port 80 o 443 | 80/443 |
| `sketch_udp_other` | UDP sin puerto conocido | resto |

Cada sketch por protocolo es internamente identico al OctoSketch actual: Count-Min Sketch (8 filas x 4096 columnas) con tracking de heavy hitters y contadores de bytes.

---

## Diagrama de Arquitectura

```
                              PAQUETE ENTRANTE
                                     |
                           +---------+---------+
                           |  Parse L3/L4      |
                           |  headers          |
                           |  (ya existe en    |
                           |   el worker)      |
                           +---------+---------+
                                     |
                      +--------------+--------------+
                      |              |              |
                 TCP packets    UDP packets    ICMP packets
                      |              |              |
                +-----+-----+       |         sketch_icmp
                |           |       |
           SYN flag?    dst_port?   |
                |           |       |
          sketch_syn   +----+   dst_port?
                       |        |
                  80/443     +--+--+--+--+--+--+--+--+--+--+
                       |     |  |  |  |  |  |  |  |  |  |  |
                 sketch_http 53 69 111 123 137 161 389 1434 1900 otro
                             |  |   |   |   |   |   |    |    |    |
                   sketch_dns+  |   |   |   |   |   |    |    |    |
                   sketch_tftp--+   |   |   |   |   |    |    |    |
                   sketch_portmap---+   |   |   |   |    |    |    |
                   sketch_ntp-----------+   |   |   |    |    |    |
                   sketch_netbios-----------+   |   |    |    |    |
                   sketch_snmp------------------+   |    |    |    |
                   sketch_ldap----------------------+    |    |    |
                   sketch_mssql--------------------------+    |    |
                   sketch_ssdp--------------------------------+    |
                   sketch_udp_other--------------------------------+
                                     |
                                     v
                    +----------------+----------------+
                    |     SKETCH GLOBAL (actual)      |
                    |     Alimentado con TODOS los    |
                    |     paquetes (sin filtro)        |
                    +---------------------------------+
```

### Estructura interna de cada sketch

```
+-----------------------------------------------+
|  sketch_X (ej: sketch_dns)                    |
|  =============================================|
|  Count-Min Sketch: 8 rows x 4096 cols        |
|    - hash(src_ip) por fila                    |
|    - query: min(filas) = estimacion paquetes  |
|                                               |
|  Heavy Hitter Tracker:                        |
|    - ip_counts[65536]                         |
|    - ip_addrs[65536]                          |
|    - Top-K IPs con mas trafico               |
|                                               |
|  Contadores globales:                         |
|    - total_updates (paquetes del protocolo)   |
|    - total_bytes (bytes del protocolo)        |
+-----------------------------------------------+

Features extraidas por sketch (4 por protocolo):
  1. pps_proto      = total_updates / window_sec
  2. hh_proto       = num IPs con > threshold pps
  3. concentr_proto = top1_ip.count / total_updates
  4. ratio_proto    = sketch_X.pps / sketch_global.pps
```

### Features totales del nuevo modelo

```
+-----------------------------------------------------------+
|  BLOQUE 1: Sketch Global (14 features existentes)         |
|  -------------------------------------------------        |
|  delta_pps_5w, delta_pps_10w, pps_variance,               |
|  pps_baseline, ratio_vs_baseline,                         |
|  top_ip_pps_50ms, top_ip_pps_1s, top_ip_pps_1min,        |
|  ratio_50ms_1min, num_heavy_hitters, ip_concentration,    |
|  new_ips_ratio, attack_entropy, adaptive_threshold        |
+-----------------------------------------------------------+
|  BLOQUE 2: Sketches por Protocolo (4 x 12 = 48 features) |
|  -------------------------------------------------        |
|  dns:       pps, heavy_hitters, concentracion, ratio      |
|  ntp:       pps, heavy_hitters, concentracion, ratio      |
|  snmp:      pps, heavy_hitters, concentracion, ratio      |
|  ssdp:      pps, heavy_hitters, concentracion, ratio      |
|  portmap:   pps, heavy_hitters, concentracion, ratio      |
|  netbios:   pps, heavy_hitters, concentracion, ratio      |
|  ldap:      pps, heavy_hitters, concentracion, ratio      |
|  mssql:     pps, heavy_hitters, concentracion, ratio      |
|  tftp:      pps, heavy_hitters, concentracion, ratio      |
|  syn:       pps, heavy_hitters, concentracion, ratio      |
|  http:      pps, heavy_hitters, concentracion, ratio      |
|  udp_other: pps, heavy_hitters, concentracion, ratio      |
+-----------------------------------------------------------+
|  BLOQUE 3: Features de tamano de paquete (2 features)     |
|  -------------------------------------------------        |
|  avg_packet_size, packet_size_variance                    |
+-----------------------------------------------------------+
|  TOTAL: 14 + 48 + 2 = 64 features                        |
+-----------------------------------------------------------+
```

---

## Deteccion por Tipo de Ataque

### Ataques que ya se detectan bien (F1 > 0.9)

#### Benign (F1 actual: 1.000)
- **Patron**: Todos los sketches por protocolo con PPS bajo y estable. Ninguno domina. Distribucion uniforme de trafico entre protocolos.
- **Features clave**: `ratio_vs_baseline` bajo, todos los `pps_proto` bajos.

#### Mixed (F1 actual: 1.000)
- **Patron**: Varios sketches activos simultaneamente con PPS moderado. Combinacion de protocolos.
- **Features clave**: Multiples `ratio_proto` con valores intermedios, `pps_variance` moderada.

#### SYN Flood (F1 actual: 0.960)
- **Patron**: `sketch_syn.pps` extremadamente alto. Paquetes muy pequenos (~40 bytes). El ratio PPS/bytes es unico frente a ataques UDP.
- **Features clave**: `sketch_syn.pps` >> 0, `sketch_syn.ratio` cercano a 1.0, todos los `sketch_udp_*.pps` a 0.
- **Mejora con sketch por protocolo**: Confirmacion explicita de que solo hay trafico SYN, sin ambiguedad.

### Ataques parcialmente detectados

#### UDP Flood generico (F1 actual: 0.646)
- **Patron**: `sketch_udp_other.pps` muy alto, pero **todos** los sketches de amplificacion (DNS, NTP, SNMP, etc.) a cero. Es trafico UDP que no pertenece a ningun puerto conocido.
- **Features clave**: `sketch_udp_other.pps` >> 0, `sketch_udp_other.ratio` cercano a 1.0.
- **Problema actual**: Precision baja (0.477) porque otros ataques UDP se confunden con este. Con sketch por protocolo, se eliminaria la confusion.
- **F1 estimado**: >0.95

#### WebDDoS / HTTP Flood (F1 actual: 0.426)
- **Patron**: `sketch_http.pps` alto, `sketch_syn.pps` moderado (necesita handshake TCP). PPS total mas bajo que amplificacion. Muchos heavy hitters (botnet distribuida).
- **Features clave**: `sketch_http.pps` >> 0, `sketch_http.heavy_hitters` alto (muchas IPs), todos los `sketch_udp_*.pps` a 0.
- **Problema actual**: 115 muestras se clasifican como UDP. Con sketch por protocolo, se veria que el trafico es TCP 80/443.
- **F1 estimado**: >0.90

#### DNS Amplification (F1 actual: 0.337)
- **Patron**: `sketch_dns.pps` muy alto. Respuestas amplificadas (queries ANY/TXT) con tamano medio de ~3000-4000 bytes. Pocos reflectores (heavy hitters concentrados en servidores DNS publicos).
- **Features clave**: `sketch_dns.pps` >> 0, `sketch_dns.ratio` cercano a 1.0, resto de sketches a 0.
- **F1 estimado**: >0.95

### Ataques actualmente no detectados (F1 = 0)

#### NTP Amplification (F1 actual: 0.000)
- **Patron**: `sketch_ntp.pps` muy alto. Respuestas MON_GETLIST de ~482 bytes. Pocos reflectores NTP (heavy hitters concentrados).
- **Features clave**: `sketch_ntp.pps` >> 0, `sketch_ntp.ratio` cercano a 1.0, resto de sketches a 0.
- **Confusion actual**: 79 muestras clasificadas como DNS, 37 como UDP, 23 como TFTP.
- **Con sketch por protocolo**: Solo `sketch_ntp` tendria actividad. Separacion trivial.
- **F1 estimado**: >0.95

#### SNMP Amplification (F1 actual: 0.000)
- **Patron**: `sketch_snmp.pps` alto. Respuestas GetBulk grandes (~1500+ bytes). Muchos reflectores SNMP accesibles.
- **Features clave**: `sketch_snmp.pps` >> 0, `sketch_snmp.heavy_hitters` alto, resto de sketches a 0.
- **Confusion actual**: 117 muestras clasificadas como DNS, 15 como SSDP.
- **F1 estimado**: >0.95

#### SSDP Amplification (F1 actual: 0.000)
- **Patron**: `sketch_ssdp.pps` alto. Respuestas M-SEARCH de ~300-400 bytes. Alto numero de heavy hitters (muchos dispositivos IoT como reflectores).
- **Features clave**: `sketch_ssdp.pps` >> 0, `sketch_ssdp.heavy_hitters` muy alto (IoT distribuido), resto de sketches a 0.
- **Confusion actual**: 117 muestras clasificadas como NetBIOS, 20 como SNMP.
- **F1 estimado**: >0.95

#### LDAP Amplification (F1 actual: 0.000)
- **Patron**: `sketch_ldap.pps` alto. Respuestas **muy grandes** (~5000-10000 bytes, factor de amplificacion 46-55x). Pocos reflectores LDAP.
- **Features clave**: `sketch_ldap.pps` >> 0, `sketch_ldap.concentr` alto (pocos reflectores), `avg_packet_size` el mas alto de todos los ataques.
- **Confusion actual**: 86 muestras clasificadas como DNS, 24 como SNMP.
- **F1 estimado**: >0.95

#### MSSQL Amplification (F1 actual: 0.000)
- **Patron**: `sketch_mssql.pps` alto. Paquetes SQLBatch/RPC en puerto 1434. Tamano medio ~1000-1500 bytes.
- **Features clave**: `sketch_mssql.pps` >> 0, `sketch_mssql.ratio` cercano a 1.0, resto de sketches a 0.
- **Confusion actual**: 117 muestras clasificadas como DNS.
- **F1 estimado**: >0.95

#### PortMap/RPC Amplification (F1 actual: 0.027)
- **Patron**: `sketch_portmap.pps` alto. Peticiones GETPORT/DUMP en puerto 111. Tamano de respuesta variable (~500-1000 bytes).
- **Features clave**: `sketch_portmap.pps` >> 0, resto de sketches a 0.
- **Confusion actual**: 121 muestras clasificadas como SNMP, 18 como MSSQL.
- **F1 estimado**: >0.95

#### NetBIOS Amplification (F1 actual: 0.000)
- **Patron**: `sketch_netbios.pps` alto. Paquetes Name Service (puerto 137) y Datagram (puerto 138). Tamano medio ~200-500 bytes.
- **Features clave**: `sketch_netbios.pps` >> 0, resto de sketches a 0.
- **Confusion actual**: 64 muestras clasificadas como MSSQL, 45 como SNMP, 36 como TFTP.
- **F1 estimado**: >0.95

#### TFTP Amplification (F1 actual: 0.008)
- **Patron**: `sketch_tftp.pps` alto. Bloques de datos estandar de 512 bytes (tamano fijo del protocolo TFTP). Muchos reflectores.
- **Features clave**: `sketch_tftp.pps` >> 0, `avg_packet_size` cercano a 512B (muy caracteristico), resto de sketches a 0.
- **Confusion actual**: 99 muestras clasificadas como PortMap, 19 como NetBIOS.
- **F1 estimado**: >0.95

---

## Tabla resumen de deteccion

| Ataque | F1 sketch actual | Puerto sketch | Feature discriminante | Tamano medio pkt | F1 estimado |
|--------|:----------------:|:------------:|----------------------|:----------------:|:-----------:|
| benign | 1.000 | — | Todos los sketches PPS bajo | Variable | 1.000 |
| mixed | 1.000 | — | Varios sketches activos, PPS moderado | Variable | 1.000 |
| syn | 0.960 | TCP SYN | `sketch_syn.pps` extremo, pkts 40B | ~40B | >0.98 |
| udp | 0.646 | UDP otro | `sketch_udp_other.pps` alto, resto 0 | ~512-1500B | >0.95 |
| webddos | 0.426 | TCP 80/443 | `sketch_http.pps` alto, botnet distribuida | Variable | >0.90 |
| dns | 0.337 | UDP 53 | `sketch_dns.pps` alto, resto 0 | ~3000-4000B | >0.95 |
| ntp | 0.000 | UDP 123 | `sketch_ntp.pps` alto, resto 0 | ~482B | >0.95 |
| snmp | 0.000 | UDP 161 | `sketch_snmp.pps` alto, resto 0 | ~1500B | >0.95 |
| ssdp | 0.000 | UDP 1900 | `sketch_ssdp.pps` alto, IoT distribuido | ~300-400B | >0.95 |
| ldap | 0.000 | UDP/TCP 389 | `sketch_ldap.pps` alto, pkts enormes | ~5000-10000B | >0.95 |
| mssql | 0.000 | UDP 1434 | `sketch_mssql.pps` alto, resto 0 | ~1000-1500B | >0.95 |
| portmap | 0.027 | UDP 111 | `sketch_portmap.pps` alto, resto 0 | ~500-1000B | >0.95 |
| netbios | 0.000 | UDP 137/138 | `sketch_netbios.pps` alto, resto 0 | ~200-500B | >0.95 |
| tftp | 0.008 | UDP 69 | `sketch_tftp.pps` alto, bloques 512B fijos | ~512B | >0.95 |

---

## Ventajas y Desventajas sobre la Solucion Actual (DPI + Sketch)

### Ventajas

| Aspecto | DPI + Sketch actual | Sketch por Protocolo (propuesta) |
|---------|--------------------|---------------------------------|
| **Inspeccion de payload** | Requiere parsear contenido de DNS, NTP headers, SNMP OIDs, HTTP, etc. | **No necesita**. Solo lee dst_port de cabecera L4 |
| **Coste CPU por paquete** | Alto: cada worker parsea payload de multiples protocolos | **Minimo**: un `if(dst_port)` + hash de IP. O(1) por paquete |
| **Latencia de procesamiento** | Mayor por parsing de payload en cada worker | **Identica al sketch actual** (~nanosegundos) |
| **Resistencia a cifrado** | Falla si el trafico esta cifrado (TLS, VPN, tunneling) | **Funciona**: solo necesita IP:puerto, no payload |
| **Resistencia a evasion** | Atacante puede ofuscar payload para evitar parsers DPI | **Robusto**: no depende del contenido del paquete |
| **Escalabilidad a 100Gbps** | DPI es el cuello de botella a altas tasas | **Escala como el sketch actual**: O(1) por paquete |
| **Mantenimiento** | Hay que actualizar parsers si un protocolo cambia su formato | **Nulo**: los puertos estandar no cambian |
| **Anadir nuevo ataque** | Escribir nuevo parser DPI + features especificas | **Trivial**: 1 sketch nuevo + 4 features |
| **Privacidad** | Lee el contenido de los paquetes (capa 7) | **Solo cabeceras L3/L4**: no toca el payload |
| **Complejidad de codigo** | ~200 lineas de parsers por protocolo en el worker | **~30 lineas**: 12 condiciones if(dst_port) |
| **Estructura de datos** | Contadores simples uint64 (no son sketches) | **Count-Min Sketch real**: estructura probabilistica con garantias teoricas de error |
| **Base academica** | DPI es tecnica clasica, bien establecida | **Per-protocol sketching**: tecnica documentada en Elastic Sketch (SIGCOMM 2018), SketchVisor (SIGCOMM 2017), FlowRadar (NSDI 2016) |

### Desventajas

| Aspecto | Impacto | Mitigacion |
|---------|---------|------------|
| **Memoria adicional** | +12 sketches x ~390KB x 14 workers = ~65 MB extra | Insignificante en servidores con 32+ GB RAM |
| **No distingue subtipos de ataque** | No puede diferenciar DNS ANY de DNS TXT (ambos puerto 53) | Para deteccion DDoS no es necesario: ambos son DNS amplification |
| **Ataques en puertos no estandar** | Si un ataque usa un puerto no mapeado, cae en `sketch_udp_other` | Detectable como UDP flood generico; se puede ampliar la lista de sketches |
| **Accuracy ligeramente menor que DPI** | Estimado ~90-95% vs 99.14% del DPI | Compensado por velocidad, robustez y escalabilidad. Para sistemas en produccion, el rendimiento a 100Gbps es mas critico que 4% de accuracy |
| **No detecta ataques en mismo puerto** | Si dos ataques distintos usan el mismo puerto, el sketch no los separa | En la practica los ataques DDoS conocidos usan puertos distintos |

### Tabla comparativa de rendimiento estimado

| Metrica | DPI (42 features) | Sketch actual (14 features) | Sketch por protocolo (64 features) |
|---------|:-----------------:|:---------------------------:|:----------------------------------:|
| Accuracy | 99.14% | 37.74% | **~90-95% (estimado)** |
| Macro F1 | 0.991 | 0.321 | **~0.90-0.95 (estimado)** |
| CPU por paquete | Alto (payload parsing) | Minimo (1 hash) | **Minimo (1 branch + 1 hash)** |
| Memoria por worker | ~0 extra | ~390 KB | **~5 MB** |
| Memoria total (14 workers) | ~0 extra | ~5.3 MB | **~69 MB** |
| Funciona con cifrado | No | Si | **Si** |
| Lineas de codigo extra | ~200 (parsers) | 0 | **~30 (ifs por puerto)** |

---

## Coste de Implementacion

### En el detector (mira_ddos_detector.c)

Cambio necesario en el worker: donde actualmente hace

```c
octosketch_update_ip(&worker_sketch, src_ip, 1);
```

Se anade:

```c
octosketch_update_ip(&worker_sketch, src_ip, 1);  // sketch global (se mantiene)

// Sketch por protocolo
if (proto == IPPROTO_TCP) {
    if (tcp_flags & TCP_SYN_FLAG)
        octosketch_update_ip(&worker_sketch_syn, src_ip, 1);
    if (dst_port == 80 || dst_port == 443)
        octosketch_update_ip(&worker_sketch_http, src_ip, 1);
} else if (proto == IPPROTO_UDP) {
    switch (dst_port) {
        case 53:   octosketch_update_ip(&worker_sketch_dns, src_ip, 1); break;
        case 69:   octosketch_update_ip(&worker_sketch_tftp, src_ip, 1); break;
        case 111:  octosketch_update_ip(&worker_sketch_portmap, src_ip, 1); break;
        case 123:  octosketch_update_ip(&worker_sketch_ntp, src_ip, 1); break;
        case 137:
        case 138:  octosketch_update_ip(&worker_sketch_netbios, src_ip, 1); break;
        case 161:  octosketch_update_ip(&worker_sketch_snmp, src_ip, 1); break;
        case 389:  octosketch_update_ip(&worker_sketch_ldap, src_ip, 1); break;
        case 1434: octosketch_update_ip(&worker_sketch_mssql, src_ip, 1); break;
        case 1900: octosketch_update_ip(&worker_sketch_ssdp, src_ip, 1); break;
        default:   octosketch_update_ip(&worker_sketch_udp_other, src_ip, 1); break;
    }
}
```

### En octosketch.h

No requiere cambios. Cada sketch por protocolo usa la misma estructura `struct octosketch` existente.

### En el coordinador

El coordinador ya agrega sketches de los workers con `octosketch_merge()`. Se replica la misma logica para cada sketch por protocolo, y se extraen las 4 features (pps, heavy_hitters, concentracion, ratio) de cada uno.

### En el feature extractor (Python)

Se anaden las 48+2 nuevas features al CSV de salida, extrayendolas de los logs del coordinador.

---

## Justificacion Academica

La tecnica de filtrar la entrada de un sketch por criterio de flujo (protocolo, puerto, prefijo IP) es estandar en la literatura de network measurement:

- **Elastic Sketch** (Yang et al., SIGCOMM 2018): Framework adaptativo que separa flujos pesados de ligeros usando sketches diferenciados.
- **SketchVisor** (Huang et al., SIGCOMM 2017): Utiliza sketches separados en fast-path y slow-path para diferentes tipos de medicion.
- **FlowRadar** (Li et al., NSDI 2016): Decodificacion de estadisticas de flujos por protocolo usando estructuras probabilisticas.
- **UnivMon** (Liu et al., SIGCOMM 2016): Sketch universal que soporta queries sobre subconjuntos de trafico.

La propuesta es fundamentalmente un **Count-Min Sketch per-class**, donde la "clase" es el puerto de destino del paquete. Esto mantiene todas las propiedades teoricas del sketch (error acotado, actualizacion O(1), espacio sublineal) mientras anade capacidad discriminativa entre protocolos sin recurrir a inspeccion profunda de paquetes.

---

## Implementacion: Flag --sketch-adv

**Estado: IMPLEMENTADO**

La implementacion no rompe el detector actual. La flag `--sketch-adv` activa el modo avanzado de sketches por protocolo. Sin la flag, el detector funciona exactamente igual que antes.

### Pipelines de datos

```
MODO NORMAL (DPI + sketch antiguo):
  detector → .log (texto) → feature_extractor.py → .csv (56 features)

MODO SKETCH-ADV (sketch nuevo, sin DPI):
  detector → .bin (binario directo desde sketches) → sketch_adv_to_csv.py → .csv (64 features)
```

El modo sketch-adv escribe un fichero binario `../results/sketch_adv_features.bin` con los 64 features computados directamente de los sketches, sin pasar por logs de texto. Cada registro = 528 bytes (header + 64 doubles).

### Uso

```bash
# Modo actual (DPI + sketch antiguo) → guarda .log
sudo timeout 900 ./mira_ddos_detector -l 0-15 -n 4 -w 0000:41:00.0 -- -p 0 \
    2>&1 | sudo tee ../ml_system/datasets/raw_logs/2/attack_dns_run1.log

# Modo sketch-adv → guarda .bin en la ruta indicada
sudo timeout 900 ./mira_ddos_detector -l 0-15 -n 4 -w 0000:41:00.0 \
    -- --sketch-adv ../ml_system/datasets/raw_logs/2/mixed_traffic_run4.bin -p 0
```

### Formato binario (sketch_adv_record)

```
Offset  Size   Campo
------  ----   -----
0       4      magic (0x534B4156 = "SKAV")
4       4      version (1)
8       8      timestamp_ns (nanosegundos desde inicio)

16      112    Bloque 1: 14 global sketch features (14 × double)
               delta_pps_5w, delta_pps_10w, pps_variance, pps_baseline,
               ratio_vs_baseline, top_ip_pps_50ms, top_ip_pps_1s,
               top_ip_pps_1min, ratio_50ms_1min, num_heavy_hitters,
               ip_concentration, new_ips_ratio, attack_entropy,
               adaptive_threshold

128     384    Bloque 2: 48 per-protocol features (4 × 12 × double)
               Orden protocolos: dns, ntp, snmp, ssdp, portmap, netbios,
                                 ldap, mssql, tftp, syn, http, udp_other
               Por protocolo: pps, heavy_hitters, ip_concentration, ratio_vs_total

512     16     Bloque 3: 2 packet size features (2 × double)
               avg_packet_size, packet_size_variance

TOTAL: 528 bytes por registro
```

### Comparacion de los 3 experimentos

| Experimento | Pipeline | Features | Fichero de datos |
|------------|----------|:--------:|-----------------|
| DPI + sketch antiguo | .log → feature_extractor.py → .csv | 56 | .log |
| Sketch antiguo solo | .log → feature_extractor.py → .csv (filtrado) | 14 | .log |
| **Sketch nuevo (ADV)** | **.bin → sketch_adv_to_csv.py → .csv** | **64** | **.bin** |

### Cambios en el detector (mira_ddos_detector.c)

#### Paso 1: Nueva flag global

```c
/* Despues de la linea: static bool g_binary_log_enabled = false; */
static bool g_sketch_adv_enabled = false;  /* Per-protocol sketch mode */
```

#### Paso 2: Declarar 12 arrays de sketches por worker + 12 merged

```c
/* Per-protocol sketches (solo se usan si --sketch-adv esta activo) */
/* Per-worker arrays (14 workers cada uno) */
static struct octosketch g_worker_sketch_dns[NUM_RX_QUEUES] __rte_cache_aligned;
static struct octosketch g_worker_sketch_ntp[NUM_RX_QUEUES] __rte_cache_aligned;
static struct octosketch g_worker_sketch_snmp[NUM_RX_QUEUES] __rte_cache_aligned;
static struct octosketch g_worker_sketch_ssdp[NUM_RX_QUEUES] __rte_cache_aligned;
static struct octosketch g_worker_sketch_portmap[NUM_RX_QUEUES] __rte_cache_aligned;
static struct octosketch g_worker_sketch_netbios[NUM_RX_QUEUES] __rte_cache_aligned;
static struct octosketch g_worker_sketch_ldap[NUM_RX_QUEUES] __rte_cache_aligned;
static struct octosketch g_worker_sketch_mssql[NUM_RX_QUEUES] __rte_cache_aligned;
static struct octosketch g_worker_sketch_tftp[NUM_RX_QUEUES] __rte_cache_aligned;
static struct octosketch g_worker_sketch_syn[NUM_RX_QUEUES] __rte_cache_aligned;
static struct octosketch g_worker_sketch_http[NUM_RX_QUEUES] __rte_cache_aligned;
static struct octosketch g_worker_sketch_udp_other[NUM_RX_QUEUES] __rte_cache_aligned;

/* Merged sketches (coordinador) */
static struct octosketch g_merged_sketch_dns __rte_cache_aligned;
static struct octosketch g_merged_sketch_ntp __rte_cache_aligned;
static struct octosketch g_merged_sketch_snmp __rte_cache_aligned;
static struct octosketch g_merged_sketch_ssdp __rte_cache_aligned;
static struct octosketch g_merged_sketch_portmap __rte_cache_aligned;
static struct octosketch g_merged_sketch_netbios __rte_cache_aligned;
static struct octosketch g_merged_sketch_ldap __rte_cache_aligned;
static struct octosketch g_merged_sketch_mssql __rte_cache_aligned;
static struct octosketch g_merged_sketch_tftp __rte_cache_aligned;
static struct octosketch g_merged_sketch_syn __rte_cache_aligned;
static struct octosketch g_merged_sketch_http __rte_cache_aligned;
static struct octosketch g_merged_sketch_udp_other __rte_cache_aligned;
```

#### Paso 3: Parsear la flag en main()

```c
/* Junto al parsing existente de --binary-log */
if (strcmp(argv[i], "--sketch-adv") == 0) {
    g_sketch_adv_enabled = true;
    printf("Advanced per-protocol sketch mode enabled\n");
}
```

#### Paso 4: Inicializar sketches en main()

```c
if (g_sketch_adv_enabled) {
    for (int i = 0; i < NUM_RX_QUEUES; i++) {
        char name[32];
        snprintf(name, sizeof(name), "DNS-W%d", i);
        octosketch_init(&g_worker_sketch_dns[i], name);
        /* ... repetir para los 12 protocolos ... */
    }
    octosketch_init(&g_merged_sketch_dns, "DNS-Merged");
    /* ... repetir para los 12 ... */

    size_t proto_mem = octosketch_memory_size() * 12 * (NUM_RX_QUEUES + 1);
    printf("[Sketch-ADV] Per-protocol sketches: 12 protocols\n");
    printf("[Sketch-ADV] Extra memory: %.1f MB\n", proto_mem / (1024.0 * 1024.0));
}
```

#### Paso 5: Actualizar sketches por protocolo en worker_thread()

Despues del bloque existente de sketch update (linea 2284), anadir:

```c
/* Per-protocol sketch update (solo si --sketch-adv) */
if (unlikely(g_sketch_adv_enabled)) {
    /* proto ya esta disponible (linea 2114) */
    /* ip_hdr ya esta en scope (linea 2112) */
    if (proto == IPPROTO_TCP) {
        struct rte_tcp_hdr *th = (struct rte_tcp_hdr *)
            ((uint8_t *)ip_hdr + sizeof(struct rte_ipv4_hdr));
        uint16_t dp = rte_be_to_cpu_16(th->dst_port);
        uint8_t fl = th->tcp_flags;

        if (fl & RTE_TCP_SYN_FLAG)
            octosketch_update_ip(&g_worker_sketch_syn[queue_id],
                                 src_ip, SKETCH_SAMPLE_RATE);
        if (dp == 80 || dp == 443)
            octosketch_update_ip(&g_worker_sketch_http[queue_id],
                                 src_ip, SKETCH_SAMPLE_RATE);
    } else if (proto == IPPROTO_UDP) {
        struct rte_udp_hdr *uh = (struct rte_udp_hdr *)
            ((uint8_t *)ip_hdr + sizeof(struct rte_ipv4_hdr));
        uint16_t dp = rte_be_to_cpu_16(uh->dst_port);

        switch (dp) {
            case 53:   octosketch_update_ip(&g_worker_sketch_dns[queue_id],
                           src_ip, SKETCH_SAMPLE_RATE); break;
            case 69:   octosketch_update_ip(&g_worker_sketch_tftp[queue_id],
                           src_ip, SKETCH_SAMPLE_RATE); break;
            case 111:  octosketch_update_ip(&g_worker_sketch_portmap[queue_id],
                           src_ip, SKETCH_SAMPLE_RATE); break;
            case 123:  octosketch_update_ip(&g_worker_sketch_ntp[queue_id],
                           src_ip, SKETCH_SAMPLE_RATE); break;
            case 137:
            case 138:  octosketch_update_ip(&g_worker_sketch_netbios[queue_id],
                           src_ip, SKETCH_SAMPLE_RATE); break;
            case 161:  octosketch_update_ip(&g_worker_sketch_snmp[queue_id],
                           src_ip, SKETCH_SAMPLE_RATE); break;
            case 389:  octosketch_update_ip(&g_worker_sketch_ldap[queue_id],
                           src_ip, SKETCH_SAMPLE_RATE); break;
            case 1434: octosketch_update_ip(&g_worker_sketch_mssql[queue_id],
                           src_ip, SKETCH_SAMPLE_RATE); break;
            case 1900: octosketch_update_ip(&g_worker_sketch_ssdp[queue_id],
                           src_ip, SKETCH_SAMPLE_RATE); break;
            default:   octosketch_update_ip(&g_worker_sketch_udp_other[queue_id],
                           src_ip, SKETCH_SAMPLE_RATE); break;
        }
    }
}
```

**Nota**: `ip_hdr` (linea 2112), `proto` (linea 2114) y `src_ip` (linea 2113) ya estan en scope. El `rte_pktmbuf_free(m)` ocurre en la linea 2295, despues del bloque de sketch. No se necesita cambiar codigo existente.

#### Paso 6: Merge en el coordinador (detect_attacks)

Nueva funcion `merge_protocol_sketches()`:

```c
static void merge_protocol_sketches(void)
{
    struct octosketch *workers[NUM_RX_QUEUES];

    /* Macro para simplificar */
    #define MERGE_PROTO(proto_name) \
        for (int i = 0; i < NUM_RX_QUEUES; i++) \
            workers[i] = &g_worker_sketch_##proto_name[i]; \
        octosketch_merge(&g_merged_sketch_##proto_name, workers, NUM_RX_QUEUES);

    MERGE_PROTO(dns);
    MERGE_PROTO(ntp);
    MERGE_PROTO(snmp);
    MERGE_PROTO(ssdp);
    MERGE_PROTO(portmap);
    MERGE_PROTO(netbios);
    MERGE_PROTO(ldap);
    MERGE_PROTO(mssql);
    MERGE_PROTO(tftp);
    MERGE_PROTO(syn);
    MERGE_PROTO(http);
    MERGE_PROTO(udp_other);

    #undef MERGE_PROTO
}
```

Llamada en `detect_attacks()` despues de `merge_multiscale_sketches()`:

```c
if (g_sketch_adv_enabled) {
    merge_protocol_sketches();
}
```

#### Paso 7: Nueva seccion de log en print_stats()

Despues de la seccion `[RING BUFFER + MULTI-SCALE FEATURES]`, anadir una nueva seccion solo cuando `g_sketch_adv_enabled`:

```c
if (g_sketch_adv_enabled) {
    APPEND("[SKETCH-ADV PER-PROTOCOL FEATURES]\n"
           "=== Per-Protocol Sketch Analysis (12 sketches) ===\n\n");

    /* Para cada protocolo, calcular 4 features */
    struct { const char *name; struct octosketch *sketch; } protos[] = {
        {"DNS (port 53)",       &g_merged_sketch_dns},
        {"NTP (port 123)",      &g_merged_sketch_ntp},
        {"SNMP (port 161)",     &g_merged_sketch_snmp},
        {"SSDP (port 1900)",    &g_merged_sketch_ssdp},
        {"PortMap (port 111)",  &g_merged_sketch_portmap},
        {"NetBIOS (port 137)",  &g_merged_sketch_netbios},
        {"LDAP (port 389)",     &g_merged_sketch_ldap},
        {"MSSQL (port 1434)",   &g_merged_sketch_mssql},
        {"TFTP (port 69)",      &g_merged_sketch_tftp},
        {"SYN (TCP SYN)",       &g_merged_sketch_syn},
        {"HTTP (port 80/443)",  &g_merged_sketch_http},
        {"UDP-Other",           &g_merged_sketch_udp_other},
    };

    double global_pps = octosketch_pps(&g_merged_sketch_attack, window_sec);

    for (int p = 0; p < 12; p++) {
        double proto_pps = octosketch_pps(protos[p].sketch, window_sec);

        /* Heavy hitters del protocolo */
        struct heavy_hitter proto_hh[5];
        octosketch_top_k(protos[p].sketch, 5, proto_hh);
        int hh_count = 0;
        for (int h = 0; h < 5; h++) {
            if (proto_hh[h].count > 0) {
                double ip_pps = (double)proto_hh[h].count / window_sec;
                if (ip_pps > HEAVY_HITTER_PPS_THRESHOLD) hh_count++;
            }
        }

        /* Concentracion */
        uint64_t total = octosketch_get_total(protos[p].sketch);
        double concentr = (total > 0 && proto_hh[0].count > 0) ?
            (double)proto_hh[0].count / total * 100.0 : 0.0;

        /* Ratio vs total */
        double ratio = (global_pps > 0) ? proto_pps / global_pps : 0.0;

        APPEND("  [%s]\n"
               "    PPS:              %.0f\n"
               "    Heavy-hitters:    %d\n"
               "    IP Concentration: %.1f%%\n"
               "    Ratio vs Total:   %.2f\n\n",
               protos[p].name, proto_pps, hh_count, concentr, ratio);
    }

    /* Packet size features */
    uint64_t total_bytes = octosketch_get_bytes(&g_merged_sketch_attack);
    uint64_t total_pkts = octosketch_get_total(&g_merged_sketch_attack);
    double avg_pkt_size = (total_pkts > 0) ? (double)total_bytes / total_pkts : 0.0;

    APPEND("  [Packet Size]\n"
           "    Avg Packet Size:      %.1f\n\n",
           avg_pkt_size);
}
```

#### Paso 8: Reset de sketches por protocolo

Junto al reset existente de `g_worker_sketch_attack`, anadir reset de los 12 sketches:

```c
if (g_sketch_adv_enabled) {
    for (int i = 0; i < NUM_RX_QUEUES; i++) {
        octosketch_reset(&g_worker_sketch_dns[i]);
        octosketch_reset(&g_worker_sketch_ntp[i]);
        /* ... los 12 ... */
    }
}
```

### Conversor binario → CSV (POR IMPLEMENTAR)

Script `sketch_adv_to_csv.py` que lee `sketch_adv_features.bin` y produce un `.csv` con 64 columnas:

```python
import struct
import pandas as pd

RECORD_SIZE = 528
MAGIC = 0x534B4156
PROTOS = ['dns','ntp','snmp','ssdp','portmap','netbios',
          'ldap','mssql','tftp','syn','http','udp_other']

def read_sketch_adv_bin(path, label):
    records = []
    with open(path, 'rb') as f:
        while True:
            data = f.read(RECORD_SIZE)
            if len(data) < RECORD_SIZE:
                break
            magic, version, ts = struct.unpack_from('<IIQ', data, 0)
            if magic != MAGIC:
                continue
            # 14 global features
            global_feats = struct.unpack_from('<14d', data, 16)
            # 48 per-proto features (4 arrays × 12)
            pps = struct.unpack_from('<12d', data, 128)
            hh = struct.unpack_from('<12d', data, 224)
            conc = struct.unpack_from('<12d', data, 320)
            ratio = struct.unpack_from('<12d', data, 416)
            # 2 packet size
            avg_sz, var_sz = struct.unpack_from('<2d', data, 512)

            row = dict(zip(GLOBAL_NAMES, global_feats))
            for i, p in enumerate(PROTOS):
                row[f'pps_{p}'] = pps[i]
                row[f'heavy_hitters_{p}'] = hh[i]
                row[f'ip_concentration_{p}'] = conc[i]
                row[f'ratio_vs_total_{p}'] = ratio[i]
            row['avg_packet_size'] = avg_sz
            row['packet_size_variance'] = var_sz
            row['label'] = label
            records.append(row)
    return pd.DataFrame(records)
```

### feature_groups.py (ACTUALIZADO)

```python
SKETCH_FEATURES_ALL = SKETCH_FEATURES + SKETCH_ADV_FEATURES  # 14 + 50 = 64
```

Las definiciones completas de `SKETCH_ADV_FEATURES` estan en `feature_groups.py`.

### Verificacion

1. **Compilar**: `make` en detector_system/ (no hay ficheros nuevos)
2. **Sin flag**: Ejecutar sin `--sketch-adv` → comportamiento identico al actual
3. **Con flag**: Ejecutar con `--sketch-adv` → escribe `../results/sketch_adv_features.bin` + seccion texto en stdout
4. **Validar binario**: `ls -la ../results/sketch_adv_features.bin` → debe crecer 528 bytes cada 5 segundos
5. **Pipeline ML**: `.bin` → `sketch_adv_to_csv.py` → `.csv` → entrenar con 64 features
6. **Memoria**: Verificar ~65 MB extra en el log de inicializacion
