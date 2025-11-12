# Instalación de Fixes para Mezcla de Tráfico

## 📦 Archivos que Necesitas Actualizar en CloudLab

### Archivos modificados:
1. ✅ `attack_generator/generator.py` (líneas 352-358) - Fix principal
2. ✅ `regenerate_mixed_attacks.sh` (líneas 51-52) - Script de generación completa
3. ✅ `test_mix.sh` (líneas 41-42) - Script de prueba

## 🚀 PASOS A SEGUIR EN CLOUDLAB (Nodo TG)

### Paso 1: Copiar archivos actualizados

#### Opción A: Copiar archivo por archivo (RECOMENDADO)

```bash
cd /local/dpdk_100g

# 1. Backup del generator.py original
cp attack_generator/generator.py attack_generator/generator.py.backup

# 2. Editar generator.py
nano attack_generator/generator.py
```

**En nano, busca la línea 343** (`Ctrl+W` y busca "if args.config:") y reemplaza:

```python
    # Construir configuración
    if args.config:
        # Cargar desde JSON
        if args.config == '-':
            # Leer desde stdin
            config = json.load(sys.stdin)
        else:
            with open(args.config, 'r') as f:
                config = json.load(f)
    else:
```

Por:

```python
    # Construir configuración
    if args.config:
        # Cargar desde JSON
        if args.config == '-':
            # Leer desde stdin
            config = json.load(sys.stdin)
        else:
            with open(args.config, 'r') as f:
                config = json.load(f)

        # Fusionar con argumentos CLI (CLI tiene prioridad)
        if args.mix_benign:
            config['mix_benign'] = args.mix_benign
        if args.attack_ratio is not None:
            config['attack_ratio'] = args.attack_ratio
        if args.dataset_path:
            config['dataset_path'] = args.dataset_path
    else:
```

Guarda con `Ctrl+O`, `Enter`, `Ctrl+X`

```bash
# 3. Editar test_mix.sh
nano test_mix.sh
```

**Busca la línea 37** (donde está el heredoc con el JSON) y **añade estas dos líneas**:

Antes (línea ~37):
```json
{
  "target_ip": "10.10.1.2",
  "output_dir": "/local/pcaps",
  "seed": 42,
  "attacks": [
```

Después (añadir las líneas marcadas con +):
```json
{
  "target_ip": "10.10.1.2",
  "output_dir": "/local/pcaps",
  "seed": 42,
+ "mix_benign": "/local/pcaps/benign_traffic.pcap",
+ "attack_ratio": 0.25,
  "attacks": [
```

Guarda con `Ctrl+O`, `Enter`, `Ctrl+X`

```bash
# 4. Editar regenerate_mixed_attacks.sh
nano regenerate_mixed_attacks.sh
```

**Busca la línea 47** (heredoc del JSON) y **añade las mismas dos líneas**:

```json
{
  "target_ip": "$TARGET_IP",
  "output_dir": "$PCAP_DIR",
  "seed": 42,
+ "mix_benign": "$BENIGN_PCAP",
+ "attack_ratio": $ATTACK_RATIO,
  "attacks": [
```

Guarda con `Ctrl+O`, `Enter`, `Ctrl+X`

#### Opción B: Usar sed (automático pero más riesgoso)

```bash
cd /local/dpdk_100g

# Backup
cp attack_generator/generator.py attack_generator/generator.py.backup

# Fix generator.py
cat > /tmp/fix_generator.py << 'PYFIX'
import sys

with open('attack_generator/generator.py', 'r') as f:
    lines = f.readlines()

# Encontrar la línea "    else:" después de "if args.config:"
output = []
i = 0
while i < len(lines):
    output.append(lines[i])

    # Si encontramos la línea que carga el config y el siguiente else
    if 'if args.config:' in lines[i]:
        # Copiar las siguientes líneas hasta encontrar "    else:"
        i += 1
        while i < len(lines) and '    else:' not in lines[i]:
            output.append(lines[i])
            i += 1

        # Insertar el nuevo código antes del else
        if i < len(lines) and '    else:' in lines[i]:
            output.append('\n')
            output.append('        # Fusionar con argumentos CLI (CLI tiene prioridad)\n')
            output.append("        if args.mix_benign:\n")
            output.append("            config['mix_benign'] = args.mix_benign\n")
            output.append("        if args.attack_ratio is not None:\n")
            output.append("            config['attack_ratio'] = args.attack_ratio\n")
            output.append("        if args.dataset_path:\n")
            output.append("            config['dataset_path'] = args.dataset_path\n")
            # Ahora añadir la línea else
            output.append(lines[i])
            i += 1
            continue

    i += 1

with open('attack_generator/generator.py', 'w') as f:
    f.writelines(output)

print("✓ generator.py actualizado")
PYFIX

python3 /tmp/fix_generator.py

# Verificar
grep -A 10 "if args.config:" attack_generator/generator.py | head -20
```

### Paso 2: Verificar los cambios

```bash
cd /local/dpdk_100g

# Verificar generator.py
echo "=== Verificando generator.py ==="
grep -A 8 "# Fusionar con argumentos CLI" attack_generator/generator.py

# Debería mostrar:
#         # Fusionar con argumentos CLI (CLI tiene prioridad)
#         if args.mix_benign:
#             config['mix_benign'] = args.mix_benign
#         ...
```

### Paso 3: Probar con test rápido

```bash
cd /local/dpdk_100g

# Test de 1 solo ataque
sudo ./test_mix.sh
```

**Resultado esperado:**
```
✓ Archivo puro creado: syn_flood.pcap
✓ Archivo mezclado creado: syn_flood_mixed.pcap
✓✓✓ LA MEZCLA FUNCIONA! ✓✓✓
```

### Paso 4: Si el test funciona, generar todos los ataques

```bash
cd /local/dpdk_100g

# Generar los 9 ataques con mezcla
sudo ./regenerate_mixed_attacks.sh 10.10.1.2 0.25
```

### Paso 5: Verificar archivos mezclados

```bash
# Ver todos los mezclados (deberías ver 9)
ls -lh /local/pcaps/*_mixed.pcap

# Contar
ls /local/pcaps/*_mixed.pcap | wc -l
# Debe mostrar: 9
```

### Paso 6: Ejecutar experimento

```bash
cd /local/dpdk_100g

# Ejecutar experimento con PCAPs mezclados
sudo ./run_mixed_experiment.sh ens1f0 /local/pcaps 2000
```

---

## 🔍 Si algo falla:

### Verificar que generator.py tiene el fix:

```bash
grep -n "Fusionar con argumentos CLI" attack_generator/generator.py
```

Debería mostrar algo como:
```
352:        # Fusionar con argumentos CLI (CLI tiene prioridad)
```

Si no muestra nada, el fix no se aplicó.

### Verificar que test_mix.sh tiene mix_benign en el JSON:

```bash
grep -A 3 "mix_benign" test_mix.sh
```

Debería mostrar:
```
  "mix_benign": "/local/pcaps/benign_traffic.pcap",
  "attack_ratio": 0.25,
```

### Ver logs detallados del generador:

```bash
sudo python3 -m attack_generator --help | grep mix
```

Debería mostrar:
```
  --mix-benign MIX_BENIGN
                        PCAP con tráfico benigno para mezclar
  --attack-ratio ATTACK_RATIO
                        Ratio de ataque en mezcla (0.0-1.0)
```

---

## 📝 Resumen de Cambios

### generator.py (líneas 352-358)
**Qué hace:** Fusiona argumentos CLI (`--mix-benign`, `--attack-ratio`) con el config JSON.

**Por qué:** Antes, cuando usabas `--config`, ignoraba los flags CLI. Ahora los fusiona.

### test_mix.sh y regenerate_mixed_attacks.sh
**Qué hace:** Incluye `mix_benign` y `attack_ratio` dentro del JSON.

**Por qué:** Por redundancia, para asegurar que funcione incluso si el fix de generator.py no se aplicó.

---

## 🎯 Flujo Completo Resumido

```bash
# 1. Aplicar fixes (Opción A: manualmente con nano)
cd /local/dpdk_100g
nano attack_generator/generator.py  # Añadir líneas 352-358
nano test_mix.sh                    # Añadir líneas 41-42
nano regenerate_mixed_attacks.sh    # Añadir líneas 51-52

# 2. Probar
sudo ./test_mix.sh

# 3. Si funciona, generar todos
sudo ./regenerate_mixed_attacks.sh

# 4. Verificar
ls -lh /local/pcaps/*_mixed.pcap

# 5. Ejecutar experimento
sudo ./run_mixed_experiment.sh ens1f0
```

---

**¡Listo!** Después de aplicar estos cambios, la mezcla funcionará correctamente. 🚀
