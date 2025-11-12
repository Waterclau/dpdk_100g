#!/bin/bash
#
# Script para aplicar todos los fixes automáticamente
#

set -e

echo "════════════════════════════════════════════════════════════════"
echo "  Aplicando Fixes para Mezcla de Tráfico"
echo "════════════════════════════════════════════════════════════════"
echo ""

# Verificar que estamos en el directorio correcto
if [ ! -f "attack_generator/generator.py" ]; then
    echo "ERROR: Ejecutar desde /local/dpdk_100g"
    exit 1
fi

# Backup de archivos
echo "[1/3] Creando backups..."
cp attack_generator/generator.py attack_generator/generator.py.backup.$(date +%Y%m%d_%H%M%S)
echo "  ✓ Backup de generator.py creado"

# Fix 1: generator.py
echo ""
echo "[2/3] Aplicando fix a generator.py..."

# Crear archivo temporal con el fix
cat > /tmp/fix_generator.patch << 'PATCH'
--- a/generator.py
+++ b/generator.py
@@ -349,6 +349,14 @@
         else:
             with open(args.config, 'r') as f:
                 config = json.load(f)
+
+        # Fusionar con argumentos CLI (CLI tiene prioridad)
+        if args.mix_benign:
+            config['mix_benign'] = args.mix_benign
+        if args.attack_ratio is not None:
+            config['attack_ratio'] = args.attack_ratio
+        if args.dataset_path:
+            config['dataset_path'] = args.dataset_path
     else:
         # Construir desde argumentos CLI
         if not args.attack:
PATCH

# Aplicar usando Python
python3 << 'PYFIX'
import sys

with open('attack_generator/generator.py', 'r') as f:
    content = f.read()

# Buscar la sección a modificar
search = """        else:
            with open(args.config, 'r') as f:
                config = json.load(f)
    else:"""

replace = """        else:
            with open(args.config, 'r') as f:
                config = json.load(f)

        # Fusionar con argumentos CLI (CLI tiene prioridad)
        if args.mix_benign:
            config['mix_benign'] = args.mix_benign
        if args.attack_ratio is not None:
            config['attack_ratio'] = args.attack_ratio
        if args.dataset_path:
            config['dataset_path'] = args.dataset_path
    else:"""

if search in content:
    content = content.replace(search, replace)
    with open('attack_generator/generator.py', 'w') as f:
        f.write(content)
    print("  ✓ generator.py actualizado correctamente")
else:
    print("  ⚠ generator.py ya estaba actualizado o no se encontró la sección")
    sys.exit(0)
PYFIX

# Fix 2: test_mix.sh
echo ""
echo "[3/3] Aplicando fix a test_mix.sh..."

if [ -f "test_mix.sh" ]; then
    python3 << 'PYFIX2'
with open('test_mix.sh', 'r') as f:
    content = f.read()

search = '''  "seed": 42,
  "attacks": ['''

replace = '''  "seed": 42,
  "mix_benign": "/local/pcaps/benign_traffic.pcap",
  "attack_ratio": 0.25,
  "attacks": ['''

if search in content and 'mix_benign' not in content:
    content = content.replace(search, replace)
    with open('test_mix.sh', 'w') as f:
        f.write(content)
    print("  ✓ test_mix.sh actualizado correctamente")
elif 'mix_benign' in content:
    print("  ⚠ test_mix.sh ya estaba actualizado")
else:
    print("  ✗ No se pudo actualizar test_mix.sh")
PYFIX2
fi

# Fix 3: regenerate_mixed_attacks.sh
if [ -f "regenerate_mixed_attacks.sh" ]; then
    python3 << 'PYFIX3'
with open('regenerate_mixed_attacks.sh', 'r') as f:
    content = f.read()

search = '''  "seed": 42,
  "attacks": ['''

replace = '''  "seed": 42,
  "mix_benign": "$BENIGN_PCAP",
  "attack_ratio": $ATTACK_RATIO,
  "attacks": ['''

if search in content and '"mix_benign"' not in content:
    content = content.replace(search, replace)
    with open('regenerate_mixed_attacks.sh', 'w') as f:
        f.write(content)
    print("  ✓ regenerate_mixed_attacks.sh actualizado correctamente")
elif '"mix_benign"' in content:
    print("  ⚠ regenerate_mixed_attacks.sh ya estaba actualizado")
else:
    print("  ✗ No se pudo actualizar regenerate_mixed_attacks.sh")
PYFIX3
fi

echo ""
echo "════════════════════════════════════════════════════════════════"
echo "  Fixes Aplicados Exitosamente"
echo "════════════════════════════════════════════════════════════════"
echo ""
echo "Archivos modificados:"
echo "  ✓ attack_generator/generator.py"
echo "  ✓ test_mix.sh"
echo "  ✓ regenerate_mixed_attacks.sh"
echo ""
echo "Backup guardado en:"
echo "  attack_generator/generator.py.backup.<timestamp>"
echo ""
echo "Siguiente paso:"
echo "  sudo ./test_mix.sh"
echo ""
