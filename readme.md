GUÍA DE EJECUCIÓN
1. En node-monitor - Compilar y ejecutar detector:
bashcd /local/octosketch
./build_detector.sh
./run_detector.sh
2. En node-monitor - Ver logs:
bashtail -f /local/logs/ml_features.csv
3. En node-tg - Generar PCAPs:
bashcd /local/pcaps
./generate_attacks.sh
4. En node-tg - Ejecutar experimento:
bashcd /local
./run_experiment.sh
