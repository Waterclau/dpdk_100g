# Guión de Presentación - Sistema MIRA de Detección DDoS

**Duración total:** 12 minutos
**Total slides:** 21

---

## Slide 1: Portada

**Qué decir:**
> "Buenos días. Mi trabajo fin de máster trata sobre el diseño e implementación de un sistema de detección de ataques DDoS capaz de operar a velocidad de línea, combinando DPDK para procesamiento de paquetes, estructuras probabilísticas OctoSketch, y machine learning para clasificación."

**Duración:** 15 segundos

---

## Slide 2: Contenidos

**Qué decir:**
> "La presentación se estructura en cinco partes: primero una introducción al problema y las tecnologías utilizadas, luego el plan de trabajo, el trabajo desarrollado que es el núcleo de la presentación, el trabajo pendiente, y finalmente las conclusiones."

**Duración:** 15 segundos

---

## Slide 3: Separador - Introducción

*(Transición rápida)*

---

## Slide 4: 1.1 El problema de los Ataques DDoS

**Qué decir:**
> "Los ataques DDoS han crecido exponencialmente. Ataques de decenas de Gbps requieren detección en microsegundos. El problema es que el kernel de Linux está limitado a unos 3-5 millones de paquetes por segundo debido a las interrupciones por paquete. Necesitamos detección inline a velocidad de línea."

**Posibles preguntas:**
1. **¿Por qué el kernel es tan lento?**
   > "Cada paquete genera una interrupción hardware, cambio de contexto, y copia de datos. DPDK elimina todo eso."

2. **¿Qué significa detección inline?**
   > "Analizamos los paquetes mientras pasan por el sistema, en tiempo real, no después de capturarlos."

---

## Slide 5: 1.2 DPDK - Data Plane Development Kit

**Qué decir:**
> "DPDK es un conjunto de bibliotecas que permite procesar paquetes en espacio de usuario, bypaseando el kernel. Usa poll-mode en lugar de interrupciones, hugepages para memoria contigua que reduce TLB misses, y zero-copy para acceso directo a la NIC. El resultado es que podemos procesar unos 14 millones de paquetes por segundo por core, comparado con medio millón con el kernel."

**Posibles preguntas:**
1. **¿Qué son las hugepages?**
   > "Páginas de memoria de 2MB o 1GB en lugar de 4KB. Reducen las entradas en la TLB y los cache misses."

2. **¿Qué significa poll-mode?**
   > "El CPU pregunta constantemente '¿hay paquetes?' en lugar de esperar interrupciones. Consume más CPU pero elimina latencia."

3. **¿DPDK funciona con cualquier tarjeta?**
   > "Necesita drivers específicos (PMD). Soporta Intel, Mellanox, etc. Usamos Mellanox ConnectX en CloudLab."

---

## Slide 6: 1.3 OctoSketch - Estructuras Probabilísticas

**Qué decir:**
> "OctoSketch es una estructura probabilística basada en Count-Min Sketch. El problema que resuelve es cómo rastrear millones de IPs con memoria limitada. Usamos una matriz de 8 filas por 4096 columnas, solo 128 KB, pero podemos estimar la frecuencia de cualquier IP. Las operaciones son O(1). El trade-off es una pequeña probabilidad de sobreestimación por colisiones."

**Posibles preguntas:**
1. **¿Por qué tomar el mínimo de las 8 filas en la query?**
   > "Diferentes IPs pueden colisionar en el mismo bucket. Tomando el mínimo reducimos la sobreestimación, es muy improbable que colisionen en las 8 filas."

2. **¿Por qué no usar una hash table normal?**
   > "Una hash table para millones de IPs consumiría gigabytes. El sketch usa memoria constante O(1)."

3. **¿Qué es Elastic Sketch?**
   > "Es el paper de SIGCOMM 2018 en el que se basa OctoSketch."

---

## Slide 7: 1.4 Motivación

**Qué decir:**
> "Los detectores existentes basados en ML tienen latencias de más de 800 milisegundos. El ML tradicional requiere post-procesamiento offline. Nuestro objetivo es combinar lo mejor de ambos mundos: thresholds para detección rápida en menos de 200ms, y ML para clasificación precisa de tipos de ataques."

**Posibles preguntas:**
1. **¿Por qué no usar solo ML o solo thresholds?**
   > "Los thresholds son rápidos pero no clasifican tipos de ataque. El ML clasifica bien pero es más lento. La combinación da lo mejor de ambos."

---

## Slide 8: Separador - Plan de trabajo

*(Transición rápida)*

---

## Slide 9: Planificación (Gantt)

**Qué decir:**
> "El proyecto se desarrolló de septiembre a marzo. Empezamos con el estado del arte y la arquitectura, luego el desarrollo del detector básico, integración de OctoSketch, captura de datos, integración de ML, y finalmente mejoras y documentación. En naranja lo ya realizado, en azul lo pendiente."

**Posibles preguntas:**
1. **¿Qué fase tomó más tiempo?**
   > "La integración de OctoSketch y las mejoras, porque requirió optimizar el rendimiento y hacer múltiples iteraciones."

---

## Slide 10: Separador - Trabajo realizado

*(Transición rápida)*

---

## Slide 11: 3.1 Arquitectura

**Qué decir:**
> "El sistema se despliega en CloudLab con 4 nodos conectados por enlaces de 25 Gbps. El TG genera tráfico de ataque desde la red 10.10.3.x, el Controller genera tráfico benigno desde 10.10.2.x, el Monitor ejecuta el detector DPDK y procesa todo el tráfico inline, y el Victim es el servidor objetivo. Esta separación de redes nos permite etiquetar automáticamente el tráfico."

**Posibles preguntas:**
1. **¿Por qué CloudLab?**
   > "Proporciona hardware real de alta velocidad, aislamiento de red, y reproducibilidad. Simular esto localmente no es posible."

2. **¿El Monitor está inline o solo observa?**
   > "Está inline, procesa todo el tráfico que pasa hacia el Victim."

---

## Slide 12: 3.2 Generadores de tráfico (pcaps) y senders

**Qué decir:**
> "Los generadores producen tráfico benigno como HTTP y DNS normal, y 13 tipos de ataques: volumétricos como UDP y SYN Flood, de amplificación como DNS, NTP, SNMP y SSDP, y específicos como PortMap, NetBIOS, LDAP, MSSQL y TFTP. Los senders son programas DPDK que replayan PCAPs pregenerados a tasas configurables, con modos de timing real, fases de envío, loop y jitter."

**Posibles preguntas:**
1. **¿Por qué usar PCAPs y no generar tráfico sintético?**
   > "Los PCAPs del dataset CIC-DDoS-2019 contienen ataques reales con patrones auténticos."

2. **¿Qué tasa máxima pueden generar?**
   > "Hasta 17 Gbps estables."

---

## Slide 13: 3.3 Arquitectura detector

**Qué decir:**
> "El detector usa arquitectura multi-core con 14 workers y 1 coordinator. RSS distribuye los paquetes entre las 14 colas basándose en la 5-tupla. El diseño es lock-free: cada worker tiene su propio sketch y contadores. El flujo es: recibir burst, parsear, clasificar por IP origen, y actualizar sketch. Cada worker actualiza su sketch solo para 1 de cada 32 paquetes, reduciendo el overhead al 3%. El coordinator fusiona los 14 sketches cada 50ms para la detección."

**Posibles preguntas:**
1. **¿Por qué 14 workers?**
   > "Es el número necesario para sostener 17+ Gbps sin pérdida de paquetes."

2. **¿Cómo funciona el lock-free?**
   > "Cada worker solo escribe en su slot. El coordinator solo lee. Eventual consistency es aceptable para detección volumétrica."

3. **¿Por qué sampling 1/32?**
   > "Balance entre precisión y overhead. Reduce el overhead del sketch al 3.125%."

---

## Slide 14: 3.4 Sistema de detección

**Qué decir:**
> "La detección por thresholds funciona con ventanas de 50 milisegundos. Tenemos thresholds específicos por tipo de ataque: UDP Flood, SYN Flood, amplificación DNS, etc. El sistema también detecta multi-attack cuando hay varios tipos simultáneos. La latencia de detección está entre 30 y 200 milisegundos."

**Posibles preguntas:**
1. **¿Cómo elegiste los thresholds?**
   > "Experimentalmente, observando las tasas de tráfico benigno y de ataque en el testbed."

2. **¿Qué pasa con ataques bajo el threshold?**
   > "Ahí es donde el ML ayuda a detectar patrones más sutiles."

---

## Slide 15: 3.5 Captura de datos

**Qué decir:**
> "Para el ML capturamos datos en 3 runs independientes por escenario. Extraemos 42 features por ventana: 9 contadores básicos, 22 de protocolos específicos, y 11 ratios derivados. El dataset total tiene 7,780 muestras con 14 clases. La tabla muestra las métricas del detector: throughput máximo de 17 Gbps, latencia de 50ms, 14 workers, y soporte para 13+ tipos de ataques."

**Posibles preguntas:**
1. **¿Por qué 42 features?**
   > "Son las que el detector puede extraer: contadores de paquetes, bytes, protocolos específicos, y ratios normalizados."

2. **¿Cómo evitas data leakage?**
   > "Dividimos por run_id. Runs 1 y 2 van a train, run 3 a test. Datos de sesiones completamente diferentes."

---

## Slide 16: 3.6 Resultados LightGBM

**Qué decir:**
> "El modelo LightGBM logra 98.41% de accuracy tanto en validación como en test, lo que indica que no hay overfitting. Precision, recall y F1 superan el 98%. 11 de las 14 clases tienen precisión perfecta. La única clase difícil es 'mixed' con 82.7% de precisión, lo cual es esperado porque mixed contiene tráfico de ataque mezclado con benigno."

**Posibles preguntas:**
1. **¿Por qué mixed tiene menor precisión?**
   > "Porque contiene tanto tráfico benigno como de ataque. Algunos ataques puros se clasifican como mixed, lo cual es parcialmente correcto."

2. **¿El 98.41% es en datos reales?**
   > "Sí, datos capturados del testbed con PCAPs del dataset CIC-DDoS-2019."

---

## Slide 17: 3.7 Comparación

**Qué decir:**
> "Evaluamos 8 algoritmos. LightGBM con 98.41% fue el seleccionado. RandomForest logra 98.23%, HistGradientBoosting 97.56%, XGBoost 98.37%, KNN 98.49% pero es más lento, MLP 98.28%, SGDClassifier 98.08%, y LSTM logra el mejor resultado con 98.96% pero es más complejo de integrar. Elegimos LightGBM por el balance entre accuracy, velocidad de inferencia, y facilidad de integración con C."

**Posibles preguntas:**
1. **¿Por qué LightGBM y no LSTM que es mejor?**
   > "LightGBM tiene API nativa en C para DPDK, inferencia rápida de 1-3ms. LSTM requiere mantener estado de 12 ventanas y es más complejo."

2. **¿Por qué KNN es más lento?**
   > "Requiere comparar con todos los ejemplos de entrenamiento en cada predicción."

---

## Slide 18: Separador - Trabajo a realizar

*(Transición rápida)*

---

## Slide 19: 4. Trabajo a realizar

**Qué decir:**
> "Quedan tres mejoras principales. Primero, implementar logging binario para reducir el tamaño de logs 8 veces, facilitando el entrenamiento. Segundo, sketch jerárquico con múltiples ventanas temporales de 1, 5 y 30 segundos para detectar ataques de diferentes duraciones. Tercero, detección de ataques low-and-slow que están bajo el threshold, como Slowloris, usando modelos de anomalías."

**Posibles preguntas:**
1. **¿Qué es un sketch jerárquico?**
   > "Mantener sketches a diferentes escalas temporales. Uno de 1 segundo detecta ráfagas cortas, uno de 30 segundos detecta ataques sostenidos más sutiles."

2. **¿Qué son ataques low-and-slow?**
   > "Ataques que envían tráfico bajo el threshold pero sostenido en el tiempo. Slowloris es un ejemplo que mantiene conexiones HTTP abiertas con requests muy lentos."

3. **¿Para qué el binario?**
   > "Los logs de texto actuales ocupan unos 760KB por sesión. En binario serían 62KB, 8 veces menos, facilitando almacenamiento y procesamiento."

---

## Slide 20: Separador - Conclusiones

*(Transición rápida)*

---

## Slide 21: 5. Conclusiones

**Qué decir:**
> "En conclusión, hemos desarrollado un sistema funcional de detección DDoS que procesa más de 17 Gbps. Combinamos exitosamente thresholds para detección rápida con machine learning para clasificación precisa. El modelo logra 98.41% de accuracy en 14 clases de ataques. La latencia de detección es de 50 milisegundos. El sistema es una base sólida para futuras mejoras como mitigación activa y detección de ataques más sutiles."

**Posibles preguntas:**
1. **¿Cuál es la principal contribución?**
   > "La integración de DPDK, sketches y ML en un sistema unificado que detecta ataques a velocidad de línea con clasificación precisa."

2. **¿El sistema está listo para producción?**
   > "Es un prototipo funcional. Para producción necesitaría más pruebas de estabilidad y la implementación de mitigación."

3. **¿Qué harías diferente?**
   > "Empezaría antes con ML para experimentar más con LSTM. También añadiría mitigación desde el diseño inicial."

---

# PREGUNTAS GENERALES

1. **¿Cuántas líneas de código?**
   > "El detector tiene unas 1,900 líneas en C, los scripts ML unas 1,500 en Python, los senders otras 1,000."

2. **¿El sistema escala a más de 100 Gbps?**
   > "Teóricamente sí, añadiendo más workers y NICs. El diseño lock-free escala linealmente con los cores."

3. **¿Cómo manejas falsos positivos?**
   > "El sistema genera alertas pero no bloquea automáticamente. El 98.41% accuracy implica ~1.6% de error."

4. **¿Qué pasa si el atacante cambia su patrón?**
   > "Necesitaría reentrenamiento periódico. Los thresholds seguirían detectando ataques volumétricos."

5. **¿Por qué 50ms de ventana?**
   > "Es suficiente para acumular estadísticas significativas y permite detección prácticamente en tiempo real."

---

# DISTRIBUCIÓN DE TIEMPO

| Sección | Slides | Tiempo |
|---------|--------|--------|
| Introducción | 4-7 | 3 min |
| Plan de trabajo | 9 | 0.5 min |
| Trabajo realizado | 11-17 | 6 min |
| Trabajo a realizar | 19 | 1 min |
| Conclusiones | 21 | 1 min |
| Separadores | 3,8,10,18,20 | 0.5 min |
| **Total** | **21** | **12 min** |
