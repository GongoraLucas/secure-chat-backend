# 5. Detección de esteganografía: método, parámetros y limitaciones

## 5.1 Técnica elegida: ataque chi-cuadrado sobre pares de valores (Westfeld y Pfitzmann)

La esteganografía LSB por **reemplazo** sustituye el bit menos significativo de cada componente de color por un bit del mensaje. Esto solo puede convertir un valor `2k` en `2k+1` o viceversa: cada valor se mueve únicamente **dentro de su par** `(2k, 2k+1)`, llamado *pair of values* (PoV).

Si el mensaje es aproximadamente aleatorio (como un texto cifrado o comprimido), tras incrustarlo las frecuencias de los dos valores de cada par tienden a **igualarse**. En una imagen natural, en cambio, esas frecuencias suelen diferir. El ataque mide estadísticamente qué tan igualados están los pares.

## 5.2 Cálculo

Para cada canal (R, G, B) y para una porción de los píxeles:

1. Histograma `h[0..255]`.
2. Para cada par `k = 0..127`: frecuencia esperada si hubiera incrustación  
   `E_k = (h[2k] + h[2k+1]) / 2`, y observada `O_k = h[2k]`.
3. Solo se usan pares con `E_k > 4` (condición de validez del test χ²).
4. Estadístico: `χ² = Σ (O_k − E_k)² / E_k`, con `g = (pares válidos − 1)` grados de libertad.
5. Probabilidad de incrustación: `p = 1 − F_χ²(χ², g)`, con la CDF de SciPy.

`p` cercano a 1 significa que los pares están igualados, lo que es **compatible con incrustación LSB**. `p` cercano a 0 significa que la distribución es la de una imagen natural.

El cálculo se repite sobre porciones acumuladas (10 %, 20 %, …, 100 % de los píxeles en orden de recorrido). Como el reemplazo LSB secuencial empieza al inicio de la imagen, la curva de `p` permite **estimar qué fracción de la imagen está cargada**.

## 5.3 Parámetros y clasificación

| Parámetro | Valor por defecto | Justificación |
|---|---|---|
| Formatos | PNG y BMP sin pérdida | JPEG altera los LSB al comprimir; el método no aplica |
| Mínimo de pares válidos | ≥ 2 con `E_k > 4` | Requisito de validez del test χ² |
| Tamaño mínimo | 64 × 64 px | Con menos píxeles el histograma no es representativo |
| Porciones | 10 % … 100 % (paso 10 %) | Estimar la extensión de la carga |
| Umbral sospechoso | `p > 0.95` en la primera porción de algún canal | Nivel de confianza habitual del 95 % |
| Zona gris | `0.5 < p ≤ 0.95` | Evidencia insuficiente para afirmar o descartar |

| Resultado | Condición | Política aplicada |
|---|---|---|
| `sospechoso` | p > 0.95 | **cuarentena**: archivo guardado como `quarantine/<uuid>`, nunca expuesto |
| `no_concluyente` | 0.5 < p ≤ 0.95, imagen pequeña o sin pares válidos | **advertencia**: se registra y se informa |
| `sin_indicios` | p ≤ 0.5 | archivo **eliminado** tras el análisis; solo queda el registro y el hash |
| `error` | archivo corrupto o excede límites | **rechazo** |

Un resultado `sospechoso` es un **indicio estadístico, no una prueba** de que exista un mensaje oculto.

Los umbrales implementados coinciden con esta tabla. Se configuran en `stego-service/app/config.py` (variables `SUSPICIOUS_THRESHOLD`, `INCONCLUSIVE_THRESHOLD` y `MIN_DIMENSION`; el servicio no arranca si el umbral de zona gris no es menor que el de sospecha). La clasificación usa el mayor p entre canales en la primera porción (10 %), y `embedding_estimate` es el mayor porcentaje acumulado con p > 0.95 en algún canal (`app/detection/chi_square.py`, `app/detection/classifier.py`).

## 5.4 Validación del archivo antes del análisis

Siguiendo el *OWASP File Upload Cheat Sheet*, el detector solo se ejecuta tras: autorización vigente; tamaño ≤ 5 MiB leído por trozos (413); extensión, *magic bytes* (`89 50 4E 47 0D 0A 1A 0A` para PNG, `42 4D` para BMP) y `Content-Type` coherentes (415); `Image.verify()` de Pillow y límite de 16 megapíxeles contra *decompression bombs* (422). El nombre original nunca se usa como ruta.

## 5.5 Muestras y resultados reales

Las muestras se generan de forma reproducible (semilla fija) con `stego-service/.venv/bin/python scripts/make_samples.py`; son imágenes sintéticas sin derechos de terceros.

| Muestra | Descripción |
|---|---|
| `clean_gradient.png` | Degradado suave sin carga |
| `clean_noise.png` | Ruido natural simulado sin carga |
| `stego_lsb_50.png` | `clean_noise` con reemplazo LSB secuencial del 50 % de la capacidad |
| `stego_lsb_full.png` | `clean_noise` con reemplazo LSB del 100 % de la capacidad |
| `fake.png` | Texto con extensión `.png` (debe dar 415) |
| `corrupt.png` | PNG truncado (debe dar 422) |
| `too_big.png` | > 5 MiB (debe dar 413) |

Salida real de `POST /api/steganography/analyze` (S6, 2026-11-04; AUTH simulado con `allowed:true` en un `TestClient`, mismo código del servicio). La corrida de newman contra los contenedores (I2, 2026-11-04, AUTH real, carpeta T09) dio exactamente los mismos p-values por canal a la porción del 10 %, cargas estimadas, clasificaciones y acciones (imágenes de 512×512); ver [pruebas y evidencias](07-pruebas-evidencias.md).

| Muestra | p (R) 10 % | p (G) 10 % | p (B) 10 % | Carga estimada | Clasificación | Acción |
|---|---|---|---|---|---|---|
| clean_gradient.png | 0.0 | 0.0 | 0.0 | 0 % | `sin_indicios` | — (archivo no se guarda) |
| clean_noise.png | 0.0 | 0.0 | 0.0 | 0 % | `sin_indicios` | — (archivo no se guarda) |
| stego_lsb_50.png | 0.999619 | 0.999999 | 0.999036 | 50 % | `sospechoso` | `cuarentena` |
| stego_lsb_full.png | 0.999967 | 0.999973 | 0.999957 | 100 % | `sospechoso` | `cuarentena` |

En `stego_lsb_50.png` el p se mantiene > 0.999 en las porciones 10–50 % y cae a 0.0 desde el 60 %, que es exactamente donde termina la carga secuencial: por eso `embedding_estimate` = 50. Las muestras inválidas dieron `fake.png` → 415, `corrupt.png` → 422 (registro `error`/`rechazo`) y `too_big.png` → 413.

## 5.6 Limitaciones

- Detecta bien el **reemplazo LSB secuencial** con tasas de incrustación medias o altas.
- Pierde sensibilidad con **incrustación dispersa aleatoria** y tasas bajas: los pares solo se igualan parcialmente en cada porción.
- No detecta **LSB matching (±1)**, que no conserva la estructura de pares, ni técnicas en dominio de frecuencia (DCT, F5), ni esteganografía en metadatos o datos tras el `IEND`.
- Imágenes con zonas planas, paleta indexada o muy pequeñas pueden producir **falsos positivos o resultados no concluyentes**.
- No soporta JPEG por diseño.
- El resultado es probabilístico: un `sin_indicios` no garantiza ausencia de datos ocultos.

- **Observado al generar las muestras (S5):** un degradado lineal puro y un ruido gaussiano sin procesar dieron p ≈ 1 en la primera porción, es decir, **falsos positivos** del test: sus histogramas tienen los pares (2k, 2k+1) casi igualados de forma natural. Las muestras limpias versionadas aplican gamma (degradado) y realce de contraste (ruido) para tener un histograma más parecido al de una foto; los umbrales no se tocaron. Una imagen sintética o muy uniforme puede, por tanto, salir `sospechoso` sin contener datos.
- **Riesgo residual de la subida:** el servicio rechaza con 413 antes de parsear si el `Content-Length` declarado supera el límite, y la lectura acotada corta en `MAX_UPLOAD_BYTES + 1`; pero una subida *chunked* sin `Content-Length` la vuelca el parser multipart de Starlette a un temporal antes de esa lectura. El límite real de cuerpo debe ponerlo un proxy delante.

## 5.7 Referencias

- Westfeld, A. y Pfitzmann, A. (2000). *Attacks on Steganographic Systems*. En *Information Hiding* (LNCS 1768), Springer, pp. 61–76.
- OWASP Foundation. *File Upload Cheat Sheet*. https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html
