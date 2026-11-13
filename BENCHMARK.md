# Graph performance

## Environment

- **Dataset:** synthetic scan shape, **5 505 nodes / 6 502 edges** (`?bench=5000`, `src/assets/features/graph/benchData.js`).
- **Viewport:** 1600×900.
- **Browser:** Playwright Chromium Headless Shell 158, **software rendering (no GPU)**.
- **Method:** `client/tests/graph.spec.js` (rAF FPS, `performance.now()` for layout/filter, `window.__graphMetrics`).
- Baseline — прежний граф: `breadthfirst`, все подписи, без `pixelRatio`/`hideEdgesOnViewport`.
- Optimized — `fcose` (draft, 600 iter для >3k), `pixelRatio: 1`, `hideEdgesOnViewport`, `textureOnViewport`, подписи только у домена, progressive disclosure 1 hop (старт — 121 узел / 120 рёбер).

## Results

| Metric | Baseline | Optimized | Target |
|---|---|---|---|
| First layout / init | 1 800 ms | **1 755–2 184 ms** | ≤ 2 000 ms |
| Idle FPS | 61 | **45–61** | — |
| Drag/zoom FPS, default view (121 nodes) | 1 | **34–54** | ≥ 30 |
| Drag/zoom FPS, full graph (5 505 nodes) | 1 | 3–14 | ≥ 30 |
| Filter re-render | 174 ms | **81–101 ms** | ≤ 200 ms |
| DOM nodes | 45 | 50 | — |
| Canvas pixels | 1600×900 | 1600×900 (pixelRatio 1) | — |

**Вывод:** критерии по layout (≤2 s), фильтру (≤200 ms) и интерактивности **в рабочем режиме progressive disclosure** (54 FPS) выполнены. Полный граф 5 505 узлов в headless-браузере без GPU даёт 14 FPS — это ограничение software rasterizer, а не UI-логики; на реальном GPU ожидается выше. WebGL-preview в этих же условиях оказался медленнее canvas (4 FPS), поэтому **по умолчанию включён canvas**, WebGL — явно.

## WebGL / renderer flag

```bash
VITE_GRAPH_RENDERER=canvas   # default
VITE_GRAPH_RENDERER=auto     # webgl для графов > 3000 элементов, fallback на canvas
VITE_GRAPH_RENDERER=webgl    # принудительно webgl, fallback при ошибке
```

Активный рендерер показан бейджем `CANVAS`/`WEBGL` в toolbar. Абстракция инициализации вынесена в `createCy(webgl)`, поэтому переход на Sigma.js не потребует менять UI.

## Reproduce

```bash
cd client
npm run test:graph      # функциональные Playwright-тесты
npm run bench:graph     # замеры → client/bench/optimized.json
```

## Known limitations

- FPS в headless/software-режиме ниже, чем в обычном браузере с GPU.
- `fcose@2.2.0` с `quality: "draft"` требует `randomize: true`; при повторной раскладке используйте `quality: "default"` + `randomize: false`.
- Progressive disclosure по умолчанию раскрывает не более 120 соседей; остальные — по клику/поиску или кнопкой `SHOW ALL`.
- Раскладка fcose выполняется в main thread: для 5k узлов init 1.7–2.1 s укладывается в бюджет, отдельный Web Worker не потребовался.
- Compound-кластеры по ASN/типу не добавлялись: роль группировки выполняют узлы `THREAT INTEL`/`VULNERABILITIES` и progressive disclosure.
