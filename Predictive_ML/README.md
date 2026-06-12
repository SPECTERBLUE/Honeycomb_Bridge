# Predictive_ML Module

The **Predictive_ML** module provides end-to-end machine learning capabilities for predictive maintenance within the Honeycomb Bridge platform.

**Capabilities:**
- Fetch and aggregate sensor telemetry from Honeycomb channels
- Label raw data using threshold-based or equipment-specific fault classifiers
- Train ML models (Random Forest, XGBoost, LSTM) and store them in Redis
- Run multi-horizon future predictions (1h / 6h / 24h)
- Equipment-specific training and inference (e.g. 60kW Slipring Induction Motor)
- Async training and prediction jobs with status polling
- User-defined model versioning with duplicate protection

---

# Project Structure

```
Predictive_ML/
│
├── fetch_assets_telemetry.py          # Telemetry fetching from Honeycomb channels
├── telemetry_processor.py             # Aggregation, missing-window handling, labeling
├── training_dataset_csv_creation.py   # Converts processed data to training CSV
├── pre_trained_models.py              # Equipment-specific fault labelers & label maps
├── sensor_mapping.json                # Sensor name mappings per equipment type
│
└── ml/
    ├── train_service.py               # Training orchestration & inference engine
    ├── model_store.py                 # Redis model persistence (async)
    ├── prediction.py                  # Generic & equipment-specific prediction runners
    ├── predition_store.py             # Redis prediction result storage (async)
    │
    └── trainers/
        ├── random_forest.py           # Scikit-learn RandomForestClassifier
        ├── xgboost.py                 # XGBClassifier (multi-class & binary)
        └── lstm.py                    # PyTorch LSTM (fault classification & sensor regression)
```

---

# Module Components

## `fetch_assets_telemetry.py` — `FetchAssetsTelemetry`

Fetches raw telemetry from Honeycomb HTTP channels with pagination.

- `get_telemetry_data_asset(asset_id)` — Fetches all telemetry for an entire asset (up to 100k messages, batch size 1000)
- `get_telemetry_data_things(asset_id, thing_id)` — Filtered fetch for a specific publisher/thing within an asset
- Uses auth tokens from `User_fetcher` internally

---

## `telemetry_processor.py` — `TelemetryProcessor`

Converts raw telemetry messages into structured, ML-ready windows.

- `aggregate_window(window_length)` — Fixed-size time window aggregation (avg/min/max per sensor)
- `handle_missing_windows()` — Forward-fills up to 3 consecutive missing windows; marks sensor as `NOT_WORKING` if gap exceeds 3
- `label_data(threshold_map)` — Threshold-based multi-class labeling (`normal` / `pre-failure` / `failure`)

---

## `training_dataset_csv_creation.py`

Converts labeled, aggregated data into a CSV file saved under:
```
data/training_datasets/
```
Returns the dataset path for use by the training API.

---

## `pre_trained_models.py` — Equipment-Specific Labeling

Defines custom fault labeling functions and class maps for specific equipment types.

**Currently implemented: Slipring Induction Motor 60kW**

| Class | Label | Trigger Condition |
|-------|-------|-------------------|
| 0 | Healthy | Normal operation |
| 1 | Overload | High stator current + rising temperature |
| 2 | Rotor/Slipring Fault | Rotor current abnormality |
| 3 | Stator Fault | Stator current spike |
| 4 | Mechanical Fault | High vibration + high temperature |

Labeling follows a priority hierarchy (4 → 3 → 2 → 1 → 0).

**To add new equipment:** implement a custom labeling function and register it in `EQUIPMENT_LABELERS`.

---

## `ml/model_store.py`

Handles async serialization and retrieval of ML models in Redis.

| Function | Responsibility |
|----------|---------------|
| `store_model(name, model, metadata)` | Pickle model + store JSON metadata |
| `load_model(name)` | Retrieve and unpickle model + metadata |
| `list_models()` | Return all model names from registry set |
| `delete_model(name)` | Remove model, metadata, and registry entry |

**Redis keys:**
```
ml:model:{model_name}            → Serialized model (pickle binary)
ml:model:meta:{model_name}       → Model metadata (JSON)
ml:model:list                    → Set of all model names
```

---

## `ml/train_service.py` — `TrainService`

Core orchestration layer bridging data ingestion, feature engineering, training, and inference.

**Training methods:**
- `train(csv_path, model_name, target_column, algorithm, horizon)` — Generic training from CSV
- `train_specific_model(...)` — Equipment-specific training with custom labeling function
- `covert_csv_to_dataframe()` — Converts long-format CSV to wide ML-ready format (sensor columns)
- `create_sequences(df, seq_len)` — Generates temporal sequences for LSTM input

**Prediction methods:**
- `future_predict(model, meta, df, horizon)` — Single-step future prediction for tabular models
- `predict_future_asset(model_name, asset_id, horizon)` — Multi-step sliding-window prediction for an asset

**Feature engineering applied during both training and prediction:**
- Pairwise rolling correlations between sensor columns
- StandardScaler normalization
- NaN / Inf replacement (→ 0)

---

## `ml/trainers/`

### `random_forest.py`
- **Algorithm:** `RandomForestClassifier` (scikit-learn)
- **Config:** 300 trees, max depth 12, balanced class weights, `n_jobs=-1`
- **Output:** trained model + accuracy + confusion matrix

### `xgboost.py`
- **Algorithm:** `XGBClassifier`
- **Config:** 400 estimators, GPU support; handles multiclass and binary targets
- **Output:** trained model + accuracy + confusion matrix + class probabilities

### `lstm.py`
- **Architecture:** `LSTMModel(nn.Module)` — LSTM(hidden=64) → FC(output_size)
- **Supports:** fault classification (multi-class) and sensor value regression
- **Config:** `seq_len=10`, GPU-accelerated when CUDA is available, weighted cross-entropy for imbalanced classes
- **Output:** trained model + scaler tuple, accuracy/metrics or MSE/MAE

---

## `ml/prediction.py`

Entry point for running inference.

- `predict(model_name, asset_id)` — Generic prediction: fetch telemetry → load model → run inference
- `predict_specific(model_name, asset_id, equipment_type)` — Equipment-specific prediction with matching labeling function

---

## `ml/predition_store.py`

Stores prediction results in Redis for later retrieval.

**Redis key format:**
```
prediction:{asset_id}:{model_name}:{horizon}   → JSON prediction blob
```

---

# Data Flow

## Training Pipeline

```
API: POST /downlink/predictive_ML/train
         │
         ▼
  Load CSV (data/training_datasets/)
         │
         ▼
  TrainService.covert_csv_to_dataframe()
  (long → wide: sensor_avg columns)
         │
         ▼
  Feature Engineering
  ├── Pairwise rolling correlations
  ├── StandardScaler normalization
  └── Drop NaN / Inf
         │
         ▼
  Select & Train Algorithm
  ├── Random Forest  (300 trees, balanced weights)
  ├── XGBoost        (400 estimators, GPU optional)
  └── LSTM           (seq_len=10, hidden=64, GPU optional)
         │
         ▼
  Collect Metrics
  (accuracy, confusion matrix, label distribution, sensor correlations)
         │
         ▼
  model_store.store_model()
  (pickle + JSON metadata → Redis)
```

## Prediction Pipeline

```
API: POST /downlink/predictive_ML/predict
         │
         ▼
  FetchAssetsTelemetry.get_telemetry_data_asset()
         │
         ▼
  TelemetryProcessor
  ├── aggregate_window(window_length)
  ├── handle_missing_windows()
  └── label_data(threshold_map)
         │
         ▼
  model_store.load_model(model_name)
  (retrieve + unpickle from Redis)
         │
         ▼
  TrainService.predict_future_asset()
  ├── Convert to wide format
  ├── Recompute correlation features
  └── Run model.predict() × horizon steps
         │
         ▼
  Build predictions JSON
  (timestamps, values, probabilities, confidence, named_probabilities)
         │
         ▼
  predition_store.store_prediction() + return to caller
```

---

# Supported Algorithms & Prediction Types

| Algorithm | Input Type | Supports Fault | Supports Sensor Value | GPU |
|-----------|-----------|:-:|:-:|:-:|
| Random Forest | Tabular (wide) | Yes | No | No |
| XGBoost | Tabular (wide) | Yes | No | Optional |
| LSTM | Temporal sequences | Yes | Yes | Optional |

**Prediction horizons:** `1h` (12 steps), `6h` (72 steps), `24h` (288 steps) at 5-minute frequency.

---

# Prediction Output Format

```json
{
  "timestamps": [1715000000, 1715000300, ...],
  "values": [0, 1, 0],
  "probabilities": [[0.95, 0.05, 0.0], ...],
  "confidence": [0.95, 0.87, 0.79],
  "predicted_label": "Healthy",
  "named_probabilities": {"Healthy": 0.95, "Overload": 0.05, "Mechanical Fault": 0.0},
  "confusion_matrix": [[50, 2, 1], ...],
  "sensor_correlation": {"columns": [...], "matrix": [...]},
  "meta": {"type": "fault", "mode": "multi_step", "horizon": "6h"}
}
```

**Confidence scoring:**

| Model | Source |
|-------|--------|
| RF / XGBoost | `max(predict_proba())` |
| LSTM (fault) | Max softmax probability |
| LSTM (sensor) | Gaussian estimate from historical std |

---

# Model Versioning

- User provides a base name (e.g. `motor_v1`)
- System appends a timestamp suffix: `motor_v1_20250515144500`
- Duplicate names → **HTTP 400** (no overwrite)
- Old models must be explicitly deleted via the DELETE endpoint

**Metadata stored per model:**
```json
{
  "algorithm": "xgboost",
  "target_column": "label",
  "horizon": "6h",
  "prediction_type": "fault",
  "features": ["Vibration_avg", "Temperature_avg", "..."],
  "correlation_pairs": [["Vibration_avg", "Temperature_avg"], "..."],
  "metrics": {"accuracy": 0.94, "confusion_matrix": "..."},
  "trained_at": "20250515144500",
  "freq_minutes": 5,
  "rows": 1200,
  "equipment_type": "Slipring Induction motor 60kw",
  "sequence_length": 10,
  "horizon_steps": 72,
  "num_classes": 5
}
```

---

# Redis Storage Schema

| Key | Type | Content |
|-----|------|---------|
| `ml:model:{name}` | Binary | Serialized model (pickle) |
| `ml:model:meta:{name}` | String | Model metadata (JSON) |
| `ml:model:list` | Set | Registry of all model names |
| `Window_length:{asset_id}` | Integer | Telemetry aggregation window (seconds) |
| `threshold_map:{asset_id}` | String | Sensor thresholds for labeling (JSON) |
| `sensor_map:{model_base_name}` | String | Equipment sensor name mappings (JSON) |
| `prediction:{asset_id}:{model}:{horizon}` | String | Latest prediction result (JSON) |
| `train:{job_id}:{model_name}:{target_col}` | String | Async training job status + results |

---

# API Endpoints

Defined in `api_downlink.py`.

## Telemetry & Dataset

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/downlink/predictive_ML/assets/telemetry` | Fetch, aggregate, label telemetry → generate training CSV |
| POST | `/downlink/predictive_ML/things/telemetry` | Fetch telemetry for a specific thing/publisher |
| GET | `/downlink/predictive_ML/datasets` | List available training CSV datasets |

## Training

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/downlink/predictive_ML/train` | Submit async training job |
| GET | `/downlink/predictive_ML/status/train/{job_id}` | Poll async training job status |

## Models

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/downlink/predictive_ML/models` | List all stored models |
| GET | `/downlink/predictive_ML/models/{model_name}` | Get model metadata |
| DELETE | `/downlink/predictive_ML/models/{model_name}` | Delete a stored model |

## Prediction

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/downlink/predictive_ML/predict` | Submit async prediction job |
| GET | `/downlink/predictive_ML/status/pred/{job_id}` | Poll async prediction job status |

## Equipment-Specific (Advanced)

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/downlink/predictive_ML/Asset_specific/assets/fetch-train` | Equipment-specific fetch + train pipeline |
| POST | `/downlink/predictive_ML/predict/specific` | Equipment-specific prediction |

## Sensor Mapping

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/downlink/predictive_ML/model/sensor-mapping` | Get stored sensor mapping for a model |
| GET | `/downlink/predictive_ML/model/sensor-mapping/default` | Load default `sensor_mapping.json` |

## Redis Utilities

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/downlink/predictive_ML/redis/keys` | List all ML-related Redis keys |
| GET | `/downlink/predictive_ML/redis/key` | Inspect a specific Redis key |
| DELETE | `/downlink/predictive_ML/redis/key` | Delete a specific Redis key |

---

# Integration with Honeycomb Bridge

```
┌──────────────────────────────────────────────────────────┐
│  HONEYCOMB BRIDGE  (FastAPI, port 4567)                  │
│  ├─ PostgreSQL  — device models, users, config           │
│  ├─ Redis       — sessions, model storage, pred cache    │
│  ├─ MQTT        — real-time device telemetry             │
│  ├─ gRPC        — ChirpStack integration                 │
│  │                                                        │
│  └─ PREDICTIVE_ML MODULE                                 │
│     ├─ Fetches telemetry via HTTP channels               │
│     ├─ Uses auth tokens from User_fetcher.py             │
│     ├─ Stores models & predictions in Redis              │
│     └─ Exposed via api_downlink.py                       │
└──────────────────────────────────────────────────────────┘
```

**Key internal dependencies:**
- `User_fetcher.FetchAssetsTelemetry` — auth tokens + HTTP telemetry
- `captcha_utils.redis_client` — async Redis operations
- `auth.get_current_user()` — FastAPI authorization dependency

---

# Extensibility

To add a new ML algorithm:
1. Create `ml/trainers/{algorithm}.py` with a `train_{algorithm}(X, y, ...)` function
2. Register it in `TrainService.train()` algorithm selector in `ml/train_service.py`

To add a new equipment type:
1. Define a custom labeling function in `pre_trained_models.py`
2. Add class label mapping to `EQUIPMENT_FAULT_LABELS`
3. Register the labeler in `EQUIPMENT_LABELERS`

---

# ML Lifecycle Summary

```
Telemetry → Aggregation → Labeling → CSV → Training → Redis → Prediction → Output
```
