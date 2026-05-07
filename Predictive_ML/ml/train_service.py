import pandas as pd
import logging
from datetime import datetime, timezone
from typing import Dict, Any
from itertools import combinations
from Predictive_ML.ml.trainers.random_forest import train_random_forest
from Predictive_ML.ml.model_store import store_model
from Predictive_ML.pre_trained_models import label_motor_faults
from sklearn.metrics import confusion_matrix
from Predictive_ML.ml.trainers.xgboost import train_xgboost
from Predictive_ML.ml.trainers.lstm import train_lstm
import numpy as np
from sklearn.preprocessing import StandardScaler
import torch

#  Device selection (GPU if available, else CPU)
device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

print(f"Using device: {device}")


def create_sequences(df, feature_cols, target_col, seq_length, horizon_steps, prediction_type,thresholds=None):
    X, y = [], []

    for i in range(len(df) - seq_length - horizon_steps + 1):
        seq_x = df.iloc[i:i+seq_length][feature_cols].values

        if prediction_type == "fault":
            future = df.iloc[i+seq_length:i+seq_length+horizon_steps][target_col]
            seq_y = int(future.max())  # 0=normal, 1=pre-failure, 2=failure

        else:  # sensor
            seq_y = df.iloc[
                i+seq_length:i+seq_length+horizon_steps
            ][target_col].values

        X.append(seq_x)
        y.append(seq_y)

    return np.array(X), np.array(y)

EQUIPMENT_LABELERS = {
    "Slipring Induction motor 60kw": label_motor_faults,
    # future
    # "centrifugal_pump": label_pump_faults,
    # "compressor": label_compressor_faults
}

EQUIPMENT_FAULT_LABELS = {
    "Slipring Induction motor 60kw": {
        0: "Healthy",
        1: "Overload",
        2: "Rotor/Slipring Fault",
        3: "Stator Fault",
        4: "Mechanical Fault"
    }
}

USER_DEFINED_FAULT_LABELS = {0: "Normal", 1: "Pre-failure", 2: "Failure"}

def resolve_window_status(status_series):
    if "NOT_WORKING" in status_series.values:
        return "NOT_WORKING"
    elif "FILLED" in status_series.values:
        return "FILLED"
    else:
        return "OK"
    
def horizon_to_steps(horizon: str, freq_minutes: float) -> int:
    horizon_map = {
        "1h": 60,
        "6h": 360,
        "24h": 1440
    }

    if horizon not in horizon_map:
        raise ValueError("Invalid horizon. Use 1h, 6h, 24h")

    return int(horizon_map[horizon] / freq_minutes)

def covert_csv_to_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    '''
    Docstring for covert_csv_to_dataframe
    
    :param df: Description
    '''
    # sensor,window_start,count,avg,min,max,status,label --- original csv columns
    # need to covert the coloums to window_start,sensor_name_n,label,status
    # where n is the sensor number (1,2,3..)
    
    '''
    sensor,window_start,count,avg,min,max,status,label
    Vibration,1771831768,1,0.754,0.754,0.754,OK,0
    Vibration,1771831772,1,1.156,1.156,1.156,OK,1
    Vibration,1771831776,1,0.064,0.064,0.064,OK,0
    Temp,1771831768,1,35.2,35.2,35.2,OK,0
    Temp,1771831772,1,36.5,36.5,36.5,OK,1
    Temp,1771831776,1,34.8,34.8,34.8,OK,0
    Pressure,1771831768,1,101.3,101.3,101.3,OK,0
    Pressure,1771831772,1,102.5,102.5,102.5,OK,1
    Pressure,1771831776,1,100.8,100.8,100.8,OK,0
    '''
    """
    Converts long-format telemetry CSV into wide ML-ready dataframe.

    Input columns:
    sensor, window_start, count, avg, min, max, status, label

    Output:
    window_start, sensor_1, sensor_2, ..., status, label
    """
    if df.empty:
        raise ValueError("Input dataframe is empty")

    # 🔹 Ensure proper sorting
    df = df.sort_values(["window_start", "sensor"])

    # 🔹 Pivot → wide format
    pivot_df = df.pivot(
        index="window_start",
        columns="sensor",
        values="avg"
    )
    
    # 🔹 Rename columns → Vibration → Vibration_avg
    pivot_df.columns = [f"{col}_avg" for col in pivot_df.columns]

    # 🔹 Bring status + label (per window)
    meta_df = df.groupby("window_start").agg({
        "status": resolve_window_status,
        "label": "max"
    })

    # 🔹 Merge
    final_df = pivot_df.join(meta_df)

    # 🔹 Reset index → make window_start a column
    final_df = final_df.reset_index()
    final_df = final_df.reindex(sorted(final_df.columns), axis=1)

    # 🔹 Sort by time
    final_df = final_df.sort_values("window_start")
    logging.info(
    f"Converted CSV to shape: {final_df.shape}, columns: {list(final_df.columns)}")
    
    return final_df

def convert_telemetry_to_dataframe_for_prediction(df: pd.DataFrame) -> pd.DataFrame:
    """
    Converts long-format telemetry into wide ML-ready dataframe for PREDICTION.
    
    Unlike covert_csv_to_dataframe(), this does NOT require a 'label' column,
    since labels don't exist yet during prediction — they are generated 
    afterwards by the equipment-specific labeling function.

    Input columns:
    sensor, window_start, count, avg, min, max, status

    Output:
    window_start, sensor_1_avg, sensor_2_avg, ..., status
    """
    if df.empty:
        raise ValueError("Input dataframe is empty")

    # 🔹 Ensure proper sorting
    df = df.sort_values(["window_start", "sensor"])

    # 🔹 Pivot → wide format
    pivot_df = df.pivot(
        index="window_start",
        columns="sensor",
        values="avg"
    )

    # 🔹 Rename columns → Vibration → Vibration_avg
    pivot_df.columns = [f"{col}_avg" for col in pivot_df.columns]

    # 🔹 Bring status (per window) — NO label
    meta_df = df.groupby("window_start").agg({
        "status": resolve_window_status
    })

    # 🔹 Merge
    final_df = pivot_df.join(meta_df)

    # 🔹 Reset index → make window_start a column
    final_df = final_df.reset_index()
    final_df = final_df.reindex(sorted(final_df.columns), axis=1)

    # 🔹 Sort by time
    final_df = final_df.sort_values("window_start")

    return final_df
    
'''
if prediction_type == "fault" then all the 3 algorithms can be used but if prediction_type is "sensor" then only LSTM can be used since RF and XGBoost are not good for regression problems with time series data.
'''
class TrainService:

    async def train(
        self,
        csv_path: str,
        target_column: str,
        user_model_name: str,
        horizon: str,
        algorithm: str = "random_forest",
        test_size: float = 0.2,
        random_state: int = 42,
        freq_minutes: float = 5
    ) -> Dict[str, Any]:

        # 🔹 Load + preprocess
        df = pd.read_csv(csv_path)
        df = covert_csv_to_dataframe(df)

        if target_column not in df.columns:
            raise ValueError(f"{target_column} not found in dataset")

        df = df.sort_values("window_start")

        steps = horizon_to_steps(horizon, freq_minutes)

        prediction_type = "sensor" if target_column != "label" else "fault"

        # 🔹 Filter valid rows
        if "status" in df.columns:
            df = df[df["status"] == "OK"]

        # 🔹 Feature columns (excludes target but keeps all other sensors)
        feature_cols = [
            col for col in df.columns
            if col not in ["window_start", "status", target_column]
        ]

        # 🔹 Pairwise rolling correlation features
        # For fault prediction: base = feature_cols (label excluded, all sensors present)
        # For sensor prediction: correlations are computed across ALL sensor columns
        # including the target sensor, so cross-correlations like
        # corr_Vibration__Temperature are not lost when Vibration is the target.
        # includes target sensor for sensor prediction so cross-correlations
        # like corr_Vibration__Temperature are not lost when Vibration is the target
        corr_source_cols = [
            col for col in df.columns
            if col not in ["window_start", "status", "label"]
        ]

        for col_a, col_b in combinations(corr_source_cols, 2):
            corr_col = f"corr_{col_a}__{col_b}"
            df[corr_col] = df[col_a].rolling(5, min_periods=2).corr(df[col_b])
            feature_cols.append(corr_col)
        df = df.dropna(subset=[c for c in feature_cols if c.startswith("corr_")])

        # Sensor correlation matrix on raw values before scaling — for frontend heatmap
        sensor_corr_df = df[corr_source_cols].corr().round(3)
        sensor_correlation = {
            "columns": corr_source_cols,
            "matrix": sensor_corr_df.values.tolist()
        }

        # Label / target info
        if prediction_type == "fault":
            label_counts = df["label"].value_counts().sort_index()
            label_info = {
                "distribution": {
                    USER_DEFINED_FAULT_LABELS.get(int(k), str(k)): int(v)
                    for k, v in label_counts.items()
                },
                "total": int(len(df)),
                "imbalance_warning": bool(label_counts.max() / label_counts.sum() > 0.8)
            }
        else:
            label_info = {
                "target": target_column,
                "stats": {
                    "mean": round(float(df[target_column].mean()), 4),
                    "std": round(float(df[target_column].std()), 4),
                    "min": round(float(df[target_column].min()), 4),
                    "max": round(float(df[target_column].max()), 4),
                }
            }

        scaler = StandardScaler()
        df[feature_cols] = scaler.fit_transform(df[feature_cols])
        # =========================================================
        #  LSTM (SEQUENCE MODEL)
        # =========================================================
        if algorithm == "lstm":
            

            seq_length = 10  

            X_seq, y_seq = create_sequences(
                df,
                feature_cols=feature_cols,
                target_col=target_column,
                seq_length=seq_length,
                horizon_steps=steps,
                prediction_type=prediction_type
            )

            if len(X_seq) == 0:
                raise ValueError("Not enough data to create sequences")

            num_classes = int(np.max(y_seq)) + 1 if prediction_type == "fault" else None

            split_idx = int(len(X_seq) * 0.8)
            model = train_lstm(X_seq[:split_idx], y_seq[:split_idx], prediction_type, device=device, num_classes=num_classes)

            if prediction_type == "fault" and len(X_seq[split_idx:]) > 0:
                model.eval()
                with torch.no_grad():
                    X_test_t = torch.tensor(X_seq[split_idx:], dtype=torch.float32).to(device)
                    logits = model(X_test_t).cpu().numpy()
                preds = np.argmax(logits, axis=1)
                cm = confusion_matrix(y_seq[split_idx:], preds, labels=list(range(num_classes))).tolist()
                metrics = {"confusion_matrix": cm}
            else:
                metrics = {"info": "LSTM trained"}

            features_used = feature_cols

        # =========================================================
        #  TABULAR MODELS (RF / XGBOOST)
        # =========================================================
        else:
            # 🔹 create FUTURE label (only for tabular models)
            df[target_column] = df[target_column].shift(-steps)
            df = df.dropna(subset=[target_column])

            drop_cols = [target_column, "window_start"]
            if "status" in df.columns:
                drop_cols.append("status")

            X = df.drop(columns=drop_cols)
            y = df[target_column]

            if algorithm == "random_forest":
                model, metrics = train_random_forest(
                    X, y, test_size=test_size, random_state=random_state
                )

            elif algorithm == "xgboost":
                model, metrics = train_xgboost(
                    X, y, test_size=test_size, random_state=random_state
                )

            else:
                raise ValueError(f"Unsupported algorithm: {algorithm}")

            features_used = list(X.columns)

        # =========================================================
        #  MODEL METADATA
        # =========================================================
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
        model_name = f"{user_model_name}_{timestamp}"

        metadata = {
            "algorithm": algorithm,
            "target_column": target_column,
            "horizon": horizon,
            "metrics": metrics,
            "trained_at": timestamp,
            "prediction_type": prediction_type,
            "freq_minutes": freq_minutes,
            "rows": len(df),
            "features": features_used,
            "correlation_pairs": [[a, b] for a, b in combinations(corr_source_cols, 2)]
        }

        #  Extra metadata for LSTM
        if algorithm == "lstm":
            metadata.update({
                "sequence_length": seq_length,
                "horizon_steps": steps,
                "num_classes": num_classes
            })

        model_to_store = (model, scaler) if algorithm == "lstm" else model
        await store_model(model_name, model_to_store, metadata)

        return {
            "model_name": model_name,
            "metrics": metrics,
            "metadata": metadata,
            "sensor_correlation": sensor_correlation,
            "label_info": label_info
        }


    async def train_specific_model(
        self,
        labeled_data: list,
        target_column: str,
        user_model_name: str,
        horizon: str,
        equipment_type: str,
        thresholds: dict,
        algorithm: str = "random_forest",
        test_size: float = 0.2,
        random_state: int = 42,
        freq_minutes: float = 5
    ) -> Dict[str, Any]:
        '''
        if prediction_type == "fault" then all the 3 algorithms can be used but if prediction_type is "sensor" then only LSTM can be used since RF and XGBoost are not good for regression problems with time series data.
        '''
        df = pd.DataFrame(labeled_data)

        # 🔹 Convert telemetry → wide format
        df = covert_csv_to_dataframe(df)

        # ---------------------------------
        # 🔹 Equipment specific labeling
        # ---------------------------------
        if equipment_type not in EQUIPMENT_LABELERS:
            raise ValueError(f"Unsupported equipment type: {equipment_type}")

        label_function = EQUIPMENT_LABELERS[equipment_type]
        df = label_function(df, thresholds)

        df = df.sort_values("window_start")

        steps = horizon_to_steps(horizon, freq_minutes)

        prediction_type = "sensor" if target_column != "label" else "fault"

        # ---------------------------------
        # 🔹 Filter valid rows
        # ---------------------------------
        if "status" in df.columns:
            df = df[df["status"] == "OK"]

        # 🔹 Feature columns
        feature_cols = [
            col for col in df.columns
            if col not in ["window_start", "status", target_column]
        ]

        corr_source_cols = [
            col for col in df.columns
            if col not in ["window_start", "status", "label"]
        ]

        # Sensor correlation matrix on raw values before scaling — for frontend heatmap
        sensor_corr_df = df[corr_source_cols].corr().round(3)
        sensor_correlation = {
            "columns": corr_source_cols,
            "matrix": sensor_corr_df.values.tolist()
        }

        # Label distribution with equipment-specific class names
        label_counts = df["label"].value_counts().sort_index()
        _fault_labels = EQUIPMENT_FAULT_LABELS.get(equipment_type, {})
        label_info = {
            "distribution": {
                _fault_labels.get(int(k), f"Class {k}"): int(v)
                for k, v in label_counts.items()
            },
            "total": int(len(df)),
            "imbalance_warning": bool(label_counts.max() / label_counts.sum() > 0.8)
        }

        scaler = StandardScaler()
        df[feature_cols] = scaler.fit_transform(df[feature_cols])
        # =========================================================
        # LSTM (SEQUENCE MODEL)
        # =========================================================
        if algorithm == "lstm":

            seq_length = 10

            X_seq, y_seq = create_sequences(
                df,
                feature_cols=feature_cols,
                target_col=target_column,
                seq_length=seq_length,
                horizon_steps=steps,
                prediction_type=prediction_type,
                thresholds=thresholds
            )

            if len(X_seq) == 0:
                raise ValueError("Not enough data to create sequences")

            num_classes = int(np.max(y_seq)) + 1 if prediction_type == "fault" else None

            split_idx = int(len(X_seq) * 0.8)
            model = train_lstm(X_seq[:split_idx], y_seq[:split_idx], prediction_type, device=device, num_classes=num_classes)

            if prediction_type == "fault" and len(X_seq[split_idx:]) > 0:
                model.eval()
                with torch.no_grad():
                    X_test_t = torch.tensor(X_seq[split_idx:], dtype=torch.float32).to(device)
                    logits = model(X_test_t).cpu().numpy()
                preds = np.argmax(logits, axis=1)
                cm = confusion_matrix(y_seq[split_idx:], preds, labels=list(range(num_classes))).tolist()
                metrics = {"confusion_matrix": cm}
            else:
                metrics = {"info": "LSTM trained"}

            features_used = feature_cols

        # =========================================================
        # TABULAR MODELS (RF / XGBOOST)
        # =========================================================
        else:

            # 🔹 create FUTURE label (ONLY for tabular models)
            df[target_column] = df[target_column].shift(-steps)
            df = df.dropna(subset=[target_column])

            drop_cols = [target_column, "window_start"]
            if "status" in df.columns:
                drop_cols.append("status")

            X = df.drop(columns=drop_cols)
            y = df[target_column]

            if algorithm == "random_forest":
                model, metrics = train_random_forest(
                    X, y, test_size=test_size, random_state=random_state
                )

            elif algorithm == "xgboost":
                model, metrics = train_xgboost(
                    X, y, test_size=test_size, random_state=random_state
                )

            else:
                raise ValueError(f"Unsupported algorithm: {algorithm}")

            features_used = list(X.columns)

        # =========================================================
        # 🔹 MODEL METADATA
        # =========================================================
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
        model_name = f"{user_model_name}_{timestamp}"

        metadata = {
            "algorithm": algorithm,
            "equipment_type": equipment_type,
            "target_column": target_column,
            "horizon": horizon,
            "metrics": metrics,
            "prediction_type": prediction_type,
            "trained_at": timestamp,
            "freq_minutes": freq_minutes,
            "rows": len(df),
            "features": features_used
        }

        # 🔹 Extra metadata for LSTM
        if algorithm == "lstm":
            metadata.update({
                "sequence_length": seq_length,
                "horizon_steps": steps,
                "num_classes": num_classes
            })

        model_to_store = (model, scaler) if algorithm == "lstm" else model
        await store_model(model_name, model_to_store, metadata)

        return {
            "model_name": model_name,
            "metrics": metrics,
            "metadata": metadata,
            "sensor_correlation": sensor_correlation,
            "label_info": label_info
        }

    @staticmethod
    async def future_predict(data, model, metadata, freq_minutes_override: float = None):
        '''
        if prediction_type == "fault" then all the 3 algorithms can be used but if prediction_type is "sensor" then only LSTM can be used since RF and XGBoost are not good for regression problems with time series data.
        '''
        if not data:
            logging.error("No data received for prediction.")
            return None

        # 🔹 Convert
        df = pd.DataFrame(data)
        df = covert_csv_to_dataframe(df)
        df = df.sort_values("window_start")

        # 🔹 Recompute correlation features used during training
        corr_pairs = metadata.get("correlation_pairs", [])
        for col_a, col_b in corr_pairs:
            corr_col = f"corr_{col_a}__{col_b}"
            df[corr_col] = df[col_a].rolling(5, min_periods=2).corr(df[col_b]).fillna(0)

        # Live sensor correlation from the incoming data window
        live_sensor_cols = [
            c for c in df.columns
            if not c.startswith("corr_") and c not in ["window_start", "status", "label"]
        ]
        live_corr = df[live_sensor_cols].corr().round(3)
        sensor_correlation = {
            "columns": live_sensor_cols,
            "matrix": live_corr.values.tolist(),
            "data_points": len(df)
        }

        expected_features = metadata.get("features", [])
        horizon = metadata.get("horizon")
        freq_minutes = freq_minutes_override if freq_minutes_override is not None else metadata.get("freq_minutes", 5)
        algorithm = metadata.get("algorithm")
        prediction_type = metadata.get("prediction_type")
        fault_labels = EQUIPMENT_FAULT_LABELS.get(metadata.get("equipment_type"), USER_DEFINED_FAULT_LABELS)
        predicted_label = None
        named_probs = None

        # 🔹 Validate features
        missing_features = [
            col for col in expected_features if col not in df.columns
        ]
        if missing_features:
            raise ValueError(f"Missing features: {missing_features}")

        steps = horizon_to_steps(horizon, freq_minutes)

        # =========================================================
        # LSTM
        # =========================================================
        if algorithm == "lstm":

            seq_len = metadata.get("sequence_length")

            if len(df) < seq_len:
                raise ValueError("Not enough data for LSTM")

            seq_df = df.iloc[-seq_len:][expected_features]

            scaler = None
            if isinstance(model, tuple):
                model, scaler = model
            if scaler is not None:
                seq = scaler.transform(seq_df)
            else:
                seq = seq_df.values

            X = torch.tensor(seq, dtype=torch.float32).unsqueeze(0).to(device)
            model = model.to(device)
            model.eval()
            with torch.no_grad():
                output = model(X).cpu().numpy().flatten()
                output = np.nan_to_num(output, nan=0.0, posinf=1.0, neginf=-1.0)

            base_ts = df["window_start"].iloc[-1]

            timestamps = [
                base_ts + (i + 1) * freq_minutes * 60
                for i in range(steps)
            ]

            # 🔹 Fault
            if prediction_type == "fault":
                logits = torch.tensor(output)
                class_probs = torch.softmax(logits, dim=0).numpy().tolist()
                predicted_class = int(np.argmax(class_probs))
                # replicate across all steps — LSTM answers "worst state in horizon",
                # not a per-step prediction, so every timestamp gets the same class
                values = [predicted_class] * steps
                probs = [class_probs] * steps
                confidence = [max(class_probs)] * steps
                predicted_label = fault_labels.get(predicted_class, str(predicted_class))
                named_probs = {fault_labels.get(i, f"Class {i}"): round(p, 4) for i, p in enumerate(class_probs)}

                # confusion matrix on historical labeled sequences
                cm = None
                if "label" in df.columns and len(df) > seq_len:
                    try:
                        num_classes = metadata.get("num_classes", 3)
                        feat_vals = df[expected_features].values
                        label_vals = df["label"].values
                        n = len(df) - seq_len
                        hist_X = np.array([feat_vals[i:i+seq_len] for i in range(n)])
                        hist_y = np.array([int(label_vals[i+seq_len]) for i in range(n)])
                        if scaler is not None:
                            s, t, f = hist_X.shape
                            hist_X = scaler.transform(pd.DataFrame(hist_X.reshape(-1, f), columns=expected_features)).reshape(s, t, f)
                        X_hist = torch.tensor(hist_X, dtype=torch.float32).to(device)
                        with torch.no_grad():
                            hist_preds = np.argmax(model(X_hist).cpu().numpy(), axis=1)
                        cm = confusion_matrix(hist_y, hist_preds, labels=list(range(num_classes))).tolist()
                    except Exception:
                        cm = None

            # 🔹 Sensor
            else:
                values = [
                    float(x) if np.isfinite(x) else 0.0
                    for x in output.tolist()
                ]
                probs = None
                confidence = [1.0] * len(values)
                cm = None

            return {
                "timestamps": timestamps,
                "values": values,
                "probabilities": probs,
                "confidence": confidence,
                "confusion_matrix": cm,
                "sensor_correlation": sensor_correlation,
                "predicted_label": predicted_label,
                "named_probabilities": named_probs,
                "meta": {
                    "type": prediction_type,
                    "mode": "multi_step",
                    "horizon": horizon
                }
            }

        # =========================================================
        # RF / XGBOOST
        # =========================================================
        else:

            latest_row = df.iloc[-1:]
            X = latest_row[expected_features]

            y_pred = model.predict(X)

            if hasattr(model, "predict_proba"):
                y_prob = model.predict_proba(X)
            else:
                y_prob = None

            timestamp = latest_row["window_start"].iloc[0]

            timestamps = [
                timestamp + (i + 1) * freq_minutes * 60
                for i in range(steps)
            ]

            values = [y_pred[0]] * steps

            # 🔹 Fault
            if prediction_type == "fault" and y_prob is not None:
                base_prob = y_prob[0]
                probs = [base_prob.tolist()] * steps
                confidence = [max(base_prob)] * steps
                predicted_label = fault_labels.get(int(values[0]), str(int(values[0])))
                named_probs = {fault_labels.get(i, f"Class {i}"): round(p, 4) for i, p in enumerate(base_prob)}
            else:
                probs = None
                confidence = [1.0] * steps

            # 🔹 Confusion Matrix (optional)
            cm = None
            if prediction_type == "fault" and "label" in df.columns and len(df) >= steps:
                try:
                    y_true = df["label"].iloc[-steps:].tolist()
                    if y_true:
                        y_pred_expanded = values[:len(y_true)]
                        cm = confusion_matrix(y_true, y_pred_expanded).tolist()
                except Exception:
                    cm = None

            return {
                "timestamps": timestamps,
                "values": values,
                "probabilities": probs,
                "confidence": confidence,
                "confusion_matrix": cm,
                "sensor_correlation": sensor_correlation,
                "predicted_label": predicted_label,
                "named_probabilities": named_probs,
                "meta": {
                    "type": prediction_type,
                    "mode": "single_step",
                    "horizon": horizon
                }
            }

    @staticmethod
    async def predict_future_asset(df: pd.DataFrame, model, metadata: dict, freq_minutes_override: float = None) -> dict:
        '''
    if prediction_type == "fault" then all the 3 algorithms can be used but if prediction_type is "sensor" then only LSTM can be used since RF and XGBoost are not good for regression problems with time series data.
        '''

        if df.empty:
            logging.error("Empty DataFrame received for asset prediction.")
            return None

        df = df.sort_values("window_start")

        # 🔹 Recompute correlation features used during training
        corr_pairs = metadata.get("correlation_pairs", [])
        for col_a, col_b in corr_pairs:
            corr_col = f"corr_{col_a}__{col_b}"
            df[corr_col] = df[col_a].rolling(5, min_periods=2).corr(df[col_b]).fillna(0)

        # Live sensor correlation from the incoming data window
        live_sensor_cols = [
            c for c in df.columns
            if not c.startswith("corr_") and c not in ["window_start", "status", "label"]
        ]
        live_corr = df[live_sensor_cols].corr().round(3)
        sensor_correlation = {
            "columns": live_sensor_cols,
            "matrix": live_corr.values.tolist(),
            "data_points": len(df)
        }

        expected_features = metadata.get("features", [])
        horizon = metadata.get("horizon")
        freq_minutes = freq_minutes_override if freq_minutes_override is not None else metadata.get("freq_minutes", 5)
        algorithm = metadata.get("algorithm")
        prediction_type = metadata.get("prediction_type")
        fault_labels = EQUIPMENT_FAULT_LABELS.get(metadata.get("equipment_type"), USER_DEFINED_FAULT_LABELS)
        predicted_label = None
        named_probs = None

        # 🔹 Validate features
        missing_features = [
            col for col in expected_features if col not in df.columns
        ]
        if missing_features:
            raise ValueError(f"Missing features: {missing_features}")

        steps = horizon_to_steps(horizon, freq_minutes)

        # =========================================================
        # 🔵 LSTM
        # =========================================================
        if algorithm == "lstm":

            seq_len = metadata.get("sequence_length")

            if len(df) < seq_len:
                raise ValueError("Not enough data for LSTM prediction")

            seq_df = df.iloc[-seq_len:][expected_features]

            scaler = None
            if isinstance(model, tuple):
                model, scaler = model
            if scaler is not None:
                seq = scaler.transform(seq_df)
            else:
                seq = seq_df.values

            X = torch.tensor(seq, dtype=torch.float32).unsqueeze(0).to(device)
            model = model.to(device)

            model.eval()
            with torch.no_grad():
                output = model(X).cpu().numpy().flatten()
                output = np.nan_to_num(output, nan=0.0, posinf=1.0, neginf=-1.0)
            base_ts = df["window_start"].iloc[-1]

            timestamps = [
                base_ts + (i + 1) * freq_minutes * 60
                for i in range(steps)
            ]

            if prediction_type == "fault":
                logits = torch.tensor(output)
                class_probs = torch.softmax(logits, dim=0).numpy().tolist()
                predicted_class = int(np.argmax(class_probs))
                # replicate across all steps — LSTM answers "worst state in horizon",
                # not a per-step prediction, so every timestamp gets the same class
                values = [predicted_class] * steps
                probs = [class_probs] * steps
                confidence = [max(class_probs)] * steps
                predicted_label = fault_labels.get(predicted_class, str(predicted_class))
                named_probs = {fault_labels.get(i, f"Class {i}"): round(p, 4) for i, p in enumerate(class_probs)}

                # confusion matrix on historical labeled sequences
                cm = None
                if "label" in df.columns and len(df) > seq_len:
                    try:
                        num_classes = metadata.get("num_classes", 3)
                        feat_vals = df[expected_features].values
                        label_vals = df["label"].values
                        n = len(df) - seq_len
                        hist_X = np.array([feat_vals[i:i+seq_len] for i in range(n)])
                        hist_y = np.array([int(label_vals[i+seq_len]) for i in range(n)])
                        if scaler is not None:
                            s, t, f = hist_X.shape
                            hist_X = scaler.transform(pd.DataFrame(hist_X.reshape(-1, f), columns=expected_features)).reshape(s, t, f)
                        X_hist = torch.tensor(hist_X, dtype=torch.float32).to(device)
                        with torch.no_grad():
                            hist_preds = np.argmax(model(X_hist).cpu().numpy(), axis=1)
                        cm = confusion_matrix(hist_y, hist_preds, labels=list(range(num_classes))).tolist()
                    except Exception:
                        cm = None
            else:
                values = [
                    float(x) if np.isfinite(x) else 0.0
                    for x in output.tolist()
                ]
                probs = None
                confidence = [1.0] * len(values)
                cm = None

            return {
                "timestamps": timestamps,
                "values": values,
                "probabilities": probs,
                "confidence": confidence,
                "confusion_matrix": cm,
                "sensor_correlation": sensor_correlation,
                "predicted_label": predicted_label,
                "named_probabilities": named_probs,
                "meta": {
                    "type": prediction_type,
                    "mode": "multi_step",
                    "horizon": horizon
                }
            }

        # =========================================================
        # 🟢 RF / XGBOOST
        # =========================================================
        else:

            latest_row = df.iloc[-1:]
            X = latest_row[expected_features]

            y_pred = model.predict(X)

            if hasattr(model, "predict_proba"):
                y_prob = model.predict_proba(X)
            else:
                y_prob = None

            timestamp = latest_row["window_start"].iloc[0]

            timestamps = [
                timestamp + (i + 1) * freq_minutes * 60
                for i in range(steps)
            ]

            values = [y_pred[0]] * steps

            if prediction_type == "fault" and y_prob is not None:
                base_prob = y_prob[0]
                probs = [base_prob.tolist()] * steps
                confidence = [max(base_prob)] * steps
                predicted_label = fault_labels.get(int(values[0]), str(int(values[0])))
                named_probs = {fault_labels.get(i, f"Class {i}"): round(p, 4) for i, p in enumerate(base_prob)}
            else:
                probs = None
                confidence = [1.0] * steps

            # 🔹 Optional confusion matrix
            cm = None
            if prediction_type == "fault" and "label" in df.columns and len(df) >= steps:
                try:
                    y_true = df["label"].iloc[-steps:].tolist()
                    if y_true:
                        y_pred_expanded = values[:len(y_true)]
                        cm = confusion_matrix(y_true, y_pred_expanded).tolist()
                except Exception:
                    cm = None

            return {
                "timestamps": timestamps,
                "values": values,
                "probabilities": probs,
                "confidence": confidence,
                "confusion_matrix": cm,
                "sensor_correlation": sensor_correlation,
                "predicted_label": predicted_label,
                "named_probabilities": named_probs,
                "meta": {
                    "type": prediction_type,
                    "mode": "single_step",
                    "horizon": horizon
                }
            }