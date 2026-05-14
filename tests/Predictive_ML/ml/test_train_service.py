import pytest
import pandas as pd
import numpy as np
from unittest.mock import patch, AsyncMock, MagicMock

from Predictive_ML.ml.train_service import (
    resolve_window_status,
    horizon_to_steps,
    covert_csv_to_dataframe,
    convert_telemetry_to_dataframe_for_prediction,
    create_sequences,
    TrainService
)


# =========================================================
# FIXTURE
# =========================================================
@pytest.fixture
def sample_long_df():

    rows = []

    # enough rows for LSTM sequence creation
    for i in range(1, 25):

        rows.append({
            "sensor": "Temp",
            "window_start": i,
            "avg": float(i * 10),
            "status": "OK",
            "label": i % 3
        })

        rows.append({
            "sensor": "Pressure",
            "window_start": i,
            "avg": float(i * 20),
            "status": "OK",
            "label": i % 3
        })

    return pd.DataFrame(rows)


# =========================================================
# resolve_window_status
# =========================================================
def test_resolve_window_status():

    s1 = pd.Series(["OK"])
    assert resolve_window_status(s1) == "OK"

    s2 = pd.Series(["OK", "FILLED"])
    assert resolve_window_status(s2) == "FILLED"

    s3 = pd.Series(["OK", "NOT_WORKING"])
    assert resolve_window_status(s3) == "NOT_WORKING"


# =========================================================
# horizon_to_steps
# =========================================================
def test_horizon_to_steps():

    assert horizon_to_steps("1h", 5) == 12
    assert horizon_to_steps("6h", 10) == 36
    assert horizon_to_steps("24h", 15) == 96

    with pytest.raises(ValueError):
        horizon_to_steps("2h", 5)


# =========================================================
# covert_csv_to_dataframe
# =========================================================
def test_covert_csv_to_dataframe(sample_long_df):

    result = covert_csv_to_dataframe(sample_long_df)

    assert "Temp_avg" in result.columns
    assert "Pressure_avg" in result.columns
    assert "status" in result.columns
    assert "label" in result.columns

    assert len(result) > 0


def test_covert_csv_to_dataframe_empty():

    with pytest.raises(ValueError):
        covert_csv_to_dataframe(pd.DataFrame())


# =========================================================
# convert_telemetry_to_dataframe_for_prediction
# =========================================================
def test_convert_telemetry_prediction(sample_long_df):

    df = sample_long_df.drop(columns=["label"])

    result = convert_telemetry_to_dataframe_for_prediction(df)

    assert "Temp_avg" in result.columns
    assert "Pressure_avg" in result.columns
    assert "status" in result.columns


# =========================================================
# create_sequences fault
# =========================================================
def test_create_sequences_fault():

    df = pd.DataFrame({
        "Temp_avg": list(range(30)),
        "label": [i % 3 for i in range(30)]
    })

    X, y = create_sequences(
        df=df,
        feature_cols=["Temp_avg"],
        target_col="label",
        seq_length=5,
        horizon_steps=1,
        prediction_type="fault"
    )

    assert len(X) > 0
    assert len(y) > 0


# =========================================================
# create_sequences sensor
# =========================================================
def test_create_sequences_sensor():

    df = pd.DataFrame({
        "Temp_avg": list(range(30))
    })

    X, y = create_sequences(
        df=df,
        feature_cols=["Temp_avg"],
        target_col="Temp_avg",
        seq_length=5,
        horizon_steps=1,
        prediction_type="sensor"
    )

    assert len(X) > 0
    assert len(y) > 0


# =========================================================
# TRAIN RANDOM FOREST SUCCESS
# =========================================================
@pytest.mark.asyncio
@patch("Predictive_ML.ml.train_service.store_model")
@patch("Predictive_ML.ml.train_service.train_random_forest")
@patch("pandas.read_csv")
async def test_train_random_forest_success(
    mock_read_csv,
    mock_train_rf,
    mock_store_model,
    sample_long_df
):

    mock_read_csv.return_value = sample_long_df

    mock_train_rf.return_value = (
        MagicMock(),
        {"accuracy": 0.95}
    )

    mock_store_model.return_value = AsyncMock()

    service = TrainService()

    result = await service.train(
        csv_path="dummy.csv",
        target_column="label",
        user_model_name="rf_model",
        horizon="1h",
        algorithm="random_forest"
    )

    assert "model_name" in result
    assert "metrics" in result
    assert result["metadata"]["algorithm"] == "random_forest"


# =========================================================
# TRAIN XGBOOST SUCCESS
# =========================================================
@pytest.mark.asyncio
@patch("Predictive_ML.ml.train_service.store_model")
@patch("Predictive_ML.ml.train_service.train_xgboost")
@patch("pandas.read_csv")
async def test_train_xgboost_success(
    mock_read_csv,
    mock_train_xgb,
    mock_store_model,
    sample_long_df
):

    mock_read_csv.return_value = sample_long_df

    mock_train_xgb.return_value = (
        MagicMock(),
        {"accuracy": 0.90}
    )

    mock_store_model.return_value = AsyncMock()

    service = TrainService()

    result = await service.train(
        csv_path="dummy.csv",
        target_column="label",
        user_model_name="xgb_model",
        horizon="1h",
        algorithm="xgboost"
    )

    assert result["metadata"]["algorithm"] == "xgboost"


# =========================================================
# TRAIN LSTM SUCCESS
# =========================================================
@pytest.mark.asyncio
@patch("Predictive_ML.ml.train_service.store_model")
@patch("Predictive_ML.ml.train_service.train_lstm")
@patch("pandas.read_csv")
async def test_train_lstm_success(
    mock_read_csv,
    mock_train_lstm,
    mock_store_model,
    sample_long_df
):

    mock_read_csv.return_value = sample_long_df

    # ----------------------------------------
    # Fake LSTM output tensor
    # ----------------------------------------
    fake_output = MagicMock()

    # ONLY ONE prediction
    fake_output.cpu.return_value.numpy.return_value = np.array([
        [0.1, 0.7, 0.2]
    ])

    # ----------------------------------------
    # Fake model
    # ----------------------------------------
    fake_model = MagicMock()

    fake_model.eval = MagicMock()

    # model(X) returns fake_output
    fake_model.return_value = fake_output

    mock_train_lstm.return_value = fake_model

    mock_store_model.return_value = AsyncMock()

    service = TrainService()

    result = await service.train(
        csv_path="dummy.csv",
        target_column="label",
        user_model_name="lstm_model",
        horizon="1h",
        algorithm="lstm"
    )

    assert result["metadata"]["algorithm"] == "lstm"

    assert "model_name" in result
    assert "metrics" in result

# =========================================================
# INVALID TARGET COLUMN
# =========================================================
@pytest.mark.asyncio
@patch("pandas.read_csv")
async def test_train_invalid_target(
    mock_read_csv,
    sample_long_df
):

    mock_read_csv.return_value = sample_long_df

    service = TrainService()

    with pytest.raises(ValueError):
        await service.train(
            csv_path="dummy.csv",
            target_column="invalid_target",
            user_model_name="model",
            horizon="1h"
        )


# =========================================================
# FUTURE PREDICT RF
# =========================================================
@pytest.mark.asyncio
async def test_future_predict_rf():

    data = [
        {
            "sensor": "Temp",
            "window_start": i,
            "avg": float(i * 10),
            "status": "OK",
            "label": i % 2
        }
        for i in range(1, 25)
    ]

    model = MagicMock()

    model.predict.return_value = np.array([1])

    model.predict_proba.return_value = np.array([
        [0.2, 0.8]
    ])

    metadata = {
        "features": ["Temp_avg"],
        "horizon": "1h",
        "freq_minutes": 5,
        "algorithm": "random_forest",
        "prediction_type": "fault"
    }

    result = await TrainService.future_predict(
        data,
        model,
        metadata
    )

    assert "timestamps" in result
    assert "values" in result
    assert "confidence" in result
    assert "meta" in result


# =========================================================
# FUTURE PREDICT EMPTY
# =========================================================
@pytest.mark.asyncio
async def test_future_predict_empty():

    result = await TrainService.future_predict(
        [],
        MagicMock(),
        {}
    )

    assert result is None