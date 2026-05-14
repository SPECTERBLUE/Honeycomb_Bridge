import pytest
import numpy as np
from unittest.mock import AsyncMock, MagicMock, patch

from Predictive_ML.ml.prediction import (
    convert_numpy,
    predict
)


# ------------------------------------------------
# TEST: convert_numpy with numpy types
# ------------------------------------------------
def test_convert_numpy():

    data = {
        "int": np.int64(10),
        "float": np.float32(2.5),
        "array": np.array([1, 2, 3]),
        "nested": {
            "value": np.int32(5)
        }
    }

    result = convert_numpy(data)

    assert isinstance(result["int"], int)
    assert isinstance(result["float"], float)
    assert isinstance(result["array"], list)
    assert isinstance(result["nested"]["value"], int)


# ------------------------------------------------
# TEST: predict SUCCESS
# ------------------------------------------------
@pytest.mark.asyncio
@patch("Predictive_ML.ml.prediction.store_prediction")
@patch("Predictive_ML.ml.prediction.TrainService.future_predict")
@patch("Predictive_ML.ml.prediction.load_model")
@patch("Predictive_ML.ml.prediction.redis_client")
@patch("Predictive_ML.ml.prediction.FetchAssetsTelemetry")
async def test_predict_success(
    mock_fetch,
    mock_redis,
    mock_load_model,
    mock_future_predict,
    mock_store_prediction
):

    # Mock telemetry fetch
    mock_fetch.return_value.get_telemetry_data_asset.return_value = [
        {
            "name": "Temp",
            "time": 100,
            "value": 25
        }
    ]

    # Mock redis values
    mock_redis.get = AsyncMock(
        side_effect=[
            "10",     # window length
            None      # threshold map
        ]
    )

    # Mock model loading
    mock_load_model.return_value = (
        MagicMock(),
        {
            "horizon": "1h"
        }
    )

    # Mock predictions
    mock_future_predict.return_value = {
        "timestamps": [100],
        "values": [0],
        "confidence": [0.9]
    }

    mock_store_prediction.return_value = AsyncMock()

    result = await predict(
        model_name="rf_model",
        asset_id="asset_1"
    )

    assert result["status"] == "success"
    assert result["asset_id"] == "asset_1"
    assert result["model_name"] == "rf_model"

    assert "data" in result
    assert "timestamps" in result["data"]


# ------------------------------------------------
# TEST: predict NO telemetry
# ------------------------------------------------
@pytest.mark.asyncio
@patch("Predictive_ML.ml.prediction.FetchAssetsTelemetry")
async def test_predict_no_telemetry(mock_fetch):

    mock_fetch.return_value.get_telemetry_data_asset.return_value = None

    result = await predict(
        model_name="rf_model",
        asset_id="asset_1"
    )

    assert result is None


# ------------------------------------------------
# TEST: predict default window length
# ------------------------------------------------
@pytest.mark.asyncio
@patch("Predictive_ML.ml.prediction.store_prediction")
@patch("Predictive_ML.ml.prediction.TrainService.future_predict")
@patch("Predictive_ML.ml.prediction.load_model")
@patch("Predictive_ML.ml.prediction.redis_client")
@patch("Predictive_ML.ml.prediction.FetchAssetsTelemetry")
async def test_predict_default_window(
    mock_fetch,
    mock_redis,
    mock_load_model,
    mock_future_predict,
    mock_store_prediction
):

    mock_fetch.return_value.get_telemetry_data_asset.return_value = [
        {
            "name": "Temp",
            "time": 100,
            "value": 25
        }
    ]

    # No window length in redis
    mock_redis.get = AsyncMock(
        side_effect=[
            None,
            None
        ]
    )

    mock_load_model.return_value = (
        MagicMock(),
        {
            "horizon": "1h"
        }
    )

    mock_future_predict.return_value = {
        "timestamps": [100],
        "values": [1]
    }

    result = await predict(
        model_name="rf_model",
        asset_id="asset_1"
    )

    assert result["status"] == "success"


# ------------------------------------------------
# TEST: store_prediction called
# ------------------------------------------------
@pytest.mark.asyncio
@patch("Predictive_ML.ml.prediction.store_prediction")
@patch("Predictive_ML.ml.prediction.TrainService.future_predict")
@patch("Predictive_ML.ml.prediction.load_model")
@patch("Predictive_ML.ml.prediction.redis_client")
@patch("Predictive_ML.ml.prediction.FetchAssetsTelemetry")
async def test_store_prediction_called(
    mock_fetch,
    mock_redis,
    mock_load_model,
    mock_future_predict,
    mock_store_prediction
):

    mock_fetch.return_value.get_telemetry_data_asset.return_value = [
        {
            "name": "Temp",
            "time": 100,
            "value": 25
        }
    ]

    mock_redis.get = AsyncMock(
        side_effect=[
            "10",
            None
        ]
    )

    mock_load_model.return_value = (
        MagicMock(),
        {
            "horizon": "1h"
        }
    )

    mock_future_predict.return_value = {
        "timestamps": [100],
        "values": [1]
    }

    await predict(
        model_name="rf_model",
        asset_id="asset_1"
    )

    mock_store_prediction.assert_called_once()