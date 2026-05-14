import pytest
import json
from unittest.mock import AsyncMock, patch

from Predictive_ML.ml.predition_store import store_prediction


# ------------------------------------------------
# TEST: store_prediction SUCCESS
# ------------------------------------------------
@pytest.mark.asyncio
@patch("Predictive_ML.ml.predition_store.redis_client")
async def test_store_prediction_success(mock_redis):

    mock_redis.set = AsyncMock()

    prediction_data = {
        "asset_id": "asset_1",
        "model_name": "rf_model",
        "horizon": "1h",
        "data": {
            "values": [0, 1]
        }
    }

    await store_prediction(prediction_data)

    expected_key = "prediction:asset_1:rf_model:1h"

    mock_redis.set.assert_called_once_with(
        expected_key,
        json.dumps(prediction_data)
    )


# ------------------------------------------------
# TEST: missing asset_id
# ------------------------------------------------
@pytest.mark.asyncio
@patch("Predictive_ML.ml.predition_store.redis_client")
async def test_store_prediction_missing_asset_id(mock_redis):

    mock_redis.set = AsyncMock()

    prediction_data = {
        "model_name": "rf_model",
        "horizon": "1h"
    }

    with pytest.raises(KeyError):
        await store_prediction(prediction_data)


# ------------------------------------------------
# TEST: missing model_name
# ------------------------------------------------
@pytest.mark.asyncio
@patch("Predictive_ML.ml.predition_store.redis_client")
async def test_store_prediction_missing_model_name(mock_redis):

    mock_redis.set = AsyncMock()

    prediction_data = {
        "asset_id": "asset_1",
        "horizon": "1h"
    }

    with pytest.raises(KeyError):
        await store_prediction(prediction_data)


# ------------------------------------------------
# TEST: missing horizon
# ------------------------------------------------
@pytest.mark.asyncio
@patch("Predictive_ML.ml.predition_store.redis_client")
async def test_store_prediction_missing_horizon(mock_redis):

    mock_redis.set = AsyncMock()

    prediction_data = {
        "asset_id": "asset_1",
        "model_name": "rf_model"
    }

    with pytest.raises(KeyError):
        await store_prediction(prediction_data)


# ------------------------------------------------
# TEST: empty prediction data
# ------------------------------------------------
@pytest.mark.asyncio
@patch("Predictive_ML.ml.predition_store.redis_client")
async def test_store_prediction_empty(mock_redis):

    mock_redis.set = AsyncMock()

    prediction_data = {
        "asset_id": "",
        "model_name": "",
        "horizon": ""
    }

    await store_prediction(prediction_data)

    mock_redis.set.assert_called_once()