import pytest
import pickle
import json
from unittest.mock import AsyncMock, patch

from Predictive_ML.ml.model_store import (
    store_model,
    load_model,
    delete_model,
    list_models
)


# -------------------------------
# TEST: store_model
# -------------------------------
@pytest.mark.asyncio
@patch("Predictive_ML.ml.model_store.redis_client_binary")
async def test_store_model(mock_redis):

    mock_redis.set = AsyncMock()
    mock_redis.sadd = AsyncMock()

    model = {"name": "test_model"}
    metadata = {"accuracy": 0.95}

    await store_model(
        model_name="rf_model",
        model=model,
        metadata=metadata
    )

    # set called twice
    assert mock_redis.set.call_count == 2

    # model registry updated
    mock_redis.sadd.assert_called_once_with(
        "ml:model:list",
        "rf_model"
    )


# -------------------------------
# TEST: load_model SUCCESS
# -------------------------------
@pytest.mark.asyncio
@patch("Predictive_ML.ml.model_store.redis_client_binary")
async def test_load_model_success(mock_redis):

    model = {"name": "test_model"}
    metadata = {"accuracy": 0.95}

    model_blob = pickle.dumps(model)
    metadata_blob = json.dumps(metadata)

    mock_redis.get = AsyncMock(
        side_effect=[
            model_blob,
            metadata_blob
        ]
    )

    loaded_model, loaded_metadata = await load_model("rf_model")

    assert loaded_model == model
    assert loaded_metadata == metadata


# -------------------------------
# TEST: load_model NOT FOUND
# -------------------------------
@pytest.mark.asyncio
@patch("Predictive_ML.ml.model_store.redis_client_binary")
async def test_load_model_not_found(mock_redis):

    mock_redis.get = AsyncMock(return_value=None)

    model, metadata = await load_model("missing_model")

    assert model is None
    assert metadata is None


# -------------------------------
# TEST: delete_model
# -------------------------------
@pytest.mark.asyncio
@patch("Predictive_ML.ml.model_store.redis_client_binary")
async def test_delete_model(mock_redis):

    mock_redis.delete = AsyncMock()
    mock_redis.srem = AsyncMock()

    await delete_model("rf_model")

    # delete called twice
    assert mock_redis.delete.call_count == 2

    mock_redis.srem.assert_called_once_with(
        "ml:model:list",
        "rf_model"
    )


# -------------------------------
# TEST: list_models
# -------------------------------
@pytest.mark.asyncio
@patch("Predictive_ML.ml.model_store.redis_client_binary")
async def test_list_models(mock_redis):

    mock_redis.smembers = AsyncMock(
        return_value={"model1", "model2"}
    )

    models = await list_models()

    assert isinstance(models, list)
    assert "model1" in models
    assert "model2" in models