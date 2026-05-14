import pytest
import requests
from unittest.mock import patch, MagicMock

from Predictive_ML.fetch_assets_telemetry import FetchAssetsTelemetry


# =========================================================
# FIXTURE
# =========================================================
@pytest.fixture
def fetcher():
    return FetchAssetsTelemetry()


# =========================================================
# TEST: get_auth_tokens SUCCESS
# =========================================================
@patch("Predictive_ML.fetch_assets_telemetry.User_fetcher.UserFetcher")
def test_get_auth_tokens_success(mock_user_fetcher):

    mock_instance = mock_user_fetcher.return_value

    mock_instance.fetch_auth_token_with_domain_id.return_value = {
        "access_token": "test_token"
    }

    fetcher = FetchAssetsTelemetry()

    result = fetcher.get_auth_tokens()

    assert result["access_token"] == "test_token"


# =========================================================
# TEST: get_auth_tokens FAILURE
# =========================================================
@patch("Predictive_ML.fetch_assets_telemetry.User_fetcher.UserFetcher")
def test_get_auth_tokens_failure(mock_user_fetcher):

    mock_instance = mock_user_fetcher.return_value

    mock_instance.fetch_auth_token_with_domain_id.return_value = None

    fetcher = FetchAssetsTelemetry()

    result = fetcher.get_auth_tokens()

    assert result is None


# =========================================================
# TEST: get_auth_tokens REQUEST EXCEPTION
# =========================================================
@patch("Predictive_ML.fetch_assets_telemetry.User_fetcher.UserFetcher")
def test_get_auth_tokens_exception(mock_user_fetcher):

    mock_instance = mock_user_fetcher.return_value

    mock_instance.fetch_auth_token_with_domain_id.side_effect = (
        requests.exceptions.RequestException("API Error")
    )

    fetcher = FetchAssetsTelemetry()

    result = fetcher.get_auth_tokens()

    assert result is None


# =========================================================
# TEST: get_telemetry_data_asset SUCCESS
# =========================================================
@patch("Predictive_ML.fetch_assets_telemetry.requests.get")
@patch("Predictive_ML.fetch_assets_telemetry.FetchAssetsTelemetry.get_auth_tokens")
def test_get_telemetry_data_asset_success(
    mock_tokens,
    mock_get,
    fetcher
):

    mock_tokens.return_value = {
        "access_token": "test_token"
    }

    mock_response = MagicMock()

    mock_response.json.return_value = {
        "messages": [
            {"id": 1},
            {"id": 2}
        ],
        "total": 2
    }

    mock_response.raise_for_status.return_value = None

    mock_get.return_value = mock_response

    result = fetcher.get_telemetry_data_asset(
        asset_id="asset_1"
    )

    assert len(result) == 2
    assert result[0]["id"] == 1


# =========================================================
# TEST: get_telemetry_data_asset NO TOKENS
# =========================================================
@patch("Predictive_ML.fetch_assets_telemetry.FetchAssetsTelemetry.get_auth_tokens")
def test_get_telemetry_data_asset_no_tokens(
    mock_tokens,
    fetcher
):

    mock_tokens.return_value = None

    result = fetcher.get_telemetry_data_asset(
        asset_id="asset_1"
    )

    assert result is None


# =========================================================
# TEST: get_telemetry_data_asset REQUEST ERROR
# =========================================================
@patch("Predictive_ML.fetch_assets_telemetry.requests.get")
@patch("Predictive_ML.fetch_assets_telemetry.FetchAssetsTelemetry.get_auth_tokens")
def test_get_telemetry_data_asset_request_error(
    mock_tokens,
    mock_get,
    fetcher
):

    mock_tokens.return_value = {
        "access_token": "test_token"
    }

    mock_get.side_effect = requests.RequestException(
        "API Failure"
    )

    result = fetcher.get_telemetry_data_asset(
        asset_id="asset_1"
    )

    assert result is None


# =========================================================
# TEST: get_telemetry_data_asset MAX LIMIT
# =========================================================
@patch("Predictive_ML.fetch_assets_telemetry.requests.get")
@patch("Predictive_ML.fetch_assets_telemetry.FetchAssetsTelemetry.get_auth_tokens")
def test_get_telemetry_data_asset_max_limit(
    mock_tokens,
    mock_get,
    fetcher
):

    mock_tokens.return_value = {
        "access_token": "test_token"
    }

    mock_response = MagicMock()

    mock_response.json.return_value = {
        "messages": [{"id": i} for i in range(10)],
        "total": 100
    }

    mock_response.raise_for_status.return_value = None

    mock_get.return_value = mock_response

    result = fetcher.get_telemetry_data_asset(
        asset_id="asset_1",
        limit=10,
        max_messages=5
    )

    assert len(result) == 5


# =========================================================
# TEST: get_telemetry_data_things SUCCESS
# =========================================================
@patch("Predictive_ML.fetch_assets_telemetry.requests.get")
@patch("Predictive_ML.fetch_assets_telemetry.FetchAssetsTelemetry.get_auth_tokens")
def test_get_telemetry_data_things_success(
    mock_tokens,
    mock_get,
    fetcher
):

    mock_tokens.return_value = {
        "access_token": "test_token"
    }

    mock_response = MagicMock()

    mock_response.json.return_value = {
        "messages": [
            {"id": 10},
            {"id": 20}
        ],
        "total": 2
    }

    mock_response.raise_for_status.return_value = None

    mock_get.return_value = mock_response

    result = fetcher.get_telemetry_data_things(
        thing_id="thing_1",
        asset_id="asset_1"
    )

    assert len(result) == 2
    assert result[1]["id"] == 20


# =========================================================
# TEST: get_telemetry_data_things NO TOKENS
# =========================================================
@patch("Predictive_ML.fetch_assets_telemetry.FetchAssetsTelemetry.get_auth_tokens")
def test_get_telemetry_data_things_no_tokens(
    mock_tokens,
    fetcher
):

    mock_tokens.return_value = None

    result = fetcher.get_telemetry_data_things(
        thing_id="thing_1",
        asset_id="asset_1"
    )

    assert result is None


# =========================================================
# TEST: get_telemetry_data_things REQUEST ERROR
# =========================================================
@patch("Predictive_ML.fetch_assets_telemetry.requests.get")
@patch("Predictive_ML.fetch_assets_telemetry.FetchAssetsTelemetry.get_auth_tokens")
def test_get_telemetry_data_things_request_error(
    mock_tokens,
    mock_get,
    fetcher
):

    mock_tokens.return_value = {
        "access_token": "test_token"
    }

    mock_get.side_effect = requests.RequestException(
        "API Failure"
    )

    result = fetcher.get_telemetry_data_things(
        thing_id="thing_1",
        asset_id="asset_1"
    )

    assert result is None


# =========================================================
# TEST: get_telemetry_data_things MAX LIMIT
# =========================================================
@patch("Predictive_ML.fetch_assets_telemetry.requests.get")
@patch("Predictive_ML.fetch_assets_telemetry.FetchAssetsTelemetry.get_auth_tokens")
def test_get_telemetry_data_things_max_limit(
    mock_tokens,
    mock_get,
    fetcher
):

    mock_tokens.return_value = {
        "access_token": "test_token"
    }

    mock_response = MagicMock()

    mock_response.json.return_value = {
        "messages": [{"id": i} for i in range(10)],
        "total": 100
    }

    mock_response.raise_for_status.return_value = None

    mock_get.return_value = mock_response

    result = fetcher.get_telemetry_data_things(
        thing_id="thing_1",
        asset_id="asset_1",
        limit=10,
        max_messages=5
    )

    assert len(result) == 5