import os
import csv
import pytest
from unittest.mock import patch, mock_open

from Predictive_ML.training_dataset_csv_creation import (
    create_training_dataset_csv
)


# =========================================================
# FIXTURE
# =========================================================
@pytest.fixture
def sample_processed_data():
    return [
        {
            "sensor": "Temp",
            "window_start": 0,
            "count": 5,
            "avg": 25.5,
            "min": 20,
            "max": 30,
            "status": "OK",
            "label": 0
        },
        {
            "sensor": "Pressure",
            "window_start": 0,
            "count": 5,
            "avg": 100.0,
            "min": 90,
            "max": 110,
            "status": "OK",
            "label": 1
        }
    ]


# =========================================================
# TEST: SUCCESS
# =========================================================
@patch("builtins.open", new_callable=mock_open)
@patch("os.makedirs")
def test_create_training_dataset_csv_success(
    mock_makedirs,
    mock_file,
    sample_processed_data
):

    file_path = create_training_dataset_csv(
        processed_data=sample_processed_data,
        asset_id="asset_123",
        window_length=60
    )

    # File path checks
    assert "asset_123" in file_path
    assert ".csv" in file_path

    # makedirs called
    mock_makedirs.assert_called_once()

    # file opened
    mock_file.assert_called_once()

    # ensure file write happened
    handle = mock_file()

    assert handle.write.called


# =========================================================
# TEST: EMPTY DATA
# =========================================================
def test_create_training_dataset_csv_empty():

    with pytest.raises(ValueError):

        create_training_dataset_csv(
            processed_data=[],
            asset_id="asset_123",
            window_length=60
        )


# =========================================================
# TEST: FILE WRITE ERROR
# =========================================================
@patch(
    "builtins.open",
    side_effect=Exception("File write failed")
)
def test_create_training_dataset_csv_write_error(mock_file):

    processed_data = [
        {
            "sensor": "Temp",
            "avg": 25
        }
    ]

    with pytest.raises(Exception):

        create_training_dataset_csv(
            processed_data=processed_data,
            asset_id="asset_123",
            window_length=60
        )


# =========================================================
# TEST: CSV HEADER FIELDS
# =========================================================
@patch("builtins.open", new_callable=mock_open)
@patch("csv.DictWriter")
def test_create_training_dataset_csv_headers(
    mock_writer,
    mock_file,
    sample_processed_data
):

    mock_writer_instance = mock_writer.return_value

    create_training_dataset_csv(
        processed_data=sample_processed_data,
        asset_id="asset_123",
        window_length=60
    )

    # Ensure DictWriter initialized correctly
    mock_writer.assert_called_once()

    args, kwargs = mock_writer.call_args

    assert kwargs["fieldnames"] == sample_processed_data[0].keys()

    # Ensure header written
    mock_writer_instance.writeheader.assert_called_once()

    # Ensure rows written
    mock_writer_instance.writerows.assert_called_once_with(
        sample_processed_data
    )


# =========================================================
# TEST: DIRECTORY CREATED
# =========================================================
@patch("builtins.open", new_callable=mock_open)
@patch("os.makedirs")
def test_create_training_dataset_directory_created(
    mock_makedirs,
    mock_file,
    sample_processed_data
):

    create_training_dataset_csv(
        processed_data=sample_processed_data,
        asset_id="asset_123",
        window_length=60
    )

    mock_makedirs.assert_called_once_with(
        "data/training_datasets",
        exist_ok=True
    )