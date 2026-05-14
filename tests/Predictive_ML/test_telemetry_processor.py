import pytest

from Predictive_ML.telemetry_processor import (
    TelemetryProcessor,
    handle_missing_windows,
    label_data,
    MAX_FORWARD_FILL_WINDOWS
)


# =========================================================
# FIXTURE
# =========================================================
@pytest.fixture
def sample_telemetry():
    return [
        {
            "name": "Temp",
            "time": 10,
            "value": 20
        },
        {
            "name": "Temp",
            "time": 20,
            "value": 30
        },
        {
            "name": "Pressure",
            "time": 10,
            "value": 100
        }
    ]


# =========================================================
# TEST: INIT
# =========================================================
def test_telemetry_processor_init(sample_telemetry):

    processor = TelemetryProcessor(sample_telemetry)

    assert processor.telemetry_data == sample_telemetry


# =========================================================
# TEST: filter_by_time START
# =========================================================
def test_filter_by_time_start(sample_telemetry):

    processor = TelemetryProcessor(sample_telemetry)

    result = processor.filter_by_time(start_ts=15)

    assert len(result) == 1
    assert result[0]["time"] == 20


# =========================================================
# TEST: filter_by_time RANGE
# =========================================================
def test_filter_by_time_range(sample_telemetry):

    processor = TelemetryProcessor(sample_telemetry)

    result = processor.filter_by_time(
        start_ts=10,
        end_ts=15
    )

    assert len(result) == 2


# =========================================================
# TEST: filter_by_time NONE
# =========================================================
def test_filter_by_time_none(sample_telemetry):

    processor = TelemetryProcessor(sample_telemetry)

    result = processor.filter_by_time()

    assert len(result) == 3


# =========================================================
# TEST: group_by_sensor
# =========================================================
def test_group_by_sensor(sample_telemetry):

    processor = TelemetryProcessor(sample_telemetry)

    result = processor.group_by_sensor()

    assert "Temp" in result
    assert "Pressure" in result

    assert len(result["Temp"]) == 2
    assert len(result["Pressure"]) == 1


# =========================================================
# TEST: aggregate_window
# =========================================================
def test_aggregate_window(sample_telemetry):

    processor = TelemetryProcessor(sample_telemetry)

    result = processor.aggregate_window(
        window_size_sec=10
    )

    assert len(result) > 0

    first = result[0]

    assert "sensor" in first
    assert "window_start" in first
    assert "count" in first
    assert "avg" in first
    assert "min" in first
    assert "max" in first


# =========================================================
# TEST: aggregate_window malformed data
# =========================================================
def test_aggregate_window_malformed():

    telemetry = [
        {
            "name": "Temp",
            "time": 10
        }
    ]

    processor = TelemetryProcessor(telemetry)

    # Actual implementation raises ZeroDivisionError
    with pytest.raises(ZeroDivisionError):

        processor.aggregate_window(
            window_size_sec=10
        )


# =========================================================
# TEST: handle_missing_windows FILLED
# =========================================================
def test_handle_missing_windows_filled():

    processed_data = [
        {
            "sensor": "Temp",
            "window_start": 0,
            "avg": 10
        },
        {
            "sensor": "Temp",
            "window_start": 10,
            "avg": None
        }
    ]

    result = handle_missing_windows(processed_data)

    assert result[1]["status"] == "FILLED"
    assert result[1]["avg"] == 10


# =========================================================
# TEST: handle_missing_windows NOT_WORKING
# =========================================================
def test_handle_missing_windows_not_working():

    processed_data = [
        {
            "sensor": "Temp",
            "window_start": 0,
            "avg": 10
        }
    ]

    # Add more than MAX_FORWARD_FILL_WINDOWS missing values
    for i in range(1, MAX_FORWARD_FILL_WINDOWS + 2):

        processed_data.append({
            "sensor": "Temp",
            "window_start": i * 10,
            "avg": None
        })

    result = handle_missing_windows(processed_data)

    assert result[-1]["status"] == "NOT_WORKING"


# =========================================================
# TEST: handle_missing_windows reset after valid value
# =========================================================
def test_handle_missing_windows_reset():

    processed_data = [
        {
            "sensor": "Temp",
            "window_start": 0,
            "avg": 10
        },
        {
            "sensor": "Temp",
            "window_start": 10,
            "avg": None
        },
        {
            "sensor": "Temp",
            "window_start": 20,
            "avg": 20
        }
    ]

    result = handle_missing_windows(processed_data)

    assert result[1]["status"] == "FILLED"
    assert result[2]["status"] == "OK"


# =========================================================
# TEST: label_data NORMAL
# =========================================================
def test_label_data_normal():

    aggregated_data = [
        {
            "sensor": "Temp",
            "avg": 40
        }
    ]

    threshold_map = {
        "Temp": {
            "prefailure": 50,
            "failure": 80
        }
    }

    result = label_data(
        aggregated_data,
        threshold_map
    )

    assert result[0]["label"] == 0


# =========================================================
# TEST: label_data PREFAILURE
# =========================================================
def test_label_data_prefailure():

    aggregated_data = [
        {
            "sensor": "Temp",
            "avg": 60
        }
    ]

    threshold_map = {
        "Temp": {
            "prefailure": 50,
            "failure": 80
        }
    }

    result = label_data(
        aggregated_data,
        threshold_map
    )

    assert result[0]["label"] == 1


# =========================================================
# TEST: label_data FAILURE
# =========================================================
def test_label_data_failure():

    aggregated_data = [
        {
            "sensor": "Temp",
            "avg": 100
        }
    ]

    threshold_map = {
        "Temp": {
            "prefailure": 50,
            "failure": 80
        }
    }

    result = label_data(
        aggregated_data,
        threshold_map
    )

    assert result[0]["label"] == 2


# =========================================================
# TEST: label_data NONE VALUE
# =========================================================
def test_label_data_none_value():

    aggregated_data = [
        {
            "sensor": "Temp",
            "avg": None
        }
    ]

    threshold_map = {
        "Temp": {
            "prefailure": 50,
            "failure": 80
        }
    }

    result = label_data(
        aggregated_data,
        threshold_map
    )

    assert result[0]["label"] == 0


# =========================================================
# TEST: label_data sensor not in threshold
# =========================================================
def test_label_data_sensor_not_found():

    aggregated_data = [
        {
            "sensor": "Unknown",
            "avg": 100
        }
    ]

    threshold_map = {
        "Temp": {
            "prefailure": 50,
            "failure": 80
        }
    }

    result = label_data(
        aggregated_data,
        threshold_map
    )

    assert result[0]["label"] == 0