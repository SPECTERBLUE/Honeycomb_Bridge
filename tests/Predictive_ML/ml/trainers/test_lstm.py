import pytest
import numpy as np
import torch

from Predictive_ML.ml.trainers.lstm import (
    LSTMModel,
    train_lstm
)


# -------------------------------
# FIXTURE: sample classification data
# -------------------------------
@pytest.fixture
def sample_fault_data():

    # shape -> (samples, seq_len, features)
    X = np.random.rand(20, 5, 3)

    # multiclass labels
    y = np.random.randint(0, 3, size=(20,))

    return X, y


# -------------------------------
# FIXTURE: sample regression data
# -------------------------------
@pytest.fixture
def sample_sensor_data():

    X = np.random.rand(20, 5, 3)

    # regression targets
    y = np.random.rand(20, 1)

    return X, y


# -------------------------------
# TEST: model initialization
# -------------------------------
def test_lstm_model_init():

    model = LSTMModel(
        input_size=3,
        hidden_size=64,
        output_size=3
    )

    assert isinstance(model, LSTMModel)


# -------------------------------
# TEST: forward pass
# -------------------------------
def test_forward_pass():

    model = LSTMModel(
        input_size=3,
        hidden_size=64,
        output_size=3
    )

    X = torch.rand(10, 5, 3)

    output = model(X)

    # batch size check
    assert output.shape[0] == 10

    # output classes check
    assert output.shape[1] == 3


# -------------------------------
# TEST: train_lstm fault prediction
# -------------------------------
def test_train_lstm_fault(sample_fault_data):

    X, y = sample_fault_data

    model = train_lstm(
        X,
        y,
        prediction_type="fault",
        num_classes=3
    )

    assert isinstance(model, LSTMModel)

    # ensure model on correct device
    assert next(model.parameters()).device.type in ["cpu", "cuda"]


# -------------------------------
# TEST: train_lstm sensor prediction
# -------------------------------
def test_train_lstm_sensor(sample_sensor_data):

    X, y = sample_sensor_data

    model = train_lstm(
        X,
        y,
        prediction_type="sensor"
    )

    assert isinstance(model, LSTMModel)


# -------------------------------
# TEST: numpy input support
# -------------------------------
def test_numpy_input():

    X = np.random.rand(15, 4, 2)
    y = np.random.randint(0, 2, size=(15,))

    model = train_lstm(
        X,
        y,
        prediction_type="fault",
        num_classes=2
    )

    assert model is not None


# -------------------------------
# TEST: invalid input mismatch
# -------------------------------
def test_invalid_input():

    X = np.random.rand(10, 5, 3)

    # mismatched labels
    y = np.random.randint(0, 2, size=(5,))

    with pytest.raises(ValueError):
        train_lstm(
            X,
            y,
            prediction_type="fault",
            num_classes=2
        )


# -------------------------------
# TEST: GPU/CPU device assignment
# -------------------------------
def test_device_assignment(sample_fault_data):

    X, y = sample_fault_data

    model = train_lstm(
        X,
        y,
        prediction_type="fault",
        num_classes=3
    )

    device = "cuda" if torch.cuda.is_available() else "cpu"

    assert next(model.parameters()).device.type == device