import pytest
import pandas as pd
import numpy as np
import warnings
warnings.filterwarnings("ignore")
from xgboost import XGBClassifier


from Predictive_ML.ml.trainers.xgboost import (
    train_xgboost
)


# -------------------------------
# FIXTURE: sample multiclass data
# -------------------------------
@pytest.fixture
def sample_data():

    X = pd.DataFrame({
        "temperature": list(range(30)),
        "pressure": list(range(30, 60))
    })

    # multiclass labels
    y = pd.Series([0, 1, 2] * 10)

    return X, y


# -------------------------------
# TEST: successful training
# -------------------------------
def test_train_xgboost_success(sample_data):

    X, y = sample_data

    model, metrics = train_xgboost(X, y)

    assert model is not None

    assert "accuracy" in metrics
    assert "classification_report" in metrics

    assert 0 <= metrics["accuracy"] <= 1


# -------------------------------
# TEST: correct model type
# -------------------------------
def test_model_type(sample_data):

    X, y = sample_data

    model, _ = train_xgboost(X, y)

    assert isinstance(model, XGBClassifier)


# -------------------------------
# TEST: classification report
# -------------------------------
def test_classification_report(sample_data):

    X, y = sample_data

    _, metrics = train_xgboost(X, y)

    report = metrics["classification_report"]

    assert isinstance(report, dict)

    # check common keys
    assert "macro avg" in report
    assert "weighted avg" in report


# -------------------------------
# TEST: numpy input support
# -------------------------------
def test_numpy_input():

    X = np.array([
        [1, 10],
        [2, 20],
        [3, 30],
        [4, 40],
        [5, 50],
        [6, 60],
        [7, 70],
        [8, 80],
        [9, 90]
    ])

    y = np.array([0, 1, 2, 0, 1, 2, 0, 1, 2])

    model, metrics = train_xgboost(X, y)

    assert model is not None
    assert "accuracy" in metrics


# -------------------------------
# TEST: small dataset
# -------------------------------
def test_small_dataset():

    X = pd.DataFrame({
        "temperature": list(range(12)),
        "pressure": list(range(12, 24))
    })

    y = pd.Series([0, 1, 2, 0, 1, 2, 0, 1, 2, 0, 1, 2])

    model, metrics = train_xgboost(X, y)

    assert model is not None
    assert "accuracy" in metrics


# -------------------------------
# TEST: invalid input mismatch
# -------------------------------
def test_invalid_input():

    X = pd.DataFrame({
        "temperature": [10, 20, 30]
    })

    # mismatched labels
    y = pd.Series([0, 1])

    with pytest.raises(ValueError):
        train_xgboost(X, y)