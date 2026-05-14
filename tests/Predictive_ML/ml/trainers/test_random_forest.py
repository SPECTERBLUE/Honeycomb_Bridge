import pytest
import pandas as pd
import numpy as np

from sklearn.ensemble import RandomForestClassifier

from Predictive_ML.ml.trainers.random_forest import (
    train_random_forest
)


# -------------------------------
# FIXTURE: sample dataset
# -------------------------------
@pytest.fixture
def sample_data():

    X = pd.DataFrame({
        "temperature": [10, 20, 30, 40, 50, 60, 70, 80],
        "pressure": [1, 2, 3, 4, 5, 6, 7, 8]
    })

    y = pd.Series([0, 1, 0, 1, 0, 1, 0, 1])

    return X, y


# -------------------------------
# TEST: successful training
# -------------------------------
def test_train_random_forest_success(sample_data):

    X, y = sample_data

    model, metrics = train_random_forest(X, y)

    assert model is not None
    assert "accuracy" in metrics

    # accuracy should be between 0 and 1
    assert 0 <= metrics["accuracy"] <= 1


# -------------------------------
# TEST: correct model type
# -------------------------------
def test_model_type(sample_data):

    X, y = sample_data

    model, _ = train_random_forest(X, y)

    assert isinstance(model, RandomForestClassifier)


# -------------------------------
# TEST: numpy input support
# -------------------------------
def test_numpy_input():

    X = np.array([
        [10, 1],
        [20, 2],
        [30, 3],
        [40, 4],
        [50, 5],
        [60, 6]
    ])

    y = np.array([0, 1, 0, 1, 0, 1])

    model, metrics = train_random_forest(X, y)

    assert model is not None
    assert "accuracy" in metrics


# -------------------------------
# TEST: small dataset
# -------------------------------
def test_small_dataset():

    X = pd.DataFrame({
        "temperature": [10, 20, 30, 40],
        "pressure": [1, 2, 3, 4]
    })

    y = pd.Series([0, 1, 0, 1])

    model, metrics = train_random_forest(X, y)

    assert model is not None
    assert "accuracy" in metrics


# -------------------------------
# TEST: invalid input mismatch
# -------------------------------
def test_invalid_input():

    X = pd.DataFrame({
        "temperature": [10, 20, 30]
    })

    # mismatched target length
    y = pd.Series([0, 1])

    with pytest.raises(ValueError):
        train_random_forest(X, y)