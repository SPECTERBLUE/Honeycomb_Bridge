import pytest
import pandas as pd

from Predictive_ML.pre_trained_models import (
    label_motor_faults
)


# =========================================================
# FIXTURE: thresholds
# =========================================================
@pytest.fixture
def thresholds():
    return {
        "Vibration_avg": {
            "failure": 10
        },
        "Temperature_avg": {
            "failure": 90,
            "prefailure": 70
        },
        "Stator_Current_avg": {
            "failure": 150,
            "prefailure": 120
        },
        "Rotor_Current_avg": {
            "failure": 110
        }
    }


# =========================================================
# TEST: HEALTHY
# =========================================================
def test_label_motor_faults_healthy(thresholds):

    df = pd.DataFrame([
        {
            "Stator_Current_avg": 100,
            "Stator_Voltage_avg": 400,
            "Rotor_Current_avg": 90,
            "Rotor_Voltage_avg": 300,
            "Vibration_avg": 5,
            "Temperature_avg": 50
        }
    ])

    result = label_motor_faults(df, thresholds)

    assert result.iloc[0]["label"] == 0


# =========================================================
# TEST: OVERLOAD
# =========================================================
def test_label_motor_faults_overload(thresholds):

    df = pd.DataFrame([
        {
            "Stator_Current_avg": 130,
            "Stator_Voltage_avg": 400,
            "Rotor_Current_avg": 90,
            "Rotor_Voltage_avg": 300,
            "Vibration_avg": 5,
            "Temperature_avg": 75
        }
    ])

    result = label_motor_faults(df, thresholds)

    assert result.iloc[0]["label"] == 1


# =========================================================
# TEST: ROTOR FAULT
# =========================================================
def test_label_motor_faults_rotor_fault(thresholds):

    df = pd.DataFrame([
        {
            "Stator_Current_avg": 100,
            "Stator_Voltage_avg": 400,
            "Rotor_Current_avg": 120,
            "Rotor_Voltage_avg": 300,
            "Vibration_avg": 5,
            "Temperature_avg": 60
        }
    ])

    result = label_motor_faults(df, thresholds)

    assert result.iloc[0]["label"] == 2


# =========================================================
# TEST: STATOR FAULT
# =========================================================
def test_label_motor_faults_stator_fault(thresholds):

    df = pd.DataFrame([
        {
            "Stator_Current_avg": 170,
            "Stator_Voltage_avg": 400,
            "Rotor_Current_avg": 90,
            "Rotor_Voltage_avg": 300,
            "Vibration_avg": 5,
            "Temperature_avg": 60
        }
    ])

    result = label_motor_faults(df, thresholds)

    assert result.iloc[0]["label"] == 3


# =========================================================
# TEST: MECHANICAL FAULT
# =========================================================
def test_label_motor_faults_mechanical_fault(thresholds):

    df = pd.DataFrame([
        {
            "Stator_Current_avg": 100,
            "Stator_Voltage_avg": 400,
            "Rotor_Current_avg": 90,
            "Rotor_Voltage_avg": 300,
            "Vibration_avg": 15,
            "Temperature_avg": 100
        }
    ])

    result = label_motor_faults(df, thresholds)

    assert result.iloc[0]["label"] == 4


# =========================================================
# TEST: MULTIPLE ROWS
# =========================================================
def test_label_motor_faults_multiple_rows(thresholds):

    df = pd.DataFrame([
        {
            "Stator_Current_avg": 100,
            "Stator_Voltage_avg": 400,
            "Rotor_Current_avg": 90,
            "Rotor_Voltage_avg": 300,
            "Vibration_avg": 5,
            "Temperature_avg": 50
        },
        {
            "Stator_Current_avg": 130,
            "Stator_Voltage_avg": 400,
            "Rotor_Current_avg": 90,
            "Rotor_Voltage_avg": 300,
            "Vibration_avg": 5,
            "Temperature_avg": 75
        },
        {
            "Stator_Current_avg": 170,
            "Stator_Voltage_avg": 400,
            "Rotor_Current_avg": 90,
            "Rotor_Voltage_avg": 300,
            "Vibration_avg": 5,
            "Temperature_avg": 60
        }
    ])

    result = label_motor_faults(df, thresholds)

    assert len(result) == 3

    assert result.iloc[0]["label"] == 0
    assert result.iloc[1]["label"] == 1
    assert result.iloc[2]["label"] == 3


# =========================================================
# TEST: LABEL COLUMN EXISTS
# =========================================================
def test_label_column_exists(thresholds):

    df = pd.DataFrame([
        {
            "Stator_Current_avg": 100,
            "Stator_Voltage_avg": 400,
            "Rotor_Current_avg": 90,
            "Rotor_Voltage_avg": 300,
            "Vibration_avg": 5,
            "Temperature_avg": 50
        }
    ])

    result = label_motor_faults(df, thresholds)

    assert "label" in result.columns