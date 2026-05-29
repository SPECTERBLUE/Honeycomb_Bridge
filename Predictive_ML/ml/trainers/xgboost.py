from xgboost import XGBClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
from sklearn.utils.class_weight import compute_sample_weight
import numpy as np

def train_xgboost(
    X,
    y,
    test_size=0.2,
    random_state=42,
    scale_pos_weight=1.0
):

    # 🔹 Ensure integer labels
    y = y.astype(int)

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=test_size,
        random_state=random_state,
        stratify=y
    )

    num_classes = len(np.unique(y))

    # =====================================================
    # MULTICLASS
    # =====================================================
    if num_classes > 2:

        sample_weights = compute_sample_weight(
            class_weight="balanced",
            y=y_train
        )

        model = XGBClassifier(
            objective="multi:softprob",
            num_class=num_classes,
            eval_metric="mlogloss",
            n_estimators=400,
            max_depth=6,
            learning_rate=0.08,
            random_state=random_state,
            subsample=0.8,
            colsample_bytree=0.8
        )

        model.fit(
            X_train,
            y_train,
            sample_weight=sample_weights
        )

    # =====================================================
    # BINARY
    # =====================================================
    else:

        model = XGBClassifier(
            objective="binary:logistic",
            eval_metric="logloss",
            n_estimators=400,
            max_depth=6,
            learning_rate=0.08,
            random_state=random_state,
            scale_pos_weight=scale_pos_weight,
            subsample=0.8,
            colsample_bytree=0.8
        )

        model.fit(X_train, y_train)

    # =====================================================
    # EVALUATION
    # =====================================================
    y_pred = model.predict(X_test)

    metrics = {
        "accuracy": float(accuracy_score(y_test, y_pred)),
        "classification_report": classification_report(
            y_test,
            y_pred,
            output_dict=True,
            zero_division=0
        )
    }

    return model, metrics