from sklearn.ensemble import RandomForestClassifier, RandomForestRegressor
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score

def train_random_forest(
    X,
    y,
    test_size: float = 0.2,
    random_state: int = 42,
    class_weight: str = "balanced"
):
    """
    Trains Random Forest for both classification & regression
    """

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=test_size, random_state=random_state
    )

    model = RandomForestClassifier(
        n_estimators=300,
        max_depth=12,
        random_state=random_state,
        n_jobs=-1,
        class_weight="balanced"
    )

    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)

    metrics = {
        "accuracy": accuracy_score(y_test, y_pred)
    }

    return model, metrics
