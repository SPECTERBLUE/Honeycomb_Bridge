import torch
import torch.nn as nn
import torch.optim as optim

device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
class LSTMModel(nn.Module):
    def __init__(self, input_size, hidden_size, output_size):
        super().__init__()
        self.lstm = nn.LSTM(input_size, hidden_size, batch_first=True)
        self.fc = nn.Linear(hidden_size, output_size)

    def forward(self, x):
        out, _ = self.lstm(x)
        out = out[:, -1, :]  # last timestep
        return self.fc(out)

def train_lstm(X, y, prediction_type, device=device, num_classes=None):

    X = torch.tensor(X, dtype=torch.float32)

    if prediction_type == "fault":
        y = torch.tensor(y, dtype=torch.long)
        output_size = num_classes if num_classes is not None else int(y.max().item()) + 1
        from collections import Counter
        counts = Counter(y.tolist())
        total = len(y)
        weights = torch.tensor(
            [total / (output_size * counts.get(i, 1)) for i in range(output_size)],
            dtype=torch.float32
        ).to(device)
        criterion = nn.CrossEntropyLoss(weight=weights)
    else:
        y = torch.tensor(y, dtype=torch.float32)
        output_size = y.shape[1] if len(y.shape) > 1 else 1
        criterion = nn.MSELoss()

    model = LSTMModel(
        input_size=X.shape[2],
        hidden_size=64,
        output_size=output_size
    ).to(device)

    optimizer = optim.Adam(model.parameters(), lr=0.0005)

    batch_size = 32

    for _ in range(100):
        model.train()

        for i in range(0, len(X), batch_size):

            X_batch = X[i:i+batch_size].to(device)
            y_batch = y[i:i+batch_size].to(device)

            optimizer.zero_grad()

            outputs = model(X_batch)
            loss = criterion(outputs, y_batch)

            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), max_norm=1.0)
            optimizer.step()

        torch.cuda.empty_cache()

    return model