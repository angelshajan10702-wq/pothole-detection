from ultralytics import YOLO

# Load trained model
model = YOLO("runs/detect/train/weights/best.pt")

# Run prediction and SAVE result
results = model.predict(
    source="test.jpg",
    save=True,
    project="runs/detect",
    name="mypredict",
    exist_ok=True
)