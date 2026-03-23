from ultralytics import YOLO

model = YOLO("runs/detect/train/weights/best.pt")

metrics = model.val(data="data.yaml", plots=True)