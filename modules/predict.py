import joblib

model = joblib.load("model.pkl")

def predict_website(features):
    prediction = model.predict([features])

    print("Prediction:", prediction)

    return prediction[0]