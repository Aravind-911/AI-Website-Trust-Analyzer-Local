import joblib

model = joblib.load("model.pkl")

def predict_website(features):
    prediction = model.predict([features])

    if prediction[0] == 1:
        return "Safe Website"
    else:
        return "Suspicious Website"