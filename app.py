import streamlit as st
import pickle
import numpy as np

st.set_page_config(page_title="Car Price Prediction")

# Load trained model
with open("car_price_model.pkl", "rb") as f:
    model = pickle.load(f)

st.title("🚗 Car Price Prediction App")

km = st.number_input("Kilometers Driven", min_value=0)
mileage = st.number_input("Mileage (kmpl)", min_value=0.0)
engine = st.number_input("Engine Capacity (CC)", min_value=0.0)
power = st.number_input("Power (bhp)", min_value=0.0)
seats = st.number_input("Number of Seats", min_value=1)
years_used = st.number_input("Years Used", min_value=0)

if st.button("Predict Price"):
    input_data = np.array([[km, mileage, engine, power, seats, years_used]])
    prediction = model.predict(input_data)[0]
    st.success(f"💰 Estimated Car Price: ₹ {round(prediction, 2)} Lakhs")




st.markdown('Designed by:**Ashish Luthra**  and  **Mishti Sehgal**')









