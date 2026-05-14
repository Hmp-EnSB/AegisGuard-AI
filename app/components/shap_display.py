import streamlit as st

def display_shap(features):
    st.subheader("🔍 SHAP Top Features")

    for f in features:
        val = f["shap_value"]
        color = "red" if val > 0 else "green"
        st.markdown(f"**{f['feature']}** → <span style='color:{color}'>{val}</span>", unsafe_allow_html=True)