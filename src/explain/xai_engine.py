# src/explain/xai_engine.py
import os
import numpy as np
import pandas as pd
import joblib
import shap
import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt


PROCESSED_DIR = os.path.join(
    os.path.dirname(__file__), "..", "..", "data", "processed"
)
MODELS_DIR = os.path.join(
    os.path.dirname(__file__), "..", "..", "models_saved"
)
REPORTS_DIR = os.path.join(
    os.path.dirname(__file__), "..", "..", "data", "processed"
)

FRAUD_FEATURES = [
    "Time",
    "V1",
    "V2",
    "V3",
    "V4",
    "V5",
    "V6",
    "V7",
    "V8",
    "V9",
    "V10",
    "V11",
    "V12",
    "V13",
    "V14",
    "V15",
    "V16",
    "V17",
    "V18",
    "V19",
    "V20",
    "V21",
    "V22",
    "V23",
    "V24",
    "V25",
    "V26",
    "V27",
    "V28",
    "Amount",
]

# 77 features — "Fwd Header Length.1" was dropped during Salma's preprocessing
# (duplicate column from raw CICIDS2017 CSV, removed before training rf_nids.pkl)
NETWORK_FEATURES = [
    "Destination Port",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Fwd Packet Length Max",
    "Fwd Packet Length Min",
    "Fwd Packet Length Mean",
    "Fwd Packet Length Std",
    "Bwd Packet Length Max",
    "Bwd Packet Length Min",
    "Bwd Packet Length Mean",
    "Bwd Packet Length Std",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Flow IAT Mean",
    "Flow IAT Std",
    "Flow IAT Max",
    "Flow IAT Min",
    "Fwd IAT Total",
    "Fwd IAT Mean",
    "Fwd IAT Std",
    "Fwd IAT Max",
    "Fwd IAT Min",
    "Bwd IAT Total",
    "Bwd IAT Mean",
    "Bwd IAT Std",
    "Bwd IAT Max",
    "Bwd IAT Min",
    "Fwd PSH Flags",
    "Bwd PSH Flags",
    "Fwd URG Flags",
    "Bwd URG Flags",
    "Fwd Header Length",
    "Bwd Header Length",
    "Fwd Packets/s",
    "Bwd Packets/s",
    "Min Packet Length",
    "Max Packet Length",
    "Packet Length Mean",
    "Packet Length Std",
    "Packet Length Variance",
    "FIN Flag Count",
    "SYN Flag Count",
    "RST Flag Count",
    "PSH Flag Count",
    "ACK Flag Count",
    "URG Flag Count",
    "CWE Flag Count",
    "ECE Flag Count",
    "Down/Up Ratio",
    "Average Packet Size",
    "Avg Fwd Segment Size",
    "Avg Bwd Segment Size",
    # "Fwd Header Length.1" REMOVED — duplicate, dropped during preprocessing
    "Fwd Avg Bytes/Bulk",
    "Fwd Avg Packets/Bulk",
    "Fwd Avg Bulk Rate",
    "Bwd Avg Bytes/Bulk",
    "Bwd Avg Packets/Bulk",
    "Bwd Avg Bulk Rate",
    "Subflow Fwd Packets",
    "Subflow Fwd Bytes",
    "Subflow Bwd Packets",
    "Subflow Bwd Bytes",
    "Init_Win_bytes_forward",
    "Init_Win_bytes_backward",
    "act_data_pkt_fwd",
    "min_seg_size_forward",
    "Active Mean",
    "Active Std",
    "Active Max",
    "Active Min",
    "Idle Mean",
    "Idle Std",
    "Idle Max",
    "Idle Min",
]

# Sanity check at import time — will print a warning if count is wrong
assert len(NETWORK_FEATURES) == 77, (
    f"NETWORK_FEATURES has {len(NETWORK_FEATURES)} entries, expected 77. "
    "Check for missing or duplicate feature names."
)

# -------------------------------------------------------------------
# RUNTIME FUNCTIONS USED BY THE API ENDPOINTS
# -------------------------------------------------------------------


def explain_fraud(X: np.ndarray) -> np.ndarray:
    """
    API helper for /predict/fraud.
    Input:  X shape (1, 30) in the same order as FRAUD_FEATURES.
    Output: SHAP values shape (1, 30).
    """
    model_path = os.path.join(MODELS_DIR, "xgb_fraude.pkl")
    model = joblib.load(model_path)

    X = np.asarray(X, dtype=float)
    if X.ndim == 1:
        X = X.reshape(1, -1)

    X_df = pd.DataFrame(X, columns=FRAUD_FEATURES)

    explainer = shap.TreeExplainer(model)
    shap_values = explainer.shap_values(X_df)

    shap_values = np.asarray(shap_values, dtype=float)
    if shap_values.ndim == 1:
        shap_values = shap_values.reshape(1, -1)

    return shap_values


def explain_network(X: np.ndarray, predicted_class: int) -> np.ndarray:
    """
    API helper for /predict/threat.
    Input:  X shape (1, 77) in the same order as NETWORK_FEATURES,
            predicted_class: int (0..n_classes-1).
    Output: SHAP values for that class, shape (1, 77).

    Note: if X arrives with 78 columns (old payload including
    'Fwd Header Length.1'), the extra column is silently trimmed
    to 77 so the API never crashes on legacy requests.
    """
    model_path = os.path.join(MODELS_DIR, "rf_nids.pkl")
    model = joblib.load(model_path)

    X = np.asarray(X, dtype=float)
    if X.ndim == 1:
        X = X.reshape(1, -1)

    # Trim to 77 if caller still sends 78 (backward-compat guard)
    if X.shape[1] > len(NETWORK_FEATURES):
        X = X[:, : len(NETWORK_FEATURES)]

    X_df = pd.DataFrame(X, columns=NETWORK_FEATURES[: X.shape[1]])

    explainer = shap.TreeExplainer(model)
    shap_values = explainer.shap_values(X_df)

    shap_values = np.asarray(shap_values, dtype=float)

    # shap_values shape: (n_classes, n_samples, n_features)
    if shap_values.ndim == 3:
        class_shap = shap_values[predicted_class, 0, :]
    # some SHAP versions: (n_samples, n_features) for binary
    elif shap_values.ndim == 2:
        class_shap = shap_values[0, :]
    else:
        class_shap = shap_values

    return np.asarray(class_shap, dtype=float).reshape(1, -1)


# -------------------------------------------------------------------
# OFFLINE EXPLAINABILITY SCRIPTS (SALMA'S ANALYSIS)
# -------------------------------------------------------------------


def explain_fraud_model():
    """Calcule et sauvegarde les SHAP values pour XGBoost Fraude."""
    print("=" * 55)
    print("SHAP - EXPLICABILITE MODELE FRAUDE")
    print("=" * 55)

    print("\nChargement modele et donnees...")
    model = joblib.load(os.path.join(MODELS_DIR, "xgb_fraude.pkl"))
    X_test, y_test = joblib.load(os.path.join(PROCESSED_DIR, "fraud_test.pkl"))

    np.random.seed(42)
    idx = np.random.choice(len(X_test), size=500, replace=False)
    X_sample = X_test.iloc[idx] if hasattr(X_test, "iloc") else X_test[idx]
    X_sample_df = pd.DataFrame(X_sample, columns=FRAUD_FEATURES)

    print(f"   Modele charge : xgb_fraude.pkl")
    print(f"   Echantillon   : {len(X_sample)} transactions")

    print("\nCalcul des SHAP values (1-2 minutes)...")
    explainer = shap.TreeExplainer(model)
    shap_values = explainer.shap_values(X_sample_df)
    print("   SHAP values calculees !")

    print("\nGeneration graphique Summary Plot...")
    plt.figure(figsize=(12, 8))
    shap.summary_plot(
        shap_values,
        X_sample_df,
        plot_type="bar",
        show=False,
        max_display=15,
    )
    plt.title("SHAP - Importance Globale des Features (Fraude)", fontsize=14)
    plt.tight_layout()
    plt.savefig(
        os.path.join(REPORTS_DIR, "shap_fraud_importance.png"),
        dpi=150,
        bbox_inches="tight",
    )
    plt.close()
    print("   shap_fraud_importance.png sauvegarde")

    print("\nGeneration graphique Beeswarm...")
    plt.figure(figsize=(12, 8))
    shap.summary_plot(
        shap_values,
        X_sample_df,
        show=False,
        max_display=15,
    )
    plt.title(
        "SHAP - Impact des Features sur la Prediction (Fraude)", fontsize=14
    )
    plt.tight_layout()
    plt.savefig(
        os.path.join(REPORTS_DIR, "shap_fraud_beeswarm.png"),
        dpi=150,
        bbox_inches="tight",
    )
    plt.close()
    print("   shap_fraud_beeswarm.png sauvegarde")

    print("\nGeneration graphique Waterfall (1 transaction)...")
    explanation = shap.Explanation(
        values=shap_values[0],
        base_values=explainer.expected_value,
        data=X_sample_df.iloc[0],
        feature_names=FRAUD_FEATURES,
    )
    plt.figure(figsize=(12, 6))
    shap.plots.waterfall(explanation, show=False, max_display=15)
    plt.title("SHAP - Explication Transaction #1", fontsize=14)
    plt.tight_layout()
    plt.savefig(
        os.path.join(REPORTS_DIR, "shap_fraud_waterfall.png"),
        dpi=150,
        bbox_inches="tight",
    )
    plt.close()
    print("   shap_fraud_waterfall.png sauvegarde")

    print("\nTop 10 features SHAP (Fraude) :")
    shap_importance = (
        pd.DataFrame(
            {
                "feature": FRAUD_FEATURES,
                "importance": np.abs(shap_values).mean(axis=0),
            }
        )
        .sort_values("importance", ascending=False)
    )

    for _, row in shap_importance.head(10).iterrows():
        print(f"   {row['feature']:<12} : {row['importance']:.4f}")

    print("\nSHAP Fraude - TERMINE !")
    print("=" * 55)
    return shap_values, explainer


def explain_network_model():
    """Calcule et sauvegarde les SHAP values pour Random Forest Reseau."""
    print("=" * 55)
    print("SHAP - EXPLICABILITE MODELE RESEAU")
    print("=" * 55)

    print("\nChargement modele et donnees...")
    model = joblib.load(os.path.join(MODELS_DIR, "rf_nids.pkl"))
    X_test, y_test = joblib.load(
        os.path.join(PROCESSED_DIR, "network_test.pkl")
    )

    np.random.seed(42)
    idx = np.random.choice(X_test.shape[0], size=200, replace=False)
    X_sample = X_test[idx]

    # Align feature names to actual feature count of X_sample
    aligned_features = NETWORK_FEATURES[: X_sample.shape[1]]
    X_sample_df = pd.DataFrame(X_sample, columns=aligned_features)

    print(f"   Modele charge : rf_nids.pkl")
    print(f"   Echantillon   : {len(X_sample)} connexions")

    print("\nCalcul des SHAP values (2-5 minutes)...")
    explainer = shap.TreeExplainer(model)
    shap_values = explainer.shap_values(X_sample_df)
    print("   SHAP values calculees !")

    print("\nGeneration graphique Summary Plot Reseau...")
    label_encoder = joblib.load(
        os.path.join(MODELS_DIR, "label_encoder_cicids.pkl")
    )
    class_names = getattr(label_encoder, "classes_", None)

    plt.figure(figsize=(12, 8))
    shap.summary_plot(
        shap_values,
        X_sample_df,
        plot_type="bar",
        show=False,
        max_display=15,
        class_names=class_names,
    )
    plt.title("SHAP - Importance Globale des Features (Reseau)", fontsize=14)
    plt.tight_layout()
    plt.savefig(
        os.path.join(REPORTS_DIR, "shap_network_importance.png"),
        dpi=150,
        bbox_inches="tight",
    )
    plt.close()
    print("   shap_network_importance.png sauvegarde")

    print("\nSHAP Reseau - TERMINE !")
    print("=" * 55)
    return shap_values, explainer


if __name__ == "__main__":
    explain_fraud_model()

    rf_path = os.path.join(MODELS_DIR, "rf_nids.pkl")
    if os.path.exists(rf_path):
        explain_network_model()
    else:
        print("\nrf_nids.pkl pas encore pret - lance d'abord nids_model.py")