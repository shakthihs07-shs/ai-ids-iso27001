"""Shared data loading and preprocessing for the NSL-KDD IDS project."""
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import OneHotEncoder, StandardScaler, FunctionTransformer
from sklearn.pipeline import Pipeline

DATA = Path(__file__).resolve().parent.parent / "data"

COLUMNS = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes", "land",
    "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in", "num_compromised",
    "root_shell", "su_attempted", "num_root", "num_file_creations", "num_shells",
    "num_access_files", "num_outbound_cmds", "is_host_login", "is_guest_login", "count",
    "srv_count", "serror_rate", "srv_serror_rate", "rerror_rate", "srv_rerror_rate",
    "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate", "dst_host_count",
    "dst_host_srv_count", "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate", "dst_host_serror_rate",
    "dst_host_srv_serror_rate", "dst_host_rerror_rate", "dst_host_srv_rerror_rate",
    "label", "difficulty",
]
CATEGORICAL = ["protocol_type", "service", "flag"]
HEAVY_TAILED = ["duration", "src_bytes", "dst_bytes", "count", "srv_count",
                "dst_host_count", "dst_host_srv_count", "hot", "num_compromised",
                "num_root", "num_file_creations", "num_access_files"]

CATEGORY = {
    "normal": "Normal",
    # Denial of Service
    "back": "DoS", "land": "DoS", "neptune": "DoS", "pod": "DoS", "smurf": "DoS",
    "teardrop": "DoS", "apache2": "DoS", "mailbomb": "DoS", "processtable": "DoS",
    "udpstorm": "DoS",
    # Probing / reconnaissance
    "ipsweep": "Probe", "nmap": "Probe", "portsweep": "Probe", "satan": "Probe",
    "mscan": "Probe", "saint": "Probe",
    # Remote to Local
    "ftp_write": "R2L", "guess_passwd": "R2L", "imap": "R2L", "multihop": "R2L",
    "phf": "R2L", "spy": "R2L", "warezclient": "R2L", "warezmaster": "R2L",
    "sendmail": "R2L", "named": "R2L", "snmpgetattack": "R2L", "snmpguess": "R2L",
    "xlock": "R2L", "xsnoop": "R2L", "worm": "R2L",
    # User to Root
    "buffer_overflow": "U2R", "loadmodule": "U2R", "perl": "U2R", "rootkit": "U2R",
    "httptunnel": "U2R", "ps": "U2R", "sqlattack": "U2R", "xterm": "U2R",
}


ENSEMBLE = ("Random Forest", "Gradient Boosting", "Neural Net (MLP)")


def ensemble_score(models, X):
    """Soft vote: mean attack probability of the ENSEMBLE members."""
    return np.mean([models[n].predict_proba(X)[:, 1] for n in ENSEMBLE], axis=0)


def load():
    train = pd.read_csv(DATA / "KDDTrain+.txt", names=COLUMNS)
    test = pd.read_csv(DATA / "KDDTest+.txt", names=COLUMNS)
    for df in (train, test):
        df["category"] = df["label"].map(CATEGORY)
        df["is_attack"] = (df["label"] != "normal").astype(int)
    unseen = sorted(set(test.label) - set(train.label))
    test["unseen_attack"] = test["label"].isin(unseen).astype(int)
    return train, test, unseen


def feature_cols():
    return [c for c in COLUMNS if c not in ("label", "difficulty")]


def make_preprocessor(scale=True):
    numeric = [c for c in feature_cols() if c not in CATEGORICAL]
    num_steps = [("log", FunctionTransformer(_log_heavy, kw_args={"cols_idx": [numeric.index(c) for c in HEAVY_TAILED]}, feature_names_out="one-to-one"))]
    if scale:
        num_steps.append(("scale", StandardScaler()))
    return ColumnTransformer([
        ("cat", OneHotEncoder(handle_unknown="ignore", sparse_output=False), CATEGORICAL),
        ("num", Pipeline(num_steps), numeric),
    ])


def _log_heavy(X, cols_idx):
    X = np.asarray(X, dtype=float).copy()
    X[:, cols_idx] = np.log1p(X[:, cols_idx])
    return X
