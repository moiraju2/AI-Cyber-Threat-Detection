import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score

# ---------------- LOAD DATASET ---------------- #

df = pd.read_csv("datasets/phishing.csv")

# ---------------- FEATURES ---------------- #

X = df[[
    'URLURL_Length',
    'having_At_Symbol',
    'having_IPhaving_IP_Address',
    'Shortining_Service',
    'Prefix_Suffix',
    'SSLfinal_State'
]]

y = df['Result']

# ---------------- TRAIN TEST SPLIT ---------------- #

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42
)

# ---------------- MODEL ---------------- #

model = RandomForestClassifier(
    n_estimators=200,
    random_state=42
)

model.fit(X_train, y_train)

# ---------------- ACCURACY ---------------- #

y_pred = model.predict(X_test)

accuracy = accuracy_score(y_test, y_pred)

print("Accuracy:", accuracy)

# ---------------- URL FEATURE EXTRACT ---------------- #

def extract_features(url):

    url_length = len(url)

    has_at = 1 if "@" in url else 0

    has_ip = 1 if "192." in url or "127." in url else 0

    shortener = 1 if (
        "bit.ly" in url
        or "tinyurl" in url
        or "goo.gl" in url
    ) else 0

    prefix_suffix = 1 if "-" in url else 0

    ssl_state = 1 if url.startswith("https") else 0

    return pd.DataFrame(
        [[
            url_length,
            has_at,
            has_ip,
            shortener,
            prefix_suffix,
            ssl_state
        ]],
        columns=[
            'URLURL_Length',
            'having_At_Symbol',
            'having_IPhaving_IP_Address',
            'Shortining_Service',
            'Prefix_Suffix',
            'SSLfinal_State'
        ]
    )

# ---------------- URL PREDICTION ---------------- #
def predict_url(url):

    # ---------------- RULE CHECKS ---------------- #

    suspicious_words = [
        "login",
        "verify",
        "bank",
        "secure",
        "update"
    ]

    # IP + suspicious text

    if "192." in url and any(
        word in url.lower()
        for word in suspicious_words
    ):
        return "Phishing"

    # Short URL

    if (
        "bit.ly" in url
        or "tinyurl" in url
        or "goo.gl" in url
    ):
        return "Phishing"

    # ML Prediction

    input_data = extract_features(url)

    result = model.predict(input_data)

    if result[0] == -1:
        return "Safe"
    else:
        return "Phishing"
    
# ---------------- PROBABILITY ---------------- #

def predict_url_probability(url):

    input_data = extract_features(url)

    probabilities = model.predict_proba(
        input_data
    )[0]

    safe_percent = round(
        max(probabilities)*100,
        2
    )

    phishing_percent = round(
        min(probabilities)*100,
        2
    )

    return safe_percent, phishing_percent