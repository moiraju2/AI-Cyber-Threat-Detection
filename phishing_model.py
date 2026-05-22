<<<<<<< HEAD
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score

# ---------------- LOAD DATASET ---------------- #

df = pd.read_csv("datasets/phishing.csv")

# ---------------- FEATURES ---------------- #

X = df[[
    'having_IPhaving_IP_Address',
    'URLURL_Length',
    'Shortining_Service',
    'having_At_Symbol',
    'double_slash_redirecting',
    'Prefix_Suffix',
    'having_Sub_Domain',
    'SSLfinal_State',
    'Domain_registeration_length',
    'Favicon',
    'port',
    'HTTPS_token',
    'Request_URL',
    'URL_of_Anchor',
    'Links_in_tags',
    'SFH',
    'Submitting_to_email',
    'Abnormal_URL',
    'Redirect',
    'on_mouseover',
    'RightClick',
    'popUpWidnow',
    'Iframe',
    'age_of_domain',
    'DNSRecord',
    'web_traffic',
    'Page_Rank',
    'Google_Index',
    'Links_pointing_to_page',
    'Statistical_report'
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
        has_ip,
        url_length,
        shortener,
        has_at,
        0,
        prefix_suffix,
        0,
        ssl_state,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0
    ]],
    columns=[
        'having_IPhaving_IP_Address',
        'URLURL_Length',
        'Shortining_Service',
        'having_At_Symbol',
        'double_slash_redirecting',
        'Prefix_Suffix',
        'having_Sub_Domain',
        'SSLfinal_State',
        'Domain_registeration_length',
        'Favicon',
        'port',
        'HTTPS_token',
        'Request_URL',
        'URL_of_Anchor',
        'Links_in_tags',
        'SFH',
        'Submitting_to_email',
        'Abnormal_URL',
        'Redirect',
        'on_mouseover',
        'RightClick',
        'popUpWidnow',
        'Iframe',
        'age_of_domain',
        'DNSRecord',
        'web_traffic',
        'Page_Rank',
        'Google_Index',
        'Links_pointing_to_page',
        'Statistical_report'
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

=======
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score

# ---------------- LOAD DATASET ---------------- #

df = pd.read_csv("datasets/phishing.csv")

# ---------------- FEATURES ---------------- #

X = df[[
    'having_IPhaving_IP_Address',
    'URLURL_Length',
    'Shortining_Service',
    'having_At_Symbol',
    'double_slash_redirecting',
    'Prefix_Suffix',
    'having_Sub_Domain',
    'SSLfinal_State',
    'Domain_registeration_length',
    'Favicon',
    'port',
    'HTTPS_token',
    'Request_URL',
    'URL_of_Anchor',
    'Links_in_tags',
    'SFH',
    'Submitting_to_email',
    'Abnormal_URL',
    'Redirect',
    'on_mouseover',
    'RightClick',
    'popUpWidnow',
    'Iframe',
    'age_of_domain',
    'DNSRecord',
    'web_traffic',
    'Page_Rank',
    'Google_Index',
    'Links_pointing_to_page',
    'Statistical_report'
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
        has_ip,
        url_length,
        shortener,
        has_at,
        0,
        prefix_suffix,
        0,
        ssl_state,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0
    ]],
    columns=[
        'having_IPhaving_IP_Address',
        'URLURL_Length',
        'Shortining_Service',
        'having_At_Symbol',
        'double_slash_redirecting',
        'Prefix_Suffix',
        'having_Sub_Domain',
        'SSLfinal_State',
        'Domain_registeration_length',
        'Favicon',
        'port',
        'HTTPS_token',
        'Request_URL',
        'URL_of_Anchor',
        'Links_in_tags',
        'SFH',
        'Submitting_to_email',
        'Abnormal_URL',
        'Redirect',
        'on_mouseover',
        'RightClick',
        'popUpWidnow',
        'Iframe',
        'age_of_domain',
        'DNSRecord',
        'web_traffic',
        'Page_Rank',
        'Google_Index',
        'Links_pointing_to_page',
        'Statistical_report'
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

>>>>>>> c314c80b1ba667284dad2bd724f11765b1b8ee1f
    return safe_percent, phishing_percent