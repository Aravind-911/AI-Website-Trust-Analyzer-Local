import pandas as pd
import os
from datetime import datetime

FILE_PATH = "data/saved_websites.csv"


def save_website(user_id, url, trust_score, ai_result):
    """
    Save a website for a specific user.
    """

    os.makedirs("data", exist_ok=True)

    new_data = pd.DataFrame([{
        "User ID": user_id,
        "Website": url,
        "Trust Score": trust_score,
        "AI Verdict": ai_result,
        "Saved Date": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }])

    if os.path.exists(FILE_PATH) and os.path.getsize(FILE_PATH) > 0:

        try:
            old_data = pd.read_csv(FILE_PATH)

            # Make sure old files have User ID column
            if "User ID" not in old_data.columns:
                old_data.insert(0, "User ID", "legacy")

            # Don't save the same website twice
            # for the SAME user
            user_saved = old_data[
                (old_data["User ID"].astype(str) == str(user_id))
                &
                (old_data["Website"].astype(str).str.lower() == url.lower())
            ]

            if not user_saved.empty:
                return False

            data = pd.concat(
                [old_data, new_data],
                ignore_index=True
            )

        except pd.errors.EmptyDataError:
            data = new_data

    else:
        data = new_data

    data.to_csv(
        FILE_PATH,
        index=False
    )

    return True


def load_saved_websites(user_id):
    """
    Load saved websites belonging only to the current user.
    """

    empty_columns = [
        "Website",
        "Trust Score",
        "AI Verdict",
        "Saved Date"
    ]

    if not os.path.exists(FILE_PATH):
        return pd.DataFrame(columns=empty_columns)

    if os.path.getsize(FILE_PATH) == 0:
        return pd.DataFrame(columns=empty_columns)

    try:
        data = pd.read_csv(FILE_PATH)

        if data.empty:
            return pd.DataFrame(columns=empty_columns)

        # Old data without User ID should not appear
        # in a logged-in user's saved list.
        if "User ID" not in data.columns:
            return pd.DataFrame(columns=empty_columns)

        user_data = data[
            data["User ID"].astype(str) == str(user_id)
        ].copy()

        # Hide internal User ID from the UI
        if "User ID" in user_data.columns:
            user_data = user_data.drop(columns=["User ID"])

        return user_data

    except (pd.errors.EmptyDataError, pd.errors.ParserError):
        return pd.DataFrame(columns=empty_columns)


def delete_saved_website(user_id, url):
    """
    Delete a saved website only for the current user.
    """

    if not os.path.exists(FILE_PATH):
        return False

    if os.path.getsize(FILE_PATH) == 0:
        return False

    try:
        data = pd.read_csv(FILE_PATH)

        if "User ID" not in data.columns:
            return False

        matching = data[
            (data["User ID"].astype(str) == str(user_id))
            &
            (data["Website"].astype(str).str.lower() == url.lower())
        ]

        if matching.empty:
            return False

        data = data.drop(matching.index)

        data.to_csv(
            FILE_PATH,
            index=False
        )

        return True

    except (pd.errors.EmptyDataError, pd.errors.ParserError):
        return False


def clear_saved_websites(user_id):
    """
    Clear saved websites only for the current user.
    """

    if not os.path.exists(FILE_PATH):
        return False

    if os.path.getsize(FILE_PATH) == 0:
        return False

    try:
        data = pd.read_csv(FILE_PATH)

        if "User ID" not in data.columns:
            return False

        original_count = len(data)

        data = data[
            data["User ID"].astype(str) != str(user_id)
        ]

        if len(data) == original_count:
            return False

        data.to_csv(
            FILE_PATH,
            index=False
        )

        return True

    except (pd.errors.EmptyDataError, pd.errors.ParserError):
        return False