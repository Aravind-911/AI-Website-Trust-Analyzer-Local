import os
import pandas as pd
from datetime import datetime

FILE_PATH = "data/history.csv"

COLUMNS = [
    "User ID",
    "Date",
    "Website",
    "Trust Score",
    "AI Verdict"
]


# =========================================================
# SAVE HISTORY
# =========================================================

def save_history(
    url,
    trust_score,
    ai_result,
    user_id=None
):
    """
    Save website analysis history.

    Logged-in users:
        History is connected to their User ID.

    Guest users:
        user_id is None, so their history is not stored.
    """

    # Do not store guest history permanently.
    if user_id is None:
        return False

    os.makedirs("data", exist_ok=True)

    new_data = pd.DataFrame([{
        "User ID": user_id,
        "Date": datetime.now().strftime("%d-%m-%Y %H:%M"),
        "Website": url,
        "Trust Score": trust_score,
        "AI Verdict": ai_result
    }])

    if (
        os.path.exists(FILE_PATH)
        and os.path.getsize(FILE_PATH) > 0
    ):
        try:
            old_data = pd.read_csv(FILE_PATH)

            # Support an older history.csv that did not have User ID.
            if "User ID" not in old_data.columns:
                old_data["User ID"] = None

            # Make sure all required columns exist.
            for column in COLUMNS:
                if column not in old_data.columns:
                    old_data[column] = None

            old_data = old_data[COLUMNS]

            history = pd.concat(
                [old_data, new_data],
                ignore_index=True
            )

        except Exception:
            history = new_data
    else:
        history = new_data

    history.to_csv(
        FILE_PATH,
        index=False
    )

    return True


# =========================================================
# LOAD HISTORY
# =========================================================

def load_history(user_id=None):
    """
    Load history for one logged-in user.

    The User ID is used internally to separate accounts,
    but it is removed from the returned DataFrame so it
    does not appear in the visible history table.
    """

    empty = pd.DataFrame(
        columns=[
            "Date",
            "Website",
            "Trust Score",
            "AI Verdict"
        ]
    )

    if user_id is None:
        return empty

    if (
        not os.path.exists(FILE_PATH)
        or os.path.getsize(FILE_PATH) == 0
    ):
        return empty

    try:
        history = pd.read_csv(FILE_PATH)

        if "User ID" not in history.columns:
            return empty

        history["User ID"] = pd.to_numeric(
            history["User ID"],
            errors="coerce"
        )

        user_history = history[
            history["User ID"] == int(user_id)
        ].copy()

        # Remove internal User ID before returning data to the UI.
        user_history = user_history.drop(
            columns=["User ID"],
            errors="ignore"
        )

        # Keep only columns that should be displayed.
        display_columns = [
            "Date",
            "Website",
            "Trust Score",
            "AI Verdict"
        ]

        for column in display_columns:
            if column not in user_history.columns:
                user_history[column] = ""

        user_history = user_history[display_columns]

        # Reset numbering so the UI starts at 1, 2, 3...
        user_history = user_history.reset_index(drop=True)

        return user_history

    except Exception:
        return empty


# =========================================================
# CLEAR USER HISTORY
# =========================================================

def clear_history(user_id=None):
    """
    Delete history belonging only to one user.
    """

    if user_id is None:
        return False

    if (
        not os.path.exists(FILE_PATH)
        or os.path.getsize(FILE_PATH) == 0
    ):
        return False

    try:
        history = pd.read_csv(FILE_PATH)

        if "User ID" not in history.columns:
            return False

        history["User ID"] = pd.to_numeric(
            history["User ID"],
            errors="coerce"
        )

        user_id = int(user_id)

        user_rows = (
            history["User ID"] == user_id
        )

        if not user_rows.any():
            return False

        remaining_history = history[
            ~user_rows
        ]

        remaining_history.to_csv(
            FILE_PATH,
            index=False
        )

        return True

    except Exception:
        return False