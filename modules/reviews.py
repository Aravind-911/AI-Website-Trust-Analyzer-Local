import os
import pandas as pd
from datetime import datetime
from urllib.parse import urlparse

FILE_PATH = "data/reviews.csv"

COLUMNS = [
    "User ID",
    "Website",
    "Experience",
    "Rating",
    "Category",
    "Review",
    "Date"
]


# =========================================================
# NORMALIZE WEBSITE
# =========================================================

def normalize_website(website):
    """
    Convert different versions of a website URL
    into the same domain format.

    Example:
        https://www.amazon.in/
        https://amazon.in
        www.amazon.in

    All become:
        amazon.in
    """

    website = str(website).strip().lower()

    if not website.startswith(("http://", "https://")):
        website = "https://" + website

    parsed = urlparse(website)

    domain = parsed.netloc.lower()

    if domain.startswith("www."):
        domain = domain[4:]

    return domain


# =========================================================
# ADD REVIEW
# =========================================================

def add_review(
    website,
    experience,
    rating,
    category,
    review,
    user_id=None
):
    """
    Save a customer review.

    user_id identifies the account that submitted the review.
    The User ID is kept internally and is not shown in public
    review results.
    """

    # Reviews should belong to a registered account.
    if user_id is None:
        return False

    os.makedirs(
        "data",
        exist_ok=True
    )

    website = normalize_website(
        website
    )

    new_review = pd.DataFrame(
        [{
            "User ID": user_id,
            "Website": website,
            "Experience": experience,
            "Rating": rating,
            "Category": category,
            "Review": review,
            "Date": datetime.now().strftime(
                "%d-%m-%Y %H:%M"
            )
        }]
    )

    if (
        os.path.exists(FILE_PATH)
        and os.path.getsize(FILE_PATH) > 0
    ):
        try:
            old_reviews = pd.read_csv(
                FILE_PATH
            )

            # Support older reviews that did not have User ID.
            if "User ID" not in old_reviews.columns:
                old_reviews["User ID"] = None

            # Support reviews created before Experience was added.
            if "Experience" not in old_reviews.columns:
                old_reviews["Experience"] = "Not specified"

            # Make sure all required columns exist.
            for column in COLUMNS:
                if column not in old_reviews.columns:
                    old_reviews[column] = None

            old_reviews = old_reviews[COLUMNS]

            reviews = pd.concat(
                [
                    old_reviews,
                    new_review
                ],
                ignore_index=True
            )

        except pd.errors.EmptyDataError:
            reviews = new_review

    else:
        reviews = new_review

    reviews.to_csv(
        FILE_PATH,
        index=False
    )

    return True


# =========================================================
# LOAD REVIEWS
# =========================================================

def load_reviews():
    """
    Load all customer reviews.

    User ID remains available internally, but it should be
    removed by the UI before displaying reviews publicly.
    """

    if (
        not os.path.exists(FILE_PATH)
        or os.path.getsize(FILE_PATH) == 0
    ):
        return pd.DataFrame(
            columns=COLUMNS
        )

    try:
        reviews = pd.read_csv(
            FILE_PATH
        )

        # Compatibility with older reviews.
        if "User ID" not in reviews.columns:
            reviews["User ID"] = None

        if "Experience" not in reviews.columns:
            reviews["Experience"] = "Not specified"

        # Make sure all columns exist.
        for column in COLUMNS:
            if column not in reviews.columns:
                reviews[column] = None

        return reviews[COLUMNS]

    except (
        pd.errors.EmptyDataError,
        pd.errors.ParserError
    ):
        return pd.DataFrame(
            columns=COLUMNS
        )


# =========================================================
# GET REVIEWS FOR ONE WEBSITE
# =========================================================

def get_website_reviews(
    website
):
    """
    Return all public reviews for one website.

    The internal User ID is removed from the returned
    DataFrame so it is not exposed directly to the UI.
    """

    reviews = load_reviews()

    if reviews.empty:
        return pd.DataFrame(
            columns=[
                "Website",
                "Experience",
                "Rating",
                "Category",
                "Review",
                "Date"
            ]
        )

    target_website = normalize_website(
        website
    )

    normalized_saved_websites = (
        reviews["Website"]
        .astype(str)
        .apply(normalize_website)
    )

    result = reviews[
        normalized_saved_websites
        == target_website
    ].copy()

    # Do not expose internal account ID.
    result = result.drop(
        columns=["User ID"],
        errors="ignore"
    )

    return result.reset_index(drop=True)


# =========================================================
# GET REVIEWS WRITTEN BY ONE USER
# =========================================================

def get_user_reviews(user_id):
    """
    Return reviews submitted by one specific user.

    User ID is hidden from the returned DataFrame.
    """

    if user_id is None:
        return pd.DataFrame(
            columns=[
                "Website",
                "Experience",
                "Rating",
                "Category",
                "Review",
                "Date"
            ]
        )

    reviews = load_reviews()

    if reviews.empty:
        return pd.DataFrame(
            columns=[
                "Website",
                "Experience",
                "Rating",
                "Category",
                "Review",
                "Date"
            ]
        )

    user_reviews = reviews[
        reviews["User ID"].astype(str)
        == str(user_id)
    ].copy()

    user_reviews = user_reviews.drop(
        columns=["User ID"],
        errors="ignore"
    )

    return user_reviews.reset_index(drop=True)


# =========================================================
# AVERAGE RATING
# =========================================================

def get_average_rating(
    website
):
    reviews = get_website_reviews(
        website
    )

    if reviews.empty:
        return 0

    ratings = pd.to_numeric(
        reviews["Rating"],
        errors="coerce"
    )

    if ratings.dropna().empty:
        return 0

    return round(
        ratings.mean(),
        1
    )


# =========================================================
# EXPERIENCE STATISTICS
# =========================================================

def get_experience_stats(
    website
):
    reviews = get_website_reviews(
        website
    )

    if reviews.empty:
        return {
            "positive": 0,
            "negative": 0
        }

    experiences = (
        reviews["Experience"]
        .astype(str)
        .str.lower()
        .str.strip()
    )

    positive = (
        experiences == "positive"
    ).sum()

    negative = (
        experiences == "negative"
    ).sum()

    return {
        "positive": int(positive),
        "negative": int(negative)
    }