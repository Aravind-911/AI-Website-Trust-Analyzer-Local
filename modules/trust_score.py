def calculate_trust_score(ssl_status, https_status, domain_age):

    score = 0

    if ssl_status:
        score += 30

    if https_status:
        score += 20

    if domain_age is not None:
        if domain_age >= 10:
            score += 50
        elif domain_age >= 5:
            score += 35
        elif domain_age >= 2:
            score += 20
        else:
            score += 10

    return score