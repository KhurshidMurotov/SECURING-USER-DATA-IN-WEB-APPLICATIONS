from django.conf import settings
from django.core import signing


EMAIL_VERIFICATION_SALT = 'accounts.email_verification'


def _get_max_age():
    """
    Return max age for email verification tokens.

    Defaults to 24 hours but can be overridden via
    EMAIL_VERIFICATION_MAX_AGE setting for testing/demo.
    """

    return getattr(settings, 'EMAIL_VERIFICATION_MAX_AGE', 60 * 60 * 24)


def generate_email_verification_token(user):
    """Generate a signed, timestamped token for email verification."""

    data = {'user_id': user.pk, 'email': user.email}
    return signing.dumps(data, salt=EMAIL_VERIFICATION_SALT)


def parse_email_verification_token(token):
    """
    Validate and decode an email verification token.

    Returns the payload dict on success, or None if the token is
    invalid or expired.
    """

    try:
        data = signing.loads(
            token,
            salt=EMAIL_VERIFICATION_SALT,
            max_age=_get_max_age(),
        )
    except (signing.BadSignature, signing.SignatureExpired):
        return None
    return data

