import datetime

from django.conf import settings
from rest_framework.settings import APISettings


USER_SETTINGS = getattr(settings, 'JWT_AUTH', None)

DEFAULTS = {
    'JWT_ENCODE_HANDLER':
    'rest_framework_jwt.utils.jwt_encode_handler',

    'JWT_DECODE_HANDLER':
    'rest_framework_jwt.utils.jwt_decode_handler',

    'JWT_PAYLOAD_HANDLER':
    'rest_framework_jwt.utils.jwt_payload_handler',

    'JWT_REFRESH_PAYLOAD_HANDLER':
    'rest_framework_jwt.utils.jwt_refresh_payload_handler',

    'JWT_PAYLOAD_GET_USER_ID_HANDLER':
    'rest_framework_jwt.utils.jwt_get_user_id_from_payload_handler',

    'JWT_PAYLOAD_GET_USER_PASSWORD_HANDLER':
    'rest_framework_jwt.utils.jwt_get_user_password_from_payload_handler',

    'JWT_PAYLOAD_GET_DECODED_USER_PASSWORD':
    'rest_framework_jwt.utils.jwt_get_decoded_user_password',

    'JWT_PRIVATE_KEY':
    None,

    'JWT_PUBLIC_KEY':
    None,

    'JWT_PAYLOAD_GET_USERNAME_HANDLER':
    'rest_framework_jwt.utils.jwt_get_username_from_payload_handler',

    'JWT_RESPONSE_PAYLOAD_HANDLER':
    'rest_framework_jwt.utils.jwt_response_payload_handler',

    'JWT_SECRET_KEY': settings.SECRET_KEY,
    'JWT_ALGORITHM': 'HS256',
    'JWT_VERIFY': True,
    'JWT_VERIFY_EXPIRATION': True,
    'JWT_LEEWAY': 0,
    'JWT_EXPIRATION_DELTA': datetime.timedelta(seconds=300),
    'JWT_AUDIENCE': None,
    'JWT_ISSUER': None,
    'JWT_TOKEN_KEYWORD': 'access',

    'JWT_ALLOW_REFRESH': True,
    'JWT_REFRESH_EXPIRATION_DELTA': datetime.timedelta(days=7),
    'JWT_REFRESH_KEYWORD': 'refresh',
    'JWT_AUTH_USER_PASSWORD_FIELD': 'password',
    'JWT_AUTH_HEADER_PREFIX': 'JWT',
}

# List of settings that may be in string import notation.
IMPORT_STRINGS = (
    'JWT_ENCODE_HANDLER',
    'JWT_DECODE_HANDLER',
    'JWT_PAYLOAD_HANDLER',
    'JWT_PAYLOAD_GET_USER_ID_HANDLER',
    'JWT_PAYLOAD_GET_USERNAME_HANDLER',
    'JWT_RESPONSE_PAYLOAD_HANDLER',
    'JWT_REFRESH_PAYLOAD_HANDLER',
    'JWT_PAYLOAD_GET_DECODED_USER_PASSWORD',
    'JWT_PAYLOAD_GET_USER_PASSWORD_HANDLER'
)

api_settings = APISettings(USER_SETTINGS, DEFAULTS, IMPORT_STRINGS)
