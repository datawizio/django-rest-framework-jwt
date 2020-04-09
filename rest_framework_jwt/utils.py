import jwt
import uuid
import warnings
from calendar import timegm
from datetime import datetime
from hashlib import sha256
from rest_framework_jwt.compat import get_username, get_username_field
from rest_framework_jwt.settings import api_settings
import six

def jwt_get_decoded_user_password(user):
    password = getattr(user, api_settings.JWT_AUTH_USER_PASSWORD_FIELD)
    if six.PY2:
        key = sha256(password).hexdigest()
    else:
        key = sha256(password.encode()).hexdigest()
    return key

def jwt_refresh_payload_handler(user):
    """
    Used to generate long-term refresh token
    """
    #We added "key" param to verify, that user password not changed
    payload = {
        'token_type': api_settings.JWT_REFRESH_KEYWORD,
        "exp": datetime.utcnow() + api_settings.JWT_REFRESH_EXPIRATION_DELTA,
        'jti': jwt_get_decoded_user_password(user),
        'user_id': user.pk,
        'username': get_username(user)
               }
    if isinstance(user.pk, uuid.UUID):
        payload['user_id'] = str(user.pk)
    if api_settings.JWT_AUDIENCE is not None:
        payload['aud'] = api_settings.JWT_AUDIENCE

    if api_settings.JWT_ISSUER is not None:
        payload['iss'] = api_settings.JWT_ISSUER
    return payload


def jwt_payload_handler(user):
    payload = {
        'user_id': user.pk,
        'jti': uuid.uuid4().hex,
        'exp': datetime.utcnow() + api_settings.JWT_EXPIRATION_DELTA,
        'token_type': api_settings.JWT_TOKEN_KEYWORD,
        'username': get_username(user)
    }
    if isinstance(user.pk, uuid.UUID):
        payload['user_id'] = str(user.pk)

    # Include original issued at time for a brand new token,
    # to allow token refresh
    # if api_settings.JWT_ALLOW_REFRESH:
    #     payload['orig_iat'] = timegm(
    #         datetime.utcnow().utctimetuple()
    #     )

    if api_settings.JWT_AUDIENCE is not None:
        payload['aud'] = api_settings.JWT_AUDIENCE

    if api_settings.JWT_ISSUER is not None:
        payload['iss'] = api_settings.JWT_ISSUER

    return payload


def jwt_get_user_id_from_payload_handler(payload):
    """
    Override this function if user_id is formatted differently in payload
    """
    warnings.warn(
        'The following will be removed in the future. '
        'Use `JWT_PAYLOAD_GET_USERNAME_HANDLER` instead.',
        DeprecationWarning
    )

    return payload.get('user_id')


def jwt_get_username_from_payload_handler(payload):
    """
    Override this function if username is formatted differently in payload
    """
    return payload.get('username')

def jwt_get_user_password_from_payload_handler(payload):
    return payload.get('jti')

def jwt_encode_handler(payload):
    return jwt.encode(
        payload,
        api_settings.JWT_PRIVATE_KEY or api_settings.JWT_SECRET_KEY,
        api_settings.JWT_ALGORITHM
    ).decode('utf-8')


def jwt_decode_handler(token):
    options = {
        'verify_exp': api_settings.JWT_VERIFY_EXPIRATION,
    }

    return jwt.decode(
        token,
        api_settings.JWT_PUBLIC_KEY or api_settings.JWT_SECRET_KEY,
        api_settings.JWT_VERIFY,
        options=options,
        leeway=api_settings.JWT_LEEWAY,
        audience=api_settings.JWT_AUDIENCE,
        issuer=api_settings.JWT_ISSUER,
        algorithms=[api_settings.JWT_ALGORITHM]
    )


def jwt_response_payload_handler(token, user=None, request=None, **kwargs):
    """
    Returns the response data for both the login and refresh views.
    Override to return a custom response such as including the
    serialized representation of the User.

    Example:

    def jwt_response_payload_handler(token, user=None, request=None):
        return {
            'token': token,
            'user': UserSerializer(user, context={'request': request}).data
        }

    """
    kwargs['token'] = token
    return kwargs