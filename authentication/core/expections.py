from django.utils.translation import gettext_lazy as _
from rest_framework.exceptions import APIException

class AccountLockedException(APIException):
    status_code= 403
    default_detail = _('Account is temporarily locaked due to multiple failed attempts')
    deafult_code = 'account_locked'

class EmailNotVerified(APIException):
    status_code = 403
    default_detail= _('Email verification required')
    default_code='email not verified'

class InvalidTokenException(APIException):
    status_code=401
    default_detail= _('Invalid or expired token')
    default_code = 'invalid_tokens'     
    
class RateLimitedExecption(APIException):
    status_code= 429
    default_detail=_('Rate limit exceeded. Please try again')
    default_code='rate_limited'
