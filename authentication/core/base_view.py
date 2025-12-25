import traceback
import logging
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.exceptions import TokenError

from response import standarized_response

logger = logging.getLogger(__name__)

class BaseAPIView(APIView):
    """ Base class for all API view with
        common error handling and response formatting"""
        
    def handle_exception(self, exc):
        """ standarized exception handling for all API views"""
        if isinstance(exc, AuthenticationFailed):
            return Response(standarized_response(success=False, error= str(exc)),
            status=status.HTTP_401_UNAUTHORIZED)
        elif isinstance(exc, TokenError):
            return Response(standarized_response(success=False, error="Invalid or expired tokens"),
            status=status.HTTP_401_UNAUTHORIZED)
        
        logger.error(f"unexpected error: {str(exc)}")
        logger.error(traceback.format_exc())
        return Response(standarized_response(success = False, error ="unexpected error occures"),
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
