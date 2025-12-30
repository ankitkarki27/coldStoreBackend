import logging
import traceback
from django.utils import timezone
from django.conf import settings
from django.middleware.csrf import get_token
from datetime import timedelta

from rest_framework import status
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.throttling import AnonRateThrottle, UserRateThrottle
from rest_framework_simplejwt.tokens import RefreshToken

from authentication.core.base_view import BaseAPIView
from authentication.core.response import standarized_response
from .services import AuthenticationService

logger = logging.getLogger(__name__)

class UserRegistrationView(BaseAPIView):
    permission_classes= [AllowAny]
    throttle_classes = [AnonRateThrottle]
    
    def post(self, request):
        try:
            email = request.data.get('email')
            password = request.data.get('password')
            phone_number = request.data.get('phone_number')
            first_name = request.data.get('first_name')
            last_name = request.data.get('last_name')
            
            success, response_data, status_code = AuthenticationService.register(
                email = email, 
                password=password,
                phone_number= phone_number,
                first_name= first_name,
                last_name= last_name,
                request = request.META,
                request=request
            )
            
            # create response obj
            response = Response(
                standarized_response(**response_data), status=status_code
            )
            
            if success and status_code in (200,201) and settings.JWT_COOKIE_SECURE:
                tokens = response_data.get('data',{}).get('tokens',{}) #data and tokens from services.py
                if 'refresh_token' in tokens and 'refresh_expirers_in' in tokens:
                    response set_cookie(
                        key = settings.JWT_COOKIE_NAME,
                        value = tokens['refresh_token'], 
                        expires= timezone.now()+ timedelta(seconds = ['refresh_expires_in']),
                        secure = True,
                        httponly = True,
                        samesite ='strict', 
                        path = '/',
                        domain = settings.SESSION_COOKIE_DOMAIN
                    )
                    
                #set csrf token
                if success:
                    get_token(request)
                    
                return response
            
        except Exception as e:
            logger.error(f"error in the registration : {str(e)}")
            
            # else 
            #     logger.error(f"Error in the registration:")
                
            
            
            
            
            

                    