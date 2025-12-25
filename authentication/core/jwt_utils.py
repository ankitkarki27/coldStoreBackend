from rest_framework_simplejwt.tokens import RefreshToken, TokenError
from datetime import datetime,timedelta
from django.conf import settings
from django.core.cache import cache
import jwt
import logging
import uuid
import time
from django.utils import timezone
from django_redis import get_redis_connection

logger = logging.getLogger(__name__)

class TokenManager:
    """enhanced JWT token manager wih Redis caching  """
    @staticmethod
    def _get_redis_client():
        """ get a req radis-py client"""
        return get_redis_connection("default")
    
    @staticmethod
    def generate_tokens(user):
        """ Generate secure access and refresh tokens with enhanceed claims and security"""
        try:
            refresh = RefreshToken.for_user(user)
            
            #create unique JTI(JWT ID) for better tracking
            jti = str(uuid.uuid4())
            
            #add custom claims with security considerations
            refresh['jti']=jti
            refresh['username']= user.username
            refresh['is_staff']= user.is_staff
            refresh['email']= user.email
            refresh['is_verified']= user.is_verified
            refresh['type']='refresh'
            
            # set up differebt claims for access tokens
            access_token = refresh.access_token
            access_token['type'] = 'access'
            access_token['jti'] = str(uuid.uuid4())
            
            access_expiry = settings.SIMPLE_JWT.get('ACCESS_TOKEN_LIFETIME', timedelta(minutes=15))
            refresh_expiry=settings.SIMPLE_JWT.get('REFRESH_TOKEN_LIFETIME',timedelta(days=14))
            
            # store token in redis
            TokenManager._store_token_metadata(user.id, jti, refresh_expiry.total_seconds())
            
            return{
                'access_token':str(access_token),
                'refresh_token':str(refresh),
                'token_type': 'Bearer',
                'expires_in':int(access_expiry.total_seconds()),
                'refresh_expires_in':int(refresh_expiry.total_seconds()),
                'user_id':user.id,
                'issued_at': int(time.time())
                }
        except Exception as e:
            logger.error(f"Failed to generate tokens for user {user.id}: {str(e)}")
            raise
        
    @staticmethod
    def refresh_tokens(refresh_token):
        """refresh token with validation and optional rotation"""
        try:
            token = RefreshToken(refresh_token)
            jti = token.get('jti')

            if not jti or TokenManager.is_token_blacklisted(jti):
                logger.warning(f"attempt to use blacklisted tokens with JTI: {jti}")
                raise TokenError("Token is blacklisted")
            
            #get user from token
            user_id = token.get('user_id')
            
            from authentication.models import CustomUser 
            
            try:
                user = CustomUser.objects.get(id = user_id)
                
            except CustomUser.DoesNotExist:
                logger.warning(f"Token refresh attempted for non existent user with this id: {user_id}")
                raise TokenError("Invalid token")
            
            if not user.is_active:
                logger.warning(f"Token refresh attempted for inactive user: {user.email} ")
                TokenManager.blacklist_token(jti)
                raise TokenError("user is inactive")
            
            if settings.SIMPLE_JWT.get('ROTATE_REFRESH_TOKENS', True):
                TokenManager.blacklist_token(jti)

            #generate new tokens after blacklising old ones
            
            return TokenManager.generate_tokens(user)
        except TokenError as e:
            logger.warning(f"Token refresh error : {str(e)}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error during token refresh: {str(e)}")
            raise TokenError(f"Token refresh failed: {str(e)}")
        
        
    @staticmethod
    def validate_tokens(token_string):
        """ validate tokens without using the db """
        try:
            unverified_jwt = jwt.decode(token_string, options = {"verify_signature":False})
            alg = unverified_jwt.get('alg', settings.SIMPLE_JWT.get('ALGORITHM','HS256'))
            
            decoded = jwt.decode(
                token_string,
                settings.SIMPLE_JWT.get('SIGNING_KEY',settings.SECRET_KEY),
                algorithms = [alg],
                options={ "verify_signature":True }  
            )
            
            token_type = decoded.get('token_type', decoded.get('type','access'))
            user_id = decoded.get('user_id')
            jti = decoded.get('jti')
            
            if jti and TokenManager.is_token_blacklisted(jti):
                logger.warning(f"Attempt to use blacklisted token with jti: {jti}")
                return False, None, None
            
            
            exp = decoded.get('exp', 0)
            if exp < time.time():
                logger.debug(f"token expired at {datetime.fromtimestamp(exp).isoformat()}")
                return False, None, None
            return True, user_id, token_type
        
        except jwt.PyJWTError as e:
            logger.debug(f"Token validation error: {str(e)}")
            return False, None, None
                    
    # method for blacklisting
    @staticmethod
    def blacklist_token(jti):
        """ blacklist a token by JTI"""
        if not jti:
            return False
        
        try:
            redis_client = TokenManager._get_redis_client()
            blacklist_key = f"blacklisted_token:{jti}"
            timeout= settings.SIMPLE_JWT.get('BLACKLIST_TIMEOUT', 86400)
            redis_client.setex(blacklist_key, timeout, "1")
            return True
        except Exception as e:
            logger.error(f"Error blacklisting token in redis")
            return False

    @staticmethod
    def is_token_blacklisted(jti):
        """ check if a token is blacklisted or not"""
        if not jti:
            return False
        
        try:
            redis_client = TokenManager._get_redis_client()
            blacklist_key = f"blacklisted_token:{jti}"
            return redis_client.exists(blacklist_key)>0
        
        except Exception as e:
            logger.error(f"Error Checking token blacklist in redis: {str(e)}")
            return False
            
                  
   
    @staticmethod
    def _store_token_metadata(user_id, jti, expiry_seconds):
        """ store token methofds in redis for blacklisting"""
        
        try:
            redis_client = TokenManager._get_redis_client()
            user_tokens_key = f"user_tokens: {user_id}"
            
            pipe = redis_client.pipeline()
            pipe.sadd(user_tokens_key, jti)
            pipe.expire(user_tokens_key, int(expiry_seconds))
            pipe.execute()
            
        except Exception as e:
            logger.error(f"Error storing token metadata in redis: {str(e)}")
            
    
    @staticmethod
    def blacklist_all_user_tokens(user_id):
        """ blacklist all user tokens from specific user and id"""
        try:
            redis_client = TokenManager._get_redis_client()
            user_tokens_key = f"user_tokens:{user_id}"
            
            #get all active tokens fr the user
            active_tokens = redis_client.smembers(user_tokens_key)
            if not active_tokens:
                return 0
            
            pipe = redis_client.pipeline()
            blacklist_timeout = settings.Simple_JWT.get('BLACKLIST_TIMEOUT', 86400)
            
            for jti in active_tokens:
                jti_str = jti.decode('utf-8') if isinstance(jti,bytes) else jti
                
                blacklist_key = f"blacklisted_token: {jti_str}"
                pipe.setex(blacklist_key, blacklist_timeout, "1")
                
            #clear the user tokens set
            pipe.delete(user_tokens_key)
            pipe.execute()
            
            logger.info(f"Blacklisted {len(active_tokens)} tokens for user {user_id}")
            return len(active_tokens)

        except Exception as e:
            logger.error(f"Error blacklisting user tokens in redis :{str(e)}")
            return 0
        
    @staticmethod
    def get_user_active_tokens_count(user_id):
        """ get cout of active tokens for a user"""
        try:
            redis_client = TokenManager._get_redis_client()
            user_tokens_key = f"user_tokens: {user_id}"
            return redis_client.scard(user_tokens_key)
        except Exception as e:
            logger.error(f"Error getting user token count from Redis : {str(e)}")
            return 0
        
    @staticmethod
    def cleanup_expired_tokens():
        """ utility methods to clean up expired tokens meta data"""
        try:
            redis_client = TokenManager._get_redis_client
            logger.info("Token Cleanup Completed")
            return True
        except Exception as e:
            logger.error(f"Error during token cleanup: {str(e)}")
            return False

                