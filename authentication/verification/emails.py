import logging
import traceback
from django.conf import settings
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.contrib.auth.tokens import default_token_generator
from django.contrib.auth import get_user_model

User = get_user_model()
logger = logging.getLogger(__name__)

class EmailService:
    """ Service for sending user-related emails"""
    
    @staticmethod
    def send_verification_email(user):
        """ send verification email to a user wuth verification link"""
        try:
            #fenerate at first verificn token for link
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            token = default_token_generator.make_token(user)
            
            # create verification link
            verify_url = f"{settings.FRONTEND_URL}/auth/email_verify?uid={uid}&token={token}"
            
            subject = f"{settings.APP_NAME}- verify your email address "
            
            context = {'user':user,
                    'verify_url':verify_url,
                    'app_name':settings.APP_NAME}
            
            try:
                html_message = render_to_string('emails/verify_email.html',context)
                
                plain_message = f"""
                Hello {user.email},
                Please verify your email address by clicking the link given below:
                {verify_url}
                
                Thank you,
                {settings.APP_NAME} Team
                """
                
            except Exception as template_error:
                logger.error(f"template rendering error: {str(template_error)}")
                raise
            
            #send the email
            
            from_email = settings.DEFAULT_FROM_EMAIL or settings.EMAIL_HOST_USER
            
            send_mail(
                subject = subject,
                message= plain_message,
                from_email= from_email,
                recipient_list = {user.email},
                html_message= html_message,
                fail_silently = False
            )
            
            logger.info(f"Verification email sent to {user.email}")
        
        except Exception as e:
            logger.error(f"Error in verification email propagation for {user.email}: {str(e)}")
            raise