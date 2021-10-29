"""
Backend needed to log in using BigCommerce via python social auth.
"""
from __future__ import unicode_literals

from social_core.exceptions import AuthMissingParameter
from social_core.backends.oauth import BaseOAuth2
from social_core.backends.email import EmailAuth
from social_core.utils import handle_http_errors
# import bigcommerce.api

API_VERSION = 3

class BigCommerceAdminBaseAuth(BaseOAuth2):  # pylint: disable=abstract-method
    """
    BigCommerce OAuth authentication base backend for Admin accounts.

    In testing with BigCommerce OAuth this seems to only work with Staff Admin Users (not Customer accounts).
    Caution: This is still WIP and not fully developed.
    """

    # https://none/oauth2/authorize?client_id=&state=aoXfKXnWezd3413k4GdCil9azlP7Jcn4&redirect_uri=http%3A%2F%2Fcourses.trustworks-aas.localhost%3A18000%2Fauth%2Fcomplete%2Fbigcommerce-oauth2%2F%3Fredirect_state%3DaoXfKXnWezd3413k4GdCil9azlP7Jcn4&response_type=code

    name = ''
    AUTH_SERVICE = 'login.bigcommerce.com'
    API_SERVICE = 'api.bigcommerce.com'
    AUTHORIZATION_URL = 'https://{domain}/oauth2/authorize'
    ACCESS_TOKEN_URL = 'https://{domain}/oauth2/token'
    CUSTOMER_DETAILS_URL = 'https://{domain}/stores/{store_hash}/v{version}/customers'
    ACCESS_TOKEN_METHOD = 'POST'
    ID_KEY = "id" # (e.g. `clemson:ZTRABOO@clemson.edu` value for Clemson SAML)
    SCOPE_SEPARATOR = '+'
    STATE_PARAMETER = False
    REDIRECT_STATE = False
    EXTRA_DATA = [
        ('id', 'id'),
        ('email', 'email'),
        ('first_name', 'first_name'),
        ('last_name', 'last_name'),
        ('company', 'company'),
        ('phone', 'phone'),
        ('notes', 'notes'),
        ('registration_ip_address', 'registration_ip_address'),
        ('date_created', 'date_created'),
        ('date_modified', 'date_modified'),
        ('access_token', 'access_token', True)
    ]

    def auth_path(self, path):
        """Build Login path for BigCommerce domain."""
        return path.format(domain=self.AUTH_SERVICE)

    def api_path(self, path, api_version=''):
        """Build API path for BigCommerce domain."""
        # return 'https://{domain}/stores/{store_hash}/{api_version}/{path}'.format(domain=self.API_SERVICE, store_hash=self.setting('STORE').get('HASH'), api_version=api_version, path=path)

        version = api_version if api_version else self.setting('API_VERSION', API_VERSION)
        return path.format(domain=self.API_SERVICE, store_hash=self.setting('STORE').get('HASH'), version=version)

    def authorization_url(self):
        """OAuth2 Authorization URL."""

        # return "https://educateworkforce-development.mybigcommerce.com/login/token/eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiI2bXM0cnZya2hudjVtM2gxbzU4Mm10cWI3d3ppeHlyIiwiaWF0IjoxNjMzNzMxODcwLCJqdGkiOiJjZjE0MTgxZS1kZGNjLTRkNGMtODk4MS1kNTY1NWVhZDk3NWQiLCJvcGVyYXRpb24iOiJjdXN0b21lcl9sb2dpbiIsInN0b3JlX2hhc2giOiIxbm9sM2N0bzgiLCJjdXN0b21lcl9pZCI6IjMifQ.NFfGKDpF_Ii0DXra1kT_OcsKZf6Cluf4WoNF30oQu5g"
        # return "https://educateworkforce-development.mybigcommerce.com/login.php"
        # return "https://educateworkforce-development.mybigcommerce.com/oauth2/authorize"

        return self.auth_path(self.AUTHORIZATION_URL)

    # def uses_redirect(self):
    #     return False

    # def auth_html(self):
    #     """Abstract Method Inclusion"""
    #     pass

    def access_token_url(self):
        """OAuth2 Token URL."""
        return self.auth_path(self.ACCESS_TOKEN_URL)

    def request_access_token(self, *args, **kwargs):
        # BigCommerce expects a POST request with querystring parameters, despite
        # the spec http://tools.ietf.org/html/rfc6749#section-4.1.3
        kwargs['params'] = kwargs.pop('data')
        return super().request_access_token(*args, **kwargs)

    def user_details_url(self):
        return self.api_path(self.CUSTOMER_DETAILS_URL)

    def bigcommerce_headers(self, access_token):
        # headers = super().auth_headers()
        headers = {}
        headers['Content-Type'] = 'application/json'
        headers['X-Auth-Token'] = '{access_token}'.format(
            access_token=access_token)
        return headers

    def bigcommerce_request(self, url, access_token, kwargs):
        """Helper function to make calls to BigCommerce API"""
        response = self.get_json(
            self.user_details_url(),
            headers=self.bigcommerce_headers(access_token)
        )
        return response

    def user_data(self, access_token, *args, **kwargs):
        """Loads user data from BigCommerce user API."""
        # client_key, client_secret = self.get_key_and_secret()
        # self.setting('STORE').get('ACCESS_TOKEN')
        response = self.bigcommerce_request(self.user_details_url, access_token, kwargs)
        return response

    def get_user_details(self, response):
        """Return user details from BigCommerce account."""

        fullname, first_name, last_name = self.get_user_names(
            first_name=response['first_name'],
            last_name=response['lastName']
        )
        return {
            'fullname': fullname, 
            'first_name': first_name.title(),
            'last_name': last_name.title(),
            'username': 'Student1', # fullname.replace(' ', ''),
            'email': 's1@ew.com' # response.get('email'),
        }

    @handle_http_errors
    def auth_complete(self, *args, **kwargs):
        """Completes login process, must return user instance"""

        self.process_error(self.data)
        # state = self.validate_state()
        # data, params = None, None
        # if self.ACCESS_TOKEN_METHOD == 'GET':
        #     params = self.auth_complete_params(state)
        # else:
        #     data = self.auth_complete_params(state)

        # response = self.request_access_token(
        #     self.access_token_url(),
        #     data=data,
        #     params=params,
        #     headers=self.auth_headers(),
        #     auth=self.auth_complete_credentials(),
        #     method=self.ACCESS_TOKEN_METHOD
        # )
        # self.process_error(response)
        response = {}
        response['access_token'] = self.setting('STORE').get('ACCESS_TOKEN')
        return self.do_auth(response['access_token'], response=response,
                            *args, **kwargs)

    @handle_http_errors
    def do_auth(self, access_token, *args, **kwargs):
        """Finish the auth process once the access_token was retrieved"""
        data = self.user_data(access_token, *args, **kwargs)
        
        response = kwargs.get('response') or {}
        response.update(data or {})
        if 'access_token' not in response:
            response['access_token'] = access_token
        kwargs.update({'response': response, 'backend': self})
        return self.strategy.authenticate(*args, **kwargs)


class BigCommerceAdminDefaultAuth(BigCommerceAdminBaseAuth):  # pylint: disable=abstract-method
    """
    BigCommerce OAuth authentication backend for Admin accounts on the `default` site.
    """

    name = 'bigcommerce-admin-default'


class BigCommerceAdminTrustworksAuth(BigCommerceAdminBaseAuth):  # pylint: disable=abstract-method
    """
    BigCommerce OAuth authentication backend for Admin accounts on the `Trustworks-aaS` site.
    """

    name = 'bigcommerce-admin-trustworks'


class BigCommerceCustomerBaseAuth(EmailAuth):  # pylint: disable=abstract-method
    """
    BigCommerce email authentication base backend for Customers accounts.
    """

    name = ''
    FORM_URL = 'https://{storefront}.{domain}/login.php'
    ID_KEY = 'id'
    REQUIRES_EMAIL_VALIDATION = True
    EXTRA_DATA = [
        ('store_hash', 'store_hash'),
        ('id', 'id'),
        ('email', 'email'),
        ('first_name', 'first_name'),
        ('last_name', 'last_name'),
    ]
    # We're not pulling all the Customer details from BigCommerce but here they are if needed to store in the `social_auth_usersocialauth` extra_data field.
    # ('email', 'email'),
    # ('first_name', 'first_name'),
    # ('last_name', 'last_name'),
    # ('company', 'company'),
    # ('phone', 'phone'),
    # ('notes', 'notes'),
    # ('registration_ip_address', 'registration_ip_address'),
    # ('date_created', 'date_created'),
    # ('date_modified', 'date_modified'),

    # def get_querystring(self, url, *args, **kwargs):
    #     return self.super().get_querystring(url, *args, **kwargs)

    def get_user_id(self, details, response):
        return details.get(self.ID_KEY) or \
               response.get(self.ID_KEY)

    def auth_path(self, path):
        """Build Login path for BigCommerce domain."""
        return path.format(
            storefront=self.setting('STOREFRONT').get('PATH'), 
            domain=self.setting('STOREFRONT').get('DOMAIN')
            )
    
    def auth_url(self):
        """Must return redirect URL to auth provider"""
        return self.auth_path(self.FORM_URL)

    def auth_html(self):
        """Abstract Method Inclusion"""
        pass

    def uses_redirect(self):
        return True

    def auth_complete(self, *args, **kwargs):
        """Completes login process, must return user instance"""
        bc_customer_metadata = self.strategy.bigcommerce_retrieve_and_store_customer(self.data.get('token'), backend=self)

        # No need to keep passing this token down the social_core pipeline 
        # stages since it was decode and only used to pull in data assigned
        # below from `bc_customer_metadata`.
        self.data.pop('token')

        self.data['store_hash'] = bc_customer_metadata.get('store_hash')
        self.data['id'] = bc_customer_metadata.get('id')
        self.data['email'] = bc_customer_metadata.get('email')
        self.data['first_name'] = bc_customer_metadata.get('first_name')
        self.data['last_name'] = bc_customer_metadata.get('last_name')

        if self.ID_KEY not in self.data:
            raise AuthMissingParameter(self, self.ID_KEY)
        kwargs.update({'response': self.data, 'backend': self})
        return self.strategy.authenticate(*args, **kwargs)

    def get_user_details(self, response):
        """Return user details"""
        store_hash = response.get('store_hash', '')
        id = response.get('id', '')
        email = response.get('email', '')
        username = response.get('username', '')
        fullname, first_name, last_name = self.get_user_names(
            response.get('fullname', ''),
            response.get('first_name', ''),
            response.get('last_name', '')
        )
        if email and not username:
            username = email.split('@', 1)[0]
        return {
            'store_hash': store_hash,
            'id': id,
            'username': username,
            'email': email,
            'fullname': fullname,
            'first_name': first_name,
            'last_name': last_name,
            'country': 'US'
        }

    def extra_data(self, user, uid, response, details=None, *args, **kwargs):
        """Return access_token and extra defined names to store in
        extra_data field"""

        # Save off mapping between BigCommerce uid and platform user outside of the `socialauth_usersocialauth` table.
        payload = {'bc_uid': uid,'platform_user': user}
        self.strategy.bigcommerce_save_store_customer_platform_user(payload, backend=self)

        data = super(BigCommerceCustomerBaseAuth, self).extra_data(user, uid, response, details, *args, **kwargs)

        return data


class BigCommerceCustomerDefaultAuth(BigCommerceCustomerBaseAuth):  # pylint: disable=abstract-method
    """
    BigCommerce email authentication base backend for Customer accounts on the `default` site.
    """

    name = 'bc-customerauth-default'


class BigCommerceCustomerTrustworksAuth(BigCommerceCustomerBaseAuth):  # pylint: disable=abstract-method
    """
    BigCommerce email authentication base backend for Customer accounts on the `Trustworks` site.
    """

    name = 'bc-customerauth-trustworks'
    