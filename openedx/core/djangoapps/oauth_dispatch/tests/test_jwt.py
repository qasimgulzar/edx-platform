""" Tests for OAuth Dispatch's jwt module. """
from datetime import timedelta
from unittest.mock import patch

import ddt
from django.test import TestCase
from django.test.utils import override_settings
from django.utils.timezone import now

from openedx.core.djangoapps.oauth_dispatch import jwt as jwt_api
from openedx.core.djangoapps.oauth_dispatch.adapters import DOTAdapter
from openedx.core.djangoapps.oauth_dispatch.models import RestrictedApplication
from openedx.core.djangoapps.oauth_dispatch.tests.mixins import AccessTokenMixin
from common.djangoapps.student.tests.factories import UserFactory


@ddt.ddt
class TestCreateJWTs(AccessTokenMixin, TestCase):
    """ Tests for oauth_dispatch's jwt creation functionality. """
    def setUp(self):
        super().setUp()
        self.user = UserFactory()
        self.default_scopes = ['email', 'profile']
        self.default_scopes_password_grant_type = ['email', 'profile', 'user_id']

    def _create_client(self, oauth_adapter, client_restricted, grant_type=None):
        """
        Creates and returns an OAuth client using the given oauth_adapter.
        Configures the client as a RestrictedApplication if client_restricted is
        True.
        """
        client = oauth_adapter.create_public_client(
            name='public app',
            user=self.user,
            redirect_uri='',
            client_id='public-client-id',
            grant_type=grant_type or '',
        )
        if client_restricted:
            RestrictedApplication.objects.create(application=client)
        return client

    def _get_token_dict(self, client_restricted, oauth_adapter, grant_type=None):
        """ Creates and returns an (opaque) access token dict """
        client = self._create_client(oauth_adapter, client_restricted, grant_type=grant_type)
        expires_in = 60 * 60
        expires = now() + timedelta(seconds=expires_in)
        token_dict = dict(
            access_token=oauth_adapter.create_access_token_for_test('token', client, self.user, expires),
            expires_in=expires_in,
            scope=' '.join(self.default_scopes)
        )
        return token_dict

    def _create_jwt_for_token(
        self, oauth_adapter, use_asymmetric_key, client_restricted=False,
    ):
        """ Creates and returns the jwt returned by jwt_api.create_jwt_from_token. """
        token_dict = self._get_token_dict(client_restricted, oauth_adapter)
        return jwt_api.create_jwt_from_token(token_dict, oauth_adapter, use_asymmetric_key=use_asymmetric_key)

    def _assert_jwt_is_valid(self, jwt_token, should_be_asymmetric_key):
        """ Asserts the given jwt_token is valid and meets expectations. """
        self.assert_valid_jwt_access_token(
            jwt_token, self.user, self.default_scopes, should_be_asymmetric_key=should_be_asymmetric_key,
        )

    def test_create_jwt_for_token(self):
        oauth_adapter = DOTAdapter()
        jwt_token = self._create_jwt_for_token(oauth_adapter, use_asymmetric_key=False)
        self._assert_jwt_is_valid(jwt_token, should_be_asymmetric_key=False)

    def test_dot_create_jwt_for_token_with_asymmetric(self):
        jwt_token = self._create_jwt_for_token(DOTAdapter(), use_asymmetric_key=True)
        self._assert_jwt_is_valid(jwt_token, should_be_asymmetric_key=True)

    @override_settings(JWT_AUTH_FORCE_CREATE_ASYMMETRIC=True)
    def test_dot_create_jwt_for_token_forced_asymmetric(self):
        jwt_token = self._create_jwt_for_token(DOTAdapter(), use_asymmetric_key=False)
        self._assert_jwt_is_valid(jwt_token, should_be_asymmetric_key=True)

    @override_settings(JWT_AUTH_ADD_KID_HEADER=True)
    def test_dot_encode_and_sign(self):
        jwt_token = self._create_jwt_for_token(DOTAdapter(), use_asymmetric_key=True)
        self._assert_jwt_is_valid(jwt_token, should_be_asymmetric_key=True)

    @override_settings(JWT_AUTH_ADD_KID_HEADER=True)
    def test_dot_encode_and_sign_kid_none(self):
        jwt_private_signing_jwk = {
            'JWT_PRIVATE_SIGNING_JWK': {
                "kty": "RSA",
                "key_ops": [
                    "sign"
                ],
                "n": "smKFSYowG6nNUAdeqH1jQQnH1PmIHphzBmwJ5vRf1vu48BUI5VcVtUWIPqzRK_LDSlZYh9D0YFL0ZTxIrlb6Tn3Xz7pYvpIAeYuQv3_H5p8tbz7Fb8r63c1828wXPITVTv8f7oxx5W3lFFgpFAyYMmROC4Ee9qG5T38LFe8_oAuFCEntimWxN9F3P-FJQy43TL7wG54WodgiM0EgzkeLr5K6cDnyckWjTuZbWI-4ffcTgTZsL_Kq1owa_J2ngEfxMCObnzGy5ZLcTUomo4rZLjghVpq6KZxfS6I1Vz79ZsMVUWEdXOYePCKKsrQG20ogQEkmTf9FT_SouC6jPcHLXw",
                "e": "AQAB",
                "d": "RQ6k4NpRU3RB2lhwCbQ452W86bMMQiPsa7EJiFJUg-qBJthN0FMNQVbArtrCQ0xA1BdnQHThFiUnHcXfsTZUwmwvTuiqEGR_MI6aI7h5D8vRj_5x-pxOz-0MCB8TY8dcuK9FkljmgtYvV9flVzCk_uUb3ZJIBVyIW8En7n7nV7JXpS9zey1yVLld2AbRG6W5--Pgqr9JCI5-bLdc2otCLuen2sKyuUDHO5NIj30qGTaKUL-OW_PgVmxrwKwccF3w5uGNEvMQ-IcicosCOvzBwdIm1uhdm9rnHU1-fXz8VLRHNhGVv7z6moghjNI0_u4smhUkEsYeshPv7RQEWTdkOQ",
                "p": "7KWj7l-ZkfCElyfvwsl7kiosvi-ppOO7Imsv90cribf88DexcO67xdMPesjM9Nh5X209IT-TzbsOtVTXSQyEsy42NY72WETnd1_nAGLAmfxGdo8VV4ZDnRsA8N8POnWjRDwYlVBUEEeuT_MtMWzwIKU94bzkWVnHCY5vbhBYLeM",
                "q": "wPkfnjavNV1Hqb5Qqj2crBS9HQS6GDQIZ7WF9hlBb2ofDNe2K2dunddFqCOdvLXr7ydRcK51ZwSeHjcjgD1aJkHA9i1zqyboxgd0uAbxVDo6ohnlVqYLtap2tXXcavKm4C9MTpob_rk6FBfEuq4uSsuxFvCER4yG3CYBBa4gZVU",
                "dp": "MO9Ppss-Bl-mC1vGyJDBbMgr2GgivGYbHFLt6ERfTGsvcr0RhDjZu16ZpNpBB6B7-K-uJGHxPmmf8P9KRWDBUAwOSaT2a-pTsuux6PKCwVTZfUq5LxAkiyg6WZTGoWASEtoae0XRHEy2TvIKNl5AiX-h_DwDPDbEYcWCZVAb6-E",
                "dq": "m03j7GkGSWRxMGNCeEBtvvBR4vDS9Her7AtjbNSWnRxDMQrKSdRMaiu-m7tOT3n6D9cM7Cr7wZUtzBOENskprHBu47FgzfXakMWfYhv0TV0voxZERKAN_H7cWt4oLsprEzH9r6THsxFPdKxMYBGeoAOe2l9nlk26m6LaX7_rwqE",
                "qi": "jnJ0nfARyAcHsezENNrXKnDM-LrMJWMHPh_70ZM_pF5iRMOLojHkTVsUIzYi6Uj2ohX9Jz1zsV207kCuPqQXURbhlt1xEaktwCmySeWU4qkMTptWp4ya2jEwGn8EKJ1iEc0GhDkRyLrgm4ol-sq9DMaKEkhTGy4Y3-8mMCBVqeQ"
            }
        }
        with override_settings(JWT_AUTH=jwt_private_signing_jwk):
            jwt_token = self._create_jwt_for_token(DOTAdapter(), use_asymmetric_key=True)
        self._assert_jwt_is_valid(jwt_token, should_be_asymmetric_key=True)

    def test_create_jwt_for_token_default_expire_seconds(self):
        oauth_adapter = DOTAdapter()
        jwt_token = self._create_jwt_for_token(oauth_adapter, use_asymmetric_key=False)
        expected_expires_in = 60 * 60
        self.assert_valid_jwt_access_token(
            jwt_token, self.user, self.default_scopes, expires_in=expected_expires_in,
        )

    def test_create_jwt_for_token_overridden_expire_seconds(self):
        oauth_adapter = DOTAdapter()
        expected_expires_in = 60
        with override_settings(JWT_ACCESS_TOKEN_EXPIRE_SECONDS=expected_expires_in):
            jwt_token = self._create_jwt_for_token(oauth_adapter, use_asymmetric_key=False)
        self.assert_valid_jwt_access_token(
            jwt_token, self.user, self.default_scopes, expires_in=expected_expires_in,
        )

    def test_create_jwt_token_dict_for_default_expire_seconds(self):
        oauth_adapter = DOTAdapter()
        token_dict = self._get_token_dict(client_restricted=False, oauth_adapter=oauth_adapter)
        jwt_token_dict = jwt_api.create_jwt_token_dict(token_dict, oauth_adapter, use_asymmetric_key=False)
        expected_expires_in = 60 * 60
        self.assert_valid_jwt_access_token(
            jwt_token_dict["access_token"], self.user, self.default_scopes, expires_in=expected_expires_in,
        )
        assert jwt_token_dict["token_type"] == "JWT"
        assert jwt_token_dict["expires_in"] == expected_expires_in
        assert jwt_token_dict["scope"] == token_dict["scope"]

    def test_create_jwt_token_dict_for_overridden_expire_seconds(self):
        oauth_adapter = DOTAdapter()
        expected_expires_in = 60
        with override_settings(JWT_ACCESS_TOKEN_EXPIRE_SECONDS=expected_expires_in):
            token_dict = self._get_token_dict(client_restricted=False, oauth_adapter=oauth_adapter)
            jwt_token_dict = jwt_api.create_jwt_token_dict(token_dict, oauth_adapter, use_asymmetric_key=False)
        self.assert_valid_jwt_access_token(
            jwt_token_dict["access_token"], self.user, self.default_scopes, expires_in=expected_expires_in,
        )
        assert jwt_token_dict["token_type"] == "JWT"
        assert jwt_token_dict["expires_in"] == expected_expires_in
        assert jwt_token_dict["scope"] == token_dict["scope"]

    @ddt.data((True, False))
    def test_create_jwt_for_client_restricted(self, client_restricted):
        jwt_token = self._create_jwt_for_token(
            DOTAdapter(),
            use_asymmetric_key=None,
            client_restricted=client_restricted,
        )
        self._assert_jwt_is_valid(jwt_token, should_be_asymmetric_key=client_restricted)

    @patch('openedx.core.djangoapps.oauth_dispatch.jwt.create_role_auth_claim_for_user')
    @ddt.data(True, False)
    def test_create_jwt_for_user(self, user_email_verified, mock_create_roles):
        mock_create_roles.return_value = ['superuser', 'enterprise-admin']
        self.user.is_active = user_email_verified
        self.user.save()

        aud = 'test_aud'
        secret = 'test_secret'
        additional_claims = {'claim1_key': 'claim1_val'}
        jwt_token = jwt_api.create_jwt_for_user(self.user, secret=secret, aud=aud, additional_claims=additional_claims)
        token_payload = self.assert_valid_jwt_access_token(
            jwt_token, self.user, self.default_scopes, aud=aud, secret=secret,
        )
        self.assertDictContainsSubset(additional_claims, token_payload)
        assert user_email_verified == token_payload['email_verified']
        assert token_payload['roles'] == mock_create_roles.return_value

    def test_scopes(self):
        """
        Ensure the requested scopes are used.
        """
        scopes = [
            'user_id',
        ]
        aud = 'test_aud'
        secret = 'test_secret'

        jwt = jwt_api.create_jwt_for_user(self.user, secret=secret, aud=aud)
        jwt_scopes = jwt_api.create_jwt_for_user(self.user, secret=secret, aud=aud, scopes=scopes)

        jwt_payload = self.assert_valid_jwt_access_token(
            jwt, self.user, self.default_scopes, aud=aud, secret=secret,
        )
        jwt_scopes_payload = self.assert_valid_jwt_access_token(
            jwt_scopes, self.user, scopes, aud=aud, secret=secret,
        )
        assert jwt_payload['scopes'] == self.default_scopes
        assert jwt_scopes_payload['scopes'] == scopes
        assert jwt_scopes_payload['user_id'] == self.user.id

    def test_password_grant_type(self):
        oauth_adapter = DOTAdapter()
        token_dict = self._get_token_dict(client_restricted=False, oauth_adapter=oauth_adapter, grant_type='password')
        jwt_token_dict = jwt_api.create_jwt_token_dict(token_dict, oauth_adapter, use_asymmetric_key=False)

        self.assert_valid_jwt_access_token(
            jwt_token_dict["access_token"], self.user, self.default_scopes_password_grant_type,
            grant_type='password',
        )

    def test_None_grant_type(self):
        oauth_adapter = DOTAdapter()
        token_dict = self._get_token_dict(client_restricted=False, oauth_adapter=oauth_adapter, grant_type=None)
        jwt_token_dict = jwt_api.create_jwt_token_dict(token_dict, oauth_adapter, use_asymmetric_key=False)

        self.assert_valid_jwt_access_token(
            jwt_token_dict["access_token"], self.user, self.default_scopes,
            grant_type='',
        )

    def test_random_str_grant_type(self):
        oauth_adapter = DOTAdapter()
        token_dict = self._get_token_dict(client_restricted=False, oauth_adapter=oauth_adapter, grant_type='test rand')
        jwt_token_dict = jwt_api.create_jwt_token_dict(token_dict, oauth_adapter, use_asymmetric_key=False)

        self.assert_valid_jwt_access_token(
            jwt_token_dict["access_token"], self.user, self.default_scopes,
            grant_type='test rand',
        )
