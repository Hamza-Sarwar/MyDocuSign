from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.response import Response
from docusign_esign import ApiClient
from helpers.constants import DS_JWT
from helpers.jwt_helper import get_private_key, get_jwt_token
from .envelop_sender import SigningViaEmail


class TokenView(APIView):


    SCOPES = [

        '''A scope is a set of permissions for an API that specifies 
        what endpoints and methods your integration can call.
        e.g. signature is for eSignature'''
        
        "signature", "impersonation"
    ]

    def get_token(self, private_key, api_client):
        # Call request_jwt_user_token method
        token_response = get_jwt_token(private_key, self.SCOPES, DS_JWT["authorization_server"], DS_JWT["ds_client_id"],
                                       DS_JWT["ds_impersonated_user_id"])
        print(token_response)
        access_token = token_response.access_token

        # Save API account ID
        user_info = api_client.get_user_info(access_token)
        accounts = user_info.get_accounts()
        api_account_id = accounts[0].account_id
        base_path = accounts[0].base_uri + "/restapi"

        return {"access_token": access_token, "api_account_id": api_account_id, "base_path": base_path}

    def get_args(self, api_account_id, access_token, base_path):

        signer_email = input("Please enter the signer's email address: ")
        signer_name = input("Please enter the signer's name: ")
        cc_email = input("Please enter the cc email address: ")
        cc_name = input("Please enter the cc name: ")

        envelope_args = {
            "signer_email": signer_email,
            "signer_name": signer_name,
            "cc_email": cc_email,
            "cc_name": cc_name,
            "status": "sent",
        }
        args = {
            "account_id": api_account_id,
            "base_path": base_path,
            "access_token": access_token,
            "envelope_args": envelope_args
        }

        return args



    def get(self, request):
        api_client = ApiClient()
        api_client.set_base_path(DS_JWT["authorization_server"])
        api_client.set_oauth_host_name(DS_JWT["authorization_server"])
        private_key = get_private_key(DS_JWT["private_key_file"]).encode("ascii").decode("utf-8")
        jwt_values = self.get_token(private_key, api_client)

        args = self.get_args(jwt_values["api_account_id"], jwt_values["access_token"], jwt_values["base_path"])
        envelope_id = SigningViaEmail.worker(args)
        print("Your envelope has been sent.")
        print(envelope_id)

        return Response(envelope_id)