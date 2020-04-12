
#define PAM_SM_AUTH
#include "nss_http.h"
#include <security/pam_modules.h>


static int device_login(const char *pam_user)
{
    char device_url[512], device_postfield[512];
    char token_url[512], token_postfield[512];
    char graph_url[512], auth_header[4096];
    json_t *json_root, *token_object;
    json_error_t json_error;
    
    // read config file for AAD domain + client id
    char *client_id = nss_read_config("client_id");
    char *authority = nss_read_config("authority");
  
    snprintf(device_url, 512, "%s/oauth2/v2.0/devicecode", authority);
    snprintf(device_postfield, 512, "client_id=%s&scope=user.read%%20openid%%20profile", client_id);

    // create device login request
    char *device_code = nss_http_token_request(device_url, device_postfield);

    // print device code message
    json_root = json_loads(device_code, 0, &json_error);
    printf("%s\n", json_string_value(json_object_get(json_root, "message")));

    // create poll request for token
    snprintf(token_url, 512, "%s/oauth2/v2.0/token", authority);
    snprintf(token_postfield, 512, "grant_type=urn:ietf:params:oauth:grant-type:device_code&client_id=%s&device_code=%s", client_id, json_string_value(json_object_get(json_root, "device_code")));
    json_decref(json_root);

    // poll for token, check for valid access code
    for (int i = 0; i < 18; ++i)
    {
    char *token = nss_http_token_request(token_url, token_postfield);
    json_root = json_loads(token, 0, &json_error);
    token_object = json_object_get(json_root, "access_token");
    if (json_is_string(token_object)) break;
    json_decref(json_root);
    if (i == 17) return (-1); //timeout, return PAM_AUTHINFO_UNAVAIL
    sleep (5);
    }

    snprintf(auth_header, 4096, "%s %s", "Authorization: Bearer", json_string_value(token_object));
    json_decref(json_root);

    snprintf(graph_url, 512, "https://graph.microsoft.com/v1.0/me?$select=displayName,id,description,extj8xolrvw_linux");

    char *response = nss_http_request(graph_url, auth_header);
    json_root = json_loads(response, 0, &json_error);

    // verify if authenticated user is the same as pam user
    if (strcmp(json_string_value(json_object_get(json_object_get(json_root, "extj8xolrvw_linux"), "user")), pam_user)) return -2; //pam user is different from aad user 
    json_decref(json_root);

    // all is good; allow user to continue
  return 0;
}


PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    const char *user;

    if (pam_get_user(pamh, &user, NULL) != PAM_SUCCESS) return PAM_AUTH_ERR;

    int result = device_login(user);
  
    if (result == 0) return PAM_SUCCESS;
    if (result == -1) return PAM_AUTHINFO_UNAVAIL;
    if (result == -2) return PAM_USER_UNKNOWN;

    return PAM_AUTHINFO_UNAVAIL;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t * pamh, int flags,
                              int argc, const char **argv)
{
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t * pamh, int flags,
                                int argc, const char **argv)
{
    return PAM_SUCCESS;
}

