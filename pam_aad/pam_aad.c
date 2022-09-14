
#define PAM_SM_AUTH
#include "nss_http.h"
#include <security/pam_modules.h>
#include <security/pam_appl.h>
#include <security/pam_ext.h>
#include <syslog.h>
#include <stdarg.h>

#define MODULE_NAME "pam_aad"

typedef struct Params {
  int        echocode;
  int        debug;
} Params;

static void log_message(int priority, pam_handle_t *pamh,
                        const char *format, ...) {
  char *service = NULL;
  if (pamh)
    pam_get_item(pamh, PAM_SERVICE, (void *)&service);
  if (!service)
    service = "";

  char logname[80];
  snprintf(logname, sizeof(logname), "%s(" MODULE_NAME ")", service);

  va_list args;
  va_start(args, format);
#if !defined(DEMO) && !defined(TESTING)
  openlog(logname, LOG_CONS | LOG_PID, LOG_AUTHPRIV);
  vsyslog(priority, format, args);
  closelog();
#else
  if (!error_msg) {
    error_msg = strdup("");
  }
  {
    char buf[1000];
    vsnprintf(buf, sizeof buf, format, args);
    const int newlen = strlen(error_msg) + 1 + strlen(buf) + 1;
    char* n = malloc(newlen);
    if (n) {
      snprintf(n, newlen, "%s%s%s", error_msg, strlen(error_msg)?"\n":"",buf);
      free(error_msg);
      error_msg = n;
    } else {
      fprintf(stderr, "Failed to malloc %d bytes for log data.\n", newlen);
    }
  }
#endif

  va_end(args);

  if (priority == LOG_EMERG) {
    // Something really bad happened. There is no way we can proceed safely.
    _exit(1);
  }
}

static int converse(pam_handle_t *pamh, int nargs, PAM_CONST struct pam_message **message, struct pam_response **response) {
  struct pam_conv *conv;
  int retval = pam_get_item(pamh, PAM_CONV, (void *)&conv);
  if (retval != PAM_SUCCESS) {
    return retval;
  }
  return conv->conv(nargs, message, response, conv->appdata_ptr);
}

static int parse_args(pam_handle_t *pamh, int argc, const char **argv,
                      Params *params) {
  params->debug = 0;
  params->echocode = PAM_PROMPT_ECHO_OFF;
  for (int i = 0; i < argc; ++i) {
    if (!strcmp(argv[i], "debug")) {
      params->debug = 1;
    } else if (!strcmp(argv[i], "echo-verification-code") ||
               !strcmp(argv[i], "echo_verification_code")) {
      params->echocode = PAM_PROMPT_ECHO_ON;
    } else {
      log_message(LOG_ERR, pamh, "Unrecognized option \"%s\"", argv[i]);
      return -1;
    }
  }
  return 0;
}

static char *request_pass(pam_handle_t *pamh, const Params *params, PAM_CONST char *prompt) {
  PAM_CONST struct pam_message msg = { .mesg_style = params->echocode,
                                       .msg        = prompt};
  PAM_CONST struct pam_message *msgs = &msg;
  struct pam_response *resp = NULL;
  int retval = converse(pamh, 1, &msgs, &resp);
  char *ret = NULL;
  if (retval != PAM_SUCCESS || resp == NULL, || resp->resp == NULL ||
      *resp->resp == '\000') {
    log_message(LOG_ERR, pamh, "Did not receive verification code from user");
    if (retval == PAM_SUCCESS && resp && resp->resp) {
      ret = resp->resp;
    }
  } else {
    ret = resp->resp;
  }

  // Deallocated temporary storage
  if (resp) {
    if (!ret) {
      free(resp->resp);
    }
    free(resp);
  }

  return ret;
}

static const char *get_user_name(pam_handle_t *pamh, const Params *params) {
  // Obtain the user's name
  const char *username;
  if (pam_get_user(pamh, &username, NULL) != PAM_SUCCESS ||
      !username || !*username) {
    log_message(LOG_ERR, pamh,
                "pam_get_user() failed to get a user name"
                " when checking AAD device code");
    return NULL;
  }
  if (params->debug) {
    log_message(LOG_INFO, pamh, "debug: start of AAD Auth for \"%s\"", username);
  }
  return username;
}

static const char *get_client_id(pam_handle_t *pamh, const Params *params) {
  // Obtain the client_id
  const char *client_id;

  client_id = nss_read_config("client_id");
  if (!client_id || !*client_id) {
    log_message(LOG_ERR, pamh, "Failed to retrieve client_id from config");
    return NULL;
  }
  if (params->debug) {
    log_message(LOG_INFO, pamh, "debug: client_id for AAD Auth is \"%s\"", client_id);
  }
  return client_id;
}

static const char *get_authority(pam_handle_t *pamh, const Params *params) {
  // Obtain the authority
  const char *authority;

  authority = nss_read_config("authority");
  if (!authority || !*authority) {
    log_message(LOG_ERR, pamh, "Failed to retrieve authority from config");
    return NULL;
  }
  if (params->debug) {
    log_message(LOG_INFO, pamh, "debug: authority for AAD Auth is \"%s\"", authority);
  }
  return authority;
}

static const char *get_device_code(pam_handle_t *pamh, const Params *params,
                                   const char *device_url, const char *device_postfield) {
  // Obtain the device code
  const char *device_code;
  device_code = nss_http_token_request(device_url, device_postfield);
  if (!device_code || !*device_code) {
    log_message(LOG_ERR, pamh, "Failed to retrieve device code");
    if (params->debug) {
      log_message(LOG_INFO, pamh, "debug: device_url: \"%s\"", device_url);
      log_message(LOG_INFO, pamh, "debug: device_postfield: \"%s\"", device_postfield);
    }
    return NULL;
  }
  if (params->debug) {
    log_message(LOG_INFO, pamh, "debug: device code for AAD Auth is \"%s\"", device_code);
  }
  return device_code;
}

static int device_login(pam_handle_t *pamh, int argc, const char **argv)
{
  char device_url[512], device_postfield[512];
  char token_url[512], token_postfield[512];
  char graph_url[512], auth_header[4096];
  char *pam_password = NULL;
  char pam_message[512];
  json_t *json_root, *token_object;
  json_error_t json_error;


  // Handle optional arguments that configure the PAM module
  Params params = { 0 };
  if (parse_args(pamh, argc, argv, &params) < 0) {
    return PAM_AUTH_ERR;
  }

  const char* const username = get_user_name(pamh, &params);

  // read config file for AAD domain + client id
  const char* const client_id = get_client_id(pamh, &params);
  const char* const authority = get_authority(pamh, &params);

  snprintf(device_url, 512, "%s/oauth2/v2.0/devicecode", authority);
  snprintf(device_postfield, 512, "client_id=%s&scope=user.read%%20openid%%20profile", client_id);

  // create device login request
  const char *device_code = get_device_code(pamh, &params, device_url, device_postfield);

  // print device code message
  json_root = json_loads(device_code, 0, &json_error);
  if (!json_root) {
    log_message(LOG_ERR, pamh, "Error on line %d in device_code: \"%s\"", json_error.line, json_error.text);
    return PAM_AUTH_ERR;
  }
  snprintf(pam_message, 512, "%s\nAnd press Enter to continue....", json_string_value(json_object_get(json_root, "message")));
  if (params->debug) {
    log_message(LOG_INFO, pamh, "debug: pam_message is \"%s\"", pam_message);
  }
  pam_password = request_pass(pamh, params, pam_message);

  // create poll request for token
  snprintf(token_url, 512, "%s/oauth2/v2.0/token", authority);
  snprintf(token_postfield, 512, "grant_type=urn:ietf:params:oauth:grant-type:device_code&client_id=%s&device_code=%s", client_id, json_string_value(json_object_get(json_root, "device_code")));
  json_decref(json_root);

  if (params->debug) {
    log_message(LOG_INFO, pamh, "debug: token_url: \"%s\"", token_url);
    log_message(LOG_INFO, pamh, "debug: token_postfield: \"%s\"", token_postfield);
  }

  // poll for token, check for valid access code : 18 * 5 seconds up to max token lifetime of 90 seconds
  for (int i = 0; i < 18; ++i) {
    char *token = nss_http_token_request(token_url, token_postfield);
    printf("%s\n", token);
    json_root = json_loads(token, 0, &json_error);
    if (!json_root) {
      log_message(LOG_ERR, pamh, "Error on line %d in token response: \"%s\"", json_error.line, json_error.text);
    }
    token_object = json_object_get(json_root, "access_token");
    if (json_is_string(token_object)) {
      break;
    }
    json_decref(json_root);
    if (i == 17) {
      return PAM_AUTHINFO_UNAVAIL; // timeout
    }
    sleep (5);
  }

  snprintf(auth_header, 4096, "%s %s", "Authorization: Bearer", json_string_value(token_object));
  json_decref(json_root);

  snprintf(graph_url, 512, "https://graph.microsoft.com/v1.0/me?$select=displayName,id,description,extj8xolrvw_linux");

  char *response = nss_http_request(graph_url, auth_header);
  json_root = json_loads(response, 0, &json_error);
  if (!json_root) {
    log_message(LOG_ERR, pamh, "Error on line %d in graph response: \"%s\"", json_error.line, json_error.text);
    return PAM_AUTH_ERR;
  }

  // verify if authenticated user is the same as pam user
  if (strcmp(json_string_value(json_object_get(json_object_get(json_root, "extj8xolrvw_linux"), "user")), username)) {
    return PAM_USER_UNKNOWN; //pam user is different from aad user
  }

  json_decref(json_root);

  // all is good; allow user to continue
  if (params->debug) {
    log_message(LOG_INFO, pamh, "debug: Successful auth for \"%s\"", username);
  }
  return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
  return device_login(pamh, argc, argv);
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

int
pam_sm_open_session (pam_handle_t *pamh, int flags, int argc,
		     const char **argv)
{
  return PAM_SUCCESS;
}

int
pam_sm_close_session (pam_handle_t *pamh, int flags,
		      int argc, const char **argv)
{
  return PAM_IGNORE;
}
