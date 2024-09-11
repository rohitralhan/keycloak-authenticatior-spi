package com.redhat.sso.spi.externalsso;


import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.common.util.Time;
import org.keycloak.models.*;

import org.keycloak.services.Urls;
import org.keycloak.sessions.AuthenticationSessionModel;

import com.redhat.sso.spi.token.ExternalApplicationNotificationActionToken;
import com.redhat.sso.spi.token.ExternalApplicationNotificationActionTokenHandler;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.Response.Status;
import jakarta.ws.rs.core.*;


public class ExtAuth implements Authenticator {

	
    private static final Logger logger = Logger.getLogger(ExtAuth.class);
    private static final String IP_BASED_OTP_CONDITIONAL_USER_ATTRIBUTE = "ip_based_otp_conditional";	
    public static final String DEFAULT_APPLICATION_ID = "application-id";
	
	@Override
	public void authenticate(AuthenticationFlowContext context) {
		// TODO Auto-generated method stub
		String service_url = null;
		String ocp_apim_subscription_key = null;
		String unica_application = null;
		String unica_pid = null;
		String unica_serviceid = null;
		String unica_user = null;
		String content_type = null;
		String data = null;
		String appId = null;
		
		if (context.getAuthenticatorConfig() != null) {
			service_url = context.getAuthenticatorConfig().getConfig().get(ExtAuthFactory.SERVICE_URL);
			ocp_apim_subscription_key = context.getAuthenticatorConfig().getConfig().get(ExtAuthFactory.OCP_APIM_SUBSCRIPTION_KEY);
			unica_application = context.getAuthenticatorConfig().getConfig().get(ExtAuthFactory.UNICA_APPLICATION);
			unica_pid = context.getAuthenticatorConfig().getConfig().get(ExtAuthFactory.UNICA_PID);
			unica_serviceid = context.getAuthenticatorConfig().getConfig().get(ExtAuthFactory.UNICA_SERVICEID);
			unica_user = context.getAuthenticatorConfig().getConfig().get(ExtAuthFactory.UNICA_USER);
			content_type = context.getAuthenticatorConfig().getConfig().get(ExtAuthFactory.CONTENT_TYPE);
			data = context.getAuthenticatorConfig().getConfig().get(ExtAuthFactory.DATA);
		}
		
        if(context.getAuthenticatorConfig() == null || (ocp_apim_subscription_key == null && unica_application == null && unica_pid == null 
        		&& unica_serviceid == null && unica_user == null && content_type == null && data == null)) {
        	context.failure(AuthenticationFlowError.IDENTITY_PROVIDER_DISABLED);
        }
        
        // Send HTTP request to external Service
        /*HttpClient client = HttpClient.newBuilder().build();
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(service_url))
                .header("content-type", content_type)
                .header("Ocp-Apim-Subscription-Key", ocp_apim_subscription_key)
                .header("UNICA-Application", unica_application)
                .header("UNICA-PID", unica_pid)
                .header("UNICA-ServiceId", unica_serviceid)
                .header("UNICA-User", unica_user)
                .POST(HttpRequest.BodyPublishers.ofString(data))
                .build();
        HttpResponse<String> response = null;
        
		try {
			response = client.send(request, HttpResponse.BodyHandlers.ofString());
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InterruptedException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}*/
		
        if (appId == null) {
            appId = DEFAULT_APPLICATION_ID;
        }
		
        
        int validityInSecs = context.getRealm().getActionTokenGeneratedByUserLifespan();
        int absoluteExpirationInSecs = Time.currentTime() + validityInSecs;
        final AuthenticationSessionModel authSession = context.getAuthenticationSession();
        final String clientId = authSession.getClient().getClientId();
        
        // Create a token used to return back to the current authentication flow
       String token = new ExternalApplicationNotificationActionToken(
          context.getUser().getId(),
          absoluteExpirationInSecs,
          authSession.getParentSession().getId(),
          appId
        ).serialize(
	        context.getSession(),
	        context.getRealm(),
	        context.getUriInfo()        		
          );
       logger.info(token);
 /*
        // This URL will be used by the application to submit the action token above to return back to the flow
        String submitActionTokenUrl;
        submitActionTokenUrl = Urls
          .actionTokenBuilder(context.getUriInfo().getBaseUri(), token, clientId, authSession.getTabId())
          .queryParam(Constants.EXECUTION, context.getExecution().getId())
          .queryParam(ExternalApplicationNotificationActionTokenHandler.QUERY_PARAM_APP_TOKEN, "{tokenParameterName}")
          .build(context.getRealm().getName(), "{APP_TOKEN}")
          .toString();
		
		logger.info("##################################################");
		logger.info(submitActionTokenUrl);
		//logger.info("Response ->\n" + response.body());
		logger.info("##################################################");        
*/
        logger.info("Login Successful");		
		//context.failure(AuthenticationFlowError.UNKNOWN_USER);
        context.success();
	}

	
	@Override
	public void action(AuthenticationFlowContext context) {
		// TODO Auto-generated method stub
		authenticate(context);
		
	}

	
	@Override
	public void close() {
		// TODO Auto-generated method stub
		
	}	
	
	@Override
	public boolean requiresUser() {
		// TODO Auto-generated method stub
		return true;
	}

	@Override
	public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
		// TODO Auto-generated method stub
		return true;
	}

	@Override
	public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
		// TODO Auto-generated method stub
		
	}
	

}
