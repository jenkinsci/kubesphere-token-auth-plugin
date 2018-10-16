package io.kubesphere.jenkins.devops.auth;

import com.squareup.okhttp.*;
import hudson.Extension;
import hudson.model.User;
import jenkins.security.BasicHeaderApiTokenAuthenticator;
import jenkins.security.BasicHeaderAuthenticator;
import jenkins.security.SecurityListener;
import net.sf.json.JSONObject;
import org.acegisecurity.Authentication;
import org.acegisecurity.userdetails.UserDetails;
import org.acegisecurity.userdetails.UsernameNotFoundException;
import org.springframework.dao.DataAccessException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.logging.Logger;

import static java.util.logging.Level.WARNING;

@Extension
public class KubesphereApiTokenAuthenticator extends BasicHeaderAuthenticator {
    public static final MediaType JSON
            = MediaType.parse("application/json; charset=utf-8");

    @Override
    public Authentication authenticate(HttpServletRequest req, HttpServletResponse rsp, String username, String password) throws ServletException {
        // attempt to authenticate as API token
        User u = User.getById(username, true);
        if (!KubesphereTokenAuthGlobalConfiguration.get().isEnabled()){
            return null;
        }

        try {
            OkHttpClient client = new OkHttpClient();
            client.setConnectTimeout(30, TimeUnit.SECONDS);
            client.setReadTimeout(60, TimeUnit.SECONDS);
            Request.Builder builder = new Request.Builder();
            builder.url(KubesphereTokenAuthGlobalConfiguration.get().getServer()+"apis/account.kubesphere.io/v1alpha1/authenticate");
            Map<String,Object> token = new HashMap<>();
            token.put("token",password);
            JSONObject jsonObject = new JSONObject();
            jsonObject.put("apiVersion","authentication.k8s.io/v1beta1");
            jsonObject.put("kind","TokenReview");
            jsonObject.put("spec",token);
            builder.post(RequestBody.create(JSON,jsonObject.toString()));
            Response response = client.newCall(builder.build()).execute();
            JSONObject responseObject = JSONObject.fromObject(response.body().string());
            JSONObject status = (JSONObject)(responseObject.get("status"));
            JSONObject user = (JSONObject) status.get("user");

            if (status.getBoolean("authenticated") && user.getString("username").equals(username)){
                Authentication auth;
                try {
                    UserDetails userDetails = u.getUserDetailsForImpersonation();
                    auth = u.impersonate(userDetails);

                    SecurityListener.fireAuthenticated(userDetails);

                } catch (UsernameNotFoundException x) {
                    // The token was valid, but the impersonation failed. This token is clearly not his real password,
                    // so there's no point in continuing the request processing. Report this error and abort.
                    LOGGER.log(WARNING, "API token matched for user "+username+" but the impersonation failed",x);
                    throw new ServletException(x);
                } catch (DataAccessException x) {
                    throw new ServletException(x);
                }
                return auth;
            }

        }catch (IOException e){
            return null;
        }
        return null;
    }

    private static final Logger LOGGER = Logger.getLogger(BasicHeaderApiTokenAuthenticator.class.getName());
}


