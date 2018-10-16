package io.kubesphere.jenkins.devops.auth;

import com.squareup.okhttp.*;
import hudson.Extension;
import hudson.model.User;
import jenkins.security.BasicHeaderApiTokenAuthenticator;
import jenkins.security.BasicHeaderAuthenticator;
import jenkins.security.SecurityListener;
import net.sf.json.JSONObject;
import org.acegisecurity.Authentication;
import org.acegisecurity.providers.UsernamePasswordAuthenticationToken;
import org.acegisecurity.userdetails.UserDetails;
import org.acegisecurity.userdetails.UsernameNotFoundException;
import org.springframework.dao.DataAccessException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
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
        User u = User.getById(username, false);
        if (!KubesphereTokenAuthGlobalConfiguration.get().isEnabled()){
            return null;
        }
        if (u == null){
            return null;
        }

        try {
            KubesphereTokenReviewResponse reviewResponse = getReviewResponse(username,password);
            if (reviewResponse.getStatus().getAuthenticated() && reviewResponse.getStatus().getUser().getUsername().equals(username)){
                Authentication auth;
                try {
                    UserDetails userDetails = u.getUserDetailsForImpersonation();
                    auth = new UsernamePasswordAuthenticationToken(userDetails.getUsername(), "", userDetails.getAuthorities());

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

    private static KubesphereTokenReviewResponse getReviewResponse(String username,String token) throws IOException{
        KubesphereTokenAuthGlobalConfiguration authGlobalConfiguration = KubesphereTokenAuthGlobalConfiguration.get();
        if (authGlobalConfiguration.getCacheConfiguration() != null){
            synchronized (authGlobalConfiguration){
                Map<String, KubesphereTokenAuthGlobalConfiguration.CacheEntry<KubesphereTokenReviewResponse>>
                        tokenCache = authGlobalConfiguration.getTokenAuthCache();
                if (tokenCache == null){
                    authGlobalConfiguration.setTokenAuthCache(
                            new KubesphereTokenAuthGlobalConfiguration.CacheMap<>(
                                    authGlobalConfiguration.getCacheConfiguration().getSize()));
                }else {
                    if (((KubesphereTokenAuthGlobalConfiguration.CacheMap)tokenCache).getCacheSize()
                            != authGlobalConfiguration.getCacheConfiguration().getSize()){
                        ((KubesphereTokenAuthGlobalConfiguration.CacheMap)tokenCache).setCacheSize(
                                authGlobalConfiguration.getCacheConfiguration().getSize());
                    }
                    final KubesphereTokenAuthGlobalConfiguration.CacheEntry<KubesphereTokenReviewResponse> cached;
                        cached = tokenCache.get(username);

                    if (cached != null && cached.isValid() && cached.getValue().getToken().equals(token)){
                        return cached.getValue();
                    }
                }
            }
            KubesphereTokenReviewResponse reviewResponse = getReviewResponseFromApiServer(username, token);
            if (reviewResponse.getStatus().getAuthenticated() && (reviewResponse.getStatus().getUser().getUsername().equals(username))){
                synchronized (authGlobalConfiguration){
                    Map<String, KubesphereTokenAuthGlobalConfiguration.CacheEntry<KubesphereTokenReviewResponse>>
                            tokenCache = authGlobalConfiguration.getTokenAuthCache();
                    if (tokenCache.containsKey(username)){
                        tokenCache.replace(username,new KubesphereTokenAuthGlobalConfiguration.CacheEntry<>(
                                authGlobalConfiguration.getCacheConfiguration().getTtl(),reviewResponse
                        ));
                    }else {
                        tokenCache.put(username,new KubesphereTokenAuthGlobalConfiguration.CacheEntry<>(
                                authGlobalConfiguration.getCacheConfiguration().getTtl(),reviewResponse
                        ));
                    }
                }
            }
            return reviewResponse;
        }
        return getReviewResponseFromApiServer(username,token);
    }

    private static KubesphereTokenReviewResponse getReviewResponseFromApiServer(String username,String token) throws IOException{

        OkHttpClient client = new OkHttpClient();
        client.setConnectTimeout(30, TimeUnit.SECONDS);
        client.setReadTimeout(60, TimeUnit.SECONDS);
        Request.Builder builder = new Request.Builder();
        builder.url(KubesphereTokenAuthGlobalConfiguration.get().getServer()+"apis/account.kubesphere.io/v1alpha1/authenticate");
        KubesphereTokenReviewRequest reviewRequest = new KubesphereTokenReviewRequest(token);
        builder.post(RequestBody.create(JSON,JSONObject.fromObject(reviewRequest).toString()));
        Response response = client.newCall(builder.build()).execute();
        JSONObject responseObject = JSONObject.fromObject(response.body().string());

        KubesphereTokenReviewResponse reviewResponse = new KubesphereTokenReviewResponse(responseObject,token);

        return reviewResponse;
    }

    private static final Logger LOGGER = Logger.getLogger(BasicHeaderApiTokenAuthenticator.class.getName());
}


