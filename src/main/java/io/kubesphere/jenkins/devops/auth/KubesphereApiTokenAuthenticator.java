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

    public static KubesphereTokenReviewResponse getReviewResponse(String username,String token) throws IOException{
        KubesphereTokenAuthGlobalConfiguration authGlobalConfiguration = KubesphereTokenAuthGlobalConfiguration.get();
        if (authGlobalConfiguration.getCacheConfiguration() != null){
            synchronized (authGlobalConfiguration){
                Map<String, CacheEntry<KubesphereTokenReviewResponse>>
                        tokenCache = authGlobalConfiguration.getTokenAuthCache();
                if (tokenCache == null){
                    authGlobalConfiguration.setTokenAuthCache(
                            new CacheMap<>(
                                    authGlobalConfiguration.getCacheConfiguration().getSize()));
                }else {
                    if (((CacheMap)tokenCache).getCacheSize()
                            != authGlobalConfiguration.getCacheConfiguration().getSize()){
                        ((CacheMap)tokenCache).setCacheSize(
                                authGlobalConfiguration.getCacheConfiguration().getSize());
                    }
                    final CacheEntry<KubesphereTokenReviewResponse> cached;
                        cached = tokenCache.get(username);

                    if (cached != null && cached.isValid() && cached.getValue().getToken().equals(token)){
                        return cached.getValue();
                    }
                }
            }
            KubesphereTokenReviewResponse reviewResponse = getReviewResponseFromApiServer(
                    KubesphereTokenAuthGlobalConfiguration.get().getServerUrl(),username,token);
            if (reviewResponse.getStatus().getAuthenticated() && (reviewResponse.getStatus().getUser().getUsername().equals(username))){
                synchronized (authGlobalConfiguration){
                    Map<String,CacheEntry<KubesphereTokenReviewResponse>>
                            tokenCache = authGlobalConfiguration.getTokenAuthCache();
                    if (tokenCache.containsKey(username)){
                        tokenCache.replace(username,new CacheEntry<>(
                                authGlobalConfiguration.getCacheConfiguration().getTtl(),reviewResponse
                        ));
                    }else {
                        tokenCache.put(username,new CacheEntry<>(
                                authGlobalConfiguration.getCacheConfiguration().getTtl(),reviewResponse
                        ));
                    }
                }
            }
            return reviewResponse;
        }
        return getReviewResponseFromApiServer(KubesphereTokenAuthGlobalConfiguration.get().getServerUrl(),username,token);
    }

    public static KubesphereTokenReviewResponse getReviewResponseFromApiServer(String baseUrl,String username,String token) throws IOException{

        OkHttpClient client = new OkHttpClient();
        client.setConnectTimeout(30, TimeUnit.SECONDS);
        client.setReadTimeout(60, TimeUnit.SECONDS);
        Request.Builder builder = new Request.Builder();
        builder.url(baseUrl+"apis/account.kubesphere.io/v1alpha1/authenticate");
        KubesphereTokenReviewRequest reviewRequest = new KubesphereTokenReviewRequest(token);
        builder.post(RequestBody.create(JSON,JSONObject.fromObject(reviewRequest).toString()));
        Response response = client.newCall(builder.build()).execute();
        JSONObject responseObject = JSONObject.fromObject(response.body().string());

        KubesphereTokenReviewResponse reviewResponse = new KubesphereTokenReviewResponse(responseObject,token);

        return reviewResponse;
    }


    public static class CacheEntry<T> {
        private final long expires;
        private final T value;

        public CacheEntry(int ttlSeconds, T value) {
            this.expires = System.currentTimeMillis() + TimeUnit.SECONDS.toMillis(ttlSeconds);
            this.value = value;
        }

        public T getValue() {
            return value;
        }

        public boolean isValid() {
            return System.currentTimeMillis() < expires;
        }
    }

    /**
     * While we could use Guava's CacheBuilder the method signature changes make using it problematic.
     * Safer to roll our own and ensure compatibility across as wide a range of Jenkins versions as possible.
     *
     * @param <K> Key type
     * @param <V> Cache entry type
     */
    public static class CacheMap<K, V> extends LinkedHashMap<K, CacheEntry<V>> {

        private int cacheSize;

        public CacheMap(int cacheSize) {
            super(cacheSize + 1); // prevent realloc when hitting cacheConfiguration size limit
            this.cacheSize = cacheSize;
        }

        public void setCacheSize(int cacheSize){
            this.cacheSize = cacheSize;
        }

        public int getCacheSize(){
            return this.cacheSize;
        }

        @Override
        protected boolean removeEldestEntry(Map.Entry<K, CacheEntry<V>> eldest) {
            return size() > cacheSize || eldest.getValue() == null || !eldest.getValue().isValid();
        }
    }

    private static final Logger LOGGER = Logger.getLogger(BasicHeaderApiTokenAuthenticator.class.getName());
}


