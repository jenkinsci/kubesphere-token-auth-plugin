package io.kubesphere.jenkins.devops.auth;

import hudson.Extension;
import hudson.Util;
import hudson.model.AbstractDescribableImpl;
import hudson.model.Descriptor;
import hudson.util.ListBoxModel;
import jenkins.model.GlobalConfiguration;
import net.sf.json.JSONObject;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;
import org.kohsuke.stapler.StaplerRequest;

import javax.annotation.Nonnull;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.logging.Logger;

@Extension
public class KubesphereTokenAuthGlobalConfiguration  extends GlobalConfiguration{
    private static final Logger LOGGER = Logger.getLogger(KubesphereTokenAuthGlobalConfiguration.class.getName());

    private boolean enabled = false;

    private String server;

    private CacheConfiguration cacheConfiguration;

    private transient Map<String, CacheEntry<KubesphereTokenReviewResponse>> tokenAuthCache = null;

    public static KubesphereTokenAuthGlobalConfiguration get() {
        return GlobalConfiguration.all().get(KubesphereTokenAuthGlobalConfiguration.class);
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

    public Map<String, CacheEntry<KubesphereTokenReviewResponse>> getTokenAuthCache() {
        return tokenAuthCache;
    }

    public void setTokenAuthCache(Map<String, CacheEntry<KubesphereTokenReviewResponse>> tokenAuthCache) {
        this.tokenAuthCache = tokenAuthCache;
    }

    @Override
    @Nonnull
    public String getDisplayName() {
        return "Kubesphere Jenkins Token Auth";
    }

    @Override
    public boolean configure(StaplerRequest req, JSONObject json) {
        req.bindJSON(this, json);
        if (json.get("cacheConfiguration") == null){
           this.cacheConfiguration = null;
        }
        this.save();
        return true;
    }
    public boolean isEnabled() {
        return this.enabled;
    }

    @DataBoundSetter
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    @DataBoundSetter
    public void setServer(String server) {
        this.server = server;
    }

    public CacheConfiguration getCacheConfiguration(){
        return this.cacheConfiguration;
    }

    @DataBoundSetter
    public void setCacheConfiguration(CacheConfiguration cacheConfiguration){
        this.cacheConfiguration = cacheConfiguration;
    }

    public String getServer() {
        return this.server;
    }


    public static class CacheConfiguration extends AbstractDescribableImpl<CacheConfiguration> {
        private final int size;
        private final int ttl;

        @DataBoundConstructor
        public CacheConfiguration(int size, int ttl) {
            this.size = Math.max(10, Math.min(size, 1000));
            this.ttl = Math.max(30, Math.min(ttl, 3600));
        }

        public int getSize() {
            return size;
        }

        public int getTtl() {
            return ttl;
        }

        @Extension
        public static class DescriptorImpl extends Descriptor<CacheConfiguration> {

            @Override public String getDisplayName() {
                return "";
            }

            public ListBoxModel doFillSizeItems() {
                ListBoxModel m = new ListBoxModel();
                m.add("10");
                m.add("20");
                m.add("50");
                m.add("100");
                m.add("200");
                m.add("500");
                m.add("1000");
                return m;
            }

            public ListBoxModel doFillTtlItems() {
                ListBoxModel m = new ListBoxModel();
                for (int ttl: new int[]{30, 60, 120, 300, 600, 900, 1800, 3600}) {
                    m.add(Util.getTimeSpanString(ttl*1000L), Integer.toString(ttl));
                }
                return m;
            }

        }
    }
}
