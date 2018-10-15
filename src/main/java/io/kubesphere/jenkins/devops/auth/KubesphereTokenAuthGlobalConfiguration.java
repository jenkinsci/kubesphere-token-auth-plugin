package io.kubesphere.jenkins.devops.auth;

import hudson.Extension;
import jenkins.model.GlobalConfiguration;
import net.sf.json.JSONObject;
import org.kohsuke.stapler.DataBoundSetter;
import org.kohsuke.stapler.StaplerRequest;

import javax.annotation.Nonnull;
import java.util.logging.Logger;

@Extension
public class KubesphereTokenAuthGlobalConfiguration  extends GlobalConfiguration{
    private static final Logger LOGGER = Logger.getLogger(KubesphereTokenAuthGlobalConfiguration.class.getName());
    private boolean enabled = true;
    private String server;


    public static KubesphereTokenAuthGlobalConfiguration get() {
        return GlobalConfiguration.all().get(KubesphereTokenAuthGlobalConfiguration.class);
    }

    @Override
    @Nonnull
    public String getDisplayName() {
        return "Kubesphere Jenkins Token Auth";
    }

    @Override
    public boolean configure(StaplerRequest req, JSONObject json) {
        req.bindJSON(this, json);
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

    public String getServer() {
        return this.server;
    }
}
