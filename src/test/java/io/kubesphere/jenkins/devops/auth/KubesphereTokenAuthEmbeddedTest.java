package io.kubesphere.jenkins.devops.auth;

import hudson.util.FormValidation;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;

import static org.hamcrest.Matchers.startsWith;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertEquals;

public class KubesphereTokenAuthEmbeddedTest {
    public JenkinsRule r = new JenkinsRule();

    @Test
    public void validate() throws Exception{
        KubesphereTokenAuthGlobalConfiguration configuration = new KubesphereTokenAuthGlobalConfiguration(false,"",null);

        FormValidation validation  = configuration.doVerifyConnect("abcdefgaaaaaa");
        assertThat(validation.getMessage(),startsWith("Connect error"));

        FormValidation validation1 = configuration.doVerifyConnect("api.github.com");
        assertThat(validation1.getMessage(),startsWith("Response format error"));
    }

    @Test
    public void serverToUrlTest() throws Exception{
        String url = KubesphereTokenAuthGlobalConfiguration.serverToUrl("api.github.com");
        assertEquals(url,"http://api.github.com/");
    }

    
}
