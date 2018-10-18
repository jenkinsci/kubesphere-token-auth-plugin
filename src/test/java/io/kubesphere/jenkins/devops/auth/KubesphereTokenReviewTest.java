package io.kubesphere.jenkins.devops.auth;

import net.sf.json.JSONObject;
import net.sf.json.JsonConfig;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThat;

public class KubesphereTokenReviewTest {

    @Test
    public void newReviewRequestTest() throws Exception{
        KubesphereTokenReviewRequest reviewRequest = new KubesphereTokenReviewRequest("testToken");

        assertEquals(reviewRequest.getApiVersion(),"authentication.k8s.io/v1beta1");
        assertEquals(reviewRequest.getKind(),"TokenReview");
        assertEquals(reviewRequest.getSpec().getToken(),"testToken");
        assertEquals(JSONObject.fromObject(reviewRequest),JSONObject.fromObject("{\n" +
                "  \"apiVersion\": \"authentication.k8s.io/v1beta1\",\n" +
                "  \"kind\": \"TokenReview\",\n" +
                "  \"spec\": {\n" +
                "    \"token\": \"testToken\"\n" +
                "  }\n" +
                "}"));

    }
}
