package io.kubesphere.jenkins.devops.auth;

import net.sf.json.JSONObject;

public class KubesphereTokenReviewResponse {
    private String apiVersion;

    private String kind;

    private TokenStatus status;

    private String token;


    public KubesphereTokenReviewResponse(JSONObject jsonObject,String token){
        this.apiVersion = jsonObject.getString("apiVersion");
        this.kind = jsonObject.getString("kind");
        this.token = token;

        TokenStatus status = new TokenStatus();

        JSONObject statusObject = jsonObject.getJSONObject("status");

        status.authenticated = statusObject.getBoolean("authenticated");

        JSONObject userObject = statusObject.getJSONObject("user");

        if (!userObject.isNullObject()){
            TokenStatus.UserInfo userInfo = new TokenStatus.UserInfo();
            userInfo.username = userObject.getString("username");
            userInfo.uid = userObject.getString("uid");
            userInfo.description = userObject.getString("description");
            userInfo.email = userObject.getString("email");
            userInfo.lastLoginTime = userObject.getString("last_login_time");
            userInfo.status = userObject.getInt("status");
            status.setUser(userInfo);
        }
        this.status = status;
    }

    public void setToken(String token) {
        this.token = token;
    }

    public String getToken() {
        return token;
    }

    public String getApiVersion() {
        return apiVersion;
    }

    public String getKind() {
        return kind;
    }

    public TokenStatus getStatus() {
        return status;
    }
    public void setStatus(TokenStatus status) {
        this.status = status;
    }

    public void setApiVersion(String apiVersion) {
        this.apiVersion = apiVersion;
    }

    public void setKind(String kind) {
        this.kind = kind;
    }

    public static class TokenStatus {

        private UserInfo user;

        private Boolean authenticated;

        public UserInfo getUser() {
            return user;
        }

        public Boolean getAuthenticated() {
            return authenticated;
        }

        public void setAuthenticated(Boolean authenticated) {
            this.authenticated = authenticated;
        }

        public void setUser(UserInfo user) {
            this.user = user;
        }

        public static class UserInfo {
            private String username;

            private String uid;

            private String description;

            private String email;

            private String lastLoginTime;

            private Integer status;

            public String getDescription() {
                return description;
            }

            public String getEmail() {
                return email;
            }

            public void setLastLoginTime(String lastLoginTime) {
                this.lastLoginTime = lastLoginTime;
            }

            public Integer getStatus() {
                return status;
            }

            public String getUid() {
                return uid;
            }

            public String getUsername() {
                return username;
            }

            public void setDescription(String description) {
                this.description = description;
            }

            public void setEmail(String email) {
                this.email = email;
            }

            public String getLastLoginTime() {
                return lastLoginTime;
            }
            public void setStatus(Integer status) {
                this.status = status;
            }

            public void setUid(String uid) {
                this.uid = uid;
            }

            public void setUsername(String username) {
                this.username = username;
            }
        }
    }
}
