package io.security.oauth2.springsecurityoauth2.converters;

import io.security.oauth2.springsecurityoauth2.common.Utils.OAuth2Utils;
import io.security.oauth2.springsecurityoauth2.common.enums.OAuth2Config;
import io.security.oauth2.springsecurityoauth2.model.ProviderUser;
import io.security.oauth2.springsecurityoauth2.model.social.GoogleUser;

public class OAuth2GoogleProviderUserConverter implements ProviderUserConverter<ProviderUserRequest, ProviderUser> {
    @Override
    public ProviderUser converter(ProviderUserRequest providerUserRequest) {

        if (providerUserRequest.clientRegistration().getRegistrationId().equals(OAuth2Config.SocialType.GOOGLE.getSocialName())) {
            return null;
        }
        return new GoogleUser(OAuth2Utils.getMainAttributes(providerUserRequest.oAuth2User()), providerUserRequest.oAuth2User(), providerUserRequest.clientRegistration());
    }
}
