package com.zznode.dhmp.security.core.jackson2;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.MissingNode;
import com.zznode.dhmp.security.core.CustomUserDetails;
import org.springframework.security.core.GrantedAuthority;

import java.io.IOException;
import java.util.Collections;
import java.util.Set;

/**
 * CustomUserDetails反序列化程序
 *
 * @author 王俊
 * @date create in 2023/8/7
 */
public class CustomUserDetailsDeserializer extends JsonDeserializer<CustomUserDetails> {

    @Override
    public CustomUserDetails deserialize(JsonParser jp, DeserializationContext context) throws IOException {
        ObjectMapper mapper = (ObjectMapper) jp.getCodec();
        JsonNode jsonNode = mapper.readTree(jp);

        Set<? extends GrantedAuthority> authorities = Collections.emptySet();
        String username = readJsonNode(jsonNode, "username").asText();
        boolean enabled = readJsonNode(jsonNode, "enabled").asBoolean();
        boolean accountNonExpired = readJsonNode(jsonNode, "accountNonExpired").asBoolean();
        boolean credentialsNonExpired = readJsonNode(jsonNode, "credentialsNonExpired").asBoolean();
        boolean accountNonLocked = readJsonNode(jsonNode, "accountNonLocked").asBoolean();
        CustomUserDetails result = new CustomUserDetails(username, "", enabled, accountNonExpired,
                credentialsNonExpired, accountNonLocked, authorities);
        result.setUserId(readJsonNode(jsonNode, "userId").asLong());
        result.setEmail(readJsonNode(jsonNode, "email").asText());
        result.setAvatar(readJsonNode(jsonNode, "avatar").asText());
        result.setGender(readJsonNode(jsonNode, "gender").asInt());
        result.setUserType(readJsonNode(jsonNode, "userType").asInt());
        result.setRealName(readJsonNode(jsonNode, "realName").asText());
        result.setAdminFlag(readJsonNode(jsonNode, "adminFlag").asInt());
        result.setPhone(readJsonNode(jsonNode, "phone").asText());
        result.setUserLevel(readJsonNode(jsonNode, "userLevel").asInt());
        result.setPlaceCode(readJsonNode(jsonNode, "placeCode").asText());

        return result;
    }

    private JsonNode readJsonNode(JsonNode jsonNode, String field) {
        return jsonNode.has(field) ? jsonNode.get(field) : MissingNode.getInstance();
    }
}
