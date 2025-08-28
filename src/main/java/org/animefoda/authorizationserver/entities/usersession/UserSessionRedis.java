package org.animefoda.authorizationserver.entities.usersession;

import lombok.Data;
import org.springframework.data.redis.core.RedisHash;

@RedisHash("user_session_cache")
@Data
public class UserSessionRedis {
}
