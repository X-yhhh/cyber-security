package com.xyh.cybersecurity.guard;

import com.fasterxml.jackson.databind.JsonNode;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.dao.DuplicateKeyException;
import java.util.function.Supplier;
import java.util.function.Function;
import static com.xyh.cybersecurity.guard.GuardJson.*;

/** 主体和具体路由内的数据库幂等；响应与副作用同事务，不缓存一次性凭据。 */
@Service
public class GuardIdempotency {
    private final GuardStore store;private final GuardAccess access;private final TransactionTemplate tx;
    public GuardIdempotency(GuardStore store,GuardAccess access,PlatformTransactionManager manager){this.store=store;this.access=access;tx=new TransactionTemplate(manager);}
    public JsonNode execute(String route,String key,JsonNode body,int status,boolean credential,Supplier<JsonNode> work){
        return executeWithDigest(route,key,body,status,credential,digest->work.get());
    }
    /** 仅内部同步回调可复用本次服务器计算的摘要；两层幂等校验绑定同一未修改请求，不能接受客户端摘要。 */
    JsonNode executeWithDigest(String route,String key,JsonNode body,int status,boolean credential,Function<String,JsonNode> work){
        uuid(key);String scope=hash(object("subject",access.subject(),"route",route));String digest=hash(body);
        try{return tx.execute(s->{
            var old=store.one("guard_idempotency",map("request_scope",scope,"idempotency_key",key),true);
            if(old!=null)return replay(old,digest,credential);
            var row=store.add("guard_idempotency",map("request_scope",scope,"idempotency_key",key,"request_sha256",digest));
            JsonNode result=work.apply(digest);
            store.update("guard_idempotency",number(row,"id"),map("response_json",canonical(credential?object("issued",true):result),"http_status",status));return result;
        });}catch(DuplicateKeyException collision){
            return tx.execute(s->{var old=store.one("guard_idempotency",map("request_scope",scope,"idempotency_key",key),true);
                if(old==null)throw error(409,"IDEMPOTENCY_CONFLICT");return replay(old,digest,credential);});
        }
    }
    private JsonNode replay(java.util.Map<String,Object> row,String digest,boolean credential){
        if(!digest.equals(str(row,"request_sha256")))throw error(409,"IDEMPOTENCY_CONFLICT");
        if(credential)throw error(409,"CREDENTIAL_ALREADY_ISSUED");return json(row,"response_json");
    }
}
