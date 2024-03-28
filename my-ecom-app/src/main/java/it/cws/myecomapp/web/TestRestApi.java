package it.cws.myecomapp.web;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

@RestController
public class TestRestApi {

    @GetMapping("/data")
    @PreAuthorize("hasAnyAuthority('SCOPE_ADMIN')")
    public Map<String, Object> testData(Authentication authentication){
            Map<String, Object> map=new HashMap<String,Object>();
            map.put("message","Data Message");
            map.put("userName",authentication.getName());
            map.put("role",authentication.getAuthorities());
           // map.put("details",authentication.getCredentials());
        return  map;
    }

    @GetMapping("/test")
    @PreAuthorize("hasAnyAuthority('SCOPE_USER')")
    public Map<String, Object> testData2(Authentication authentication){
        Map<String, Object> map=new HashMap<String,Object>();
        map.put("message",authentication.getCredentials().toString());

        return  map;
    }
}
