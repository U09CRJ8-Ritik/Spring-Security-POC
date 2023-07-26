package com.springsecurity.SpringSecurityDemo.resources;

import com.springsecurity.SpringSecurityDemo.entity.Todo;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.annotation.security.RolesAllowed;
import java.util.List;

@RestController
public class TodoResource {


    public List<Todo> list =
            List.of(new Todo("ritik", "Learn Spring Security"),
                    new Todo("ankit", "Get AWS Certified"));



    @GetMapping("/todo")
//    @PreAuthorize("hasRole('USER') and #username == authentication.name")
//    @PostAuthorize("returnObject.username == 'ritik'")
    @RolesAllowed({"ADMIN","USER"})
    @Secured({"ROLE_ADMIN","ROLE_USER"})
    public List<Todo> getList() {
        return list;
    }

    @PostMapping("/todo")
    public String addTodo() {
        return "Post Mapping";
    }
}
