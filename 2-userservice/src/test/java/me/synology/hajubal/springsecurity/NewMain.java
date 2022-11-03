package me.synology.hajubal.springsecurity;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

public class NewMain {
    public static void main(String[] args) {
        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
        System.out.println("encoder.encode(\"user\") = " + encoder.encode("user"));
    }

}
