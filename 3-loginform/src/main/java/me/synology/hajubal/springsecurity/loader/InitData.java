package me.synology.hajubal.springsecurity.loader;

import me.synology.hajubal.springsecurity.entity.UserEntity;
import me.synology.hajubal.springsecurity.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Component;

@Component
public class InitData implements ApplicationRunner {
    @Autowired
    private UserRepository userRepository;

    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    @Override
    public void run(ApplicationArguments args) throws Exception {
        UserEntity userEntity = new UserEntity();
        userEntity.setUsername("user");
        userEntity.setPassword(bCryptPasswordEncoder.encode("user"));
        userEntity.setAge(10);

        userRepository.save(userEntity);
    }
}
